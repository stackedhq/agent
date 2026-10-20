package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/slots"
)

// ProxyConfigError carries a structured failure reason from
// ProxyConfig back to the dispatcher, which forwards the fields to
// the server alongside the plain `error` string. The server's
// summarizeProxyConfigError reads `error_code`/`port`/`holder` first
// and falls back to `error` for older agent payloads, so this is
// strictly additive.
type ProxyConfigError struct {
	Code    string // e.g. "port_in_use"
	Port    int    // populated for port_in_use
	Holder  string // container name owning the port, if discoverable
	Message string // human-readable; goes into the legacy `error` field
}

func (e *ProxyConfigError) Error() string { return e.Message }

// Result returns the structured payload the dispatcher should attach
// to a failed proxy_config status update. Server unpacks this back
// into `error_code`/`port`/`holder` keys.
func (e *ProxyConfigError) Result() map[string]interface{} {
	m := map[string]interface{}{
		"error":      e.Message,
		"error_code": e.Code,
	}
	if e.Port != 0 {
		m["port"] = e.Port
	}
	if e.Holder != "" {
		m["holder"] = e.Holder
	}
	return m
}

// caddyfileHeader is the placeholder content written when the Caddyfile is
// missing or has to be self-healed from a non-regular file. ProxyConfig
// will overwrite this with real content on the next op.
const caddyfileHeader = "# Managed by Stacked\n"

// domainsCachePath is where the agent persists the most recent
// `proxy_config.domains` payload. The deploy executor reads this at flip
// time so it can regenerate the Caddyfile (using the new active slot)
// without round-tripping to the server. The file is rewritten on every
// proxy_config op and treated as authoritative; absence means "no
// domains configured for any service on this machine."
var domainsCachePath = filepath.Join(proxyDir, "domains.json")

// serverBaseURL is the Stacked server origin (e.g. https://stacked.rest),
// set once at startup from the agent config via SetServerBaseURL. Used
// to build the on-demand TLS `ask` endpoint URL when rendering the
// Caddyfile. Empty until set; generateCaddyfile falls back to eager
// issuance (no on_demand) when it's empty, since an `on_demand_tls`
// block without an `ask` guard would make the box an open cert-issuing
// relay. No mutex: it's written exactly once before the poller starts
// and only read thereafter.
var serverBaseURL string

// SetServerBaseURL records the Stacked server origin for on-demand TLS
// `ask` URL construction. Trailing slash is trimmed so URL joins are
// clean. Called from main() after config load, before any op runs.
func SetServerBaseURL(u string) {
	serverBaseURL = strings.TrimRight(u, "/")
}

// machineID is this machine's server-side ID, learned from the
// `machineId` field every claimed operation carries (see NoteMachineID).
// Empty until the first op. Read when rendering the on-demand TLS ask
// URL so the server can scope authorization to this machine's domains.
var machineID atomic.Value // string

// machineIDPath persists the machine ID across restarts so the Caddyfile
// rendered by the startup reconcile (before any op has been claimed)
// already carries `?m=`. Package var for tests.
var machineIDPath = filepath.Join(stackedDir, "machine-id")

// NoteMachineID records the machine ID from an operation. Only
// UUID-shaped values are accepted, since it's spliced into a URL in
// the Caddyfile. A new value is persisted to machineIDPath (0600).
func NoteMachineID(id string) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !uuidRe.MatchString(id) || id == currentMachineID() {
		return
	}
	machineID.Store(id)
	if err := writeFileAtomic(machineIDPath, []byte(id+"\n"), 0o600); err != nil {
		log.Printf("persist machine id: %v", err)
	}
}

// LoadMachineID restores the machine ID persisted by NoteMachineID.
// Called at startup before the proxy reconcile; a missing or invalid
// file just leaves the ID unknown until the first op.
func LoadMachineID() {
	data, err := os.ReadFile(machineIDPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load machine id: %v", err)
		}
		return
	}
	id := strings.ToLower(strings.TrimSpace(string(data)))
	if uuidRe.MatchString(id) {
		machineID.Store(id)
	}
}

func currentMachineID() string {
	v, _ := machineID.Load().(string)
	return v
}

// onDemandAskURL returns the full `ask` endpoint URL Caddy should call
// before issuing an on-demand certificate, or "" when the server origin
// is unknown (in which case the caller must not emit on_demand at all).
// When the machine ID is known it's passed as `?m=<id>`; Caddy merges
// its own `domain=<host>` into the query.
func onDemandAskURL() string {
	if serverBaseURL == "" {
		return ""
	}
	u := serverBaseURL + "/api/agent/tls/ask"
	if id := currentMachineID(); id != "" {
		u += "?m=" + id
	}
	return u
}

// cachedDomain is the on-disk representation of one entry in the
// proxy_config domains array. It mirrors the JSON keys the server sends
// so we can decode the live payload straight into this type.
//
// Two shapes share this struct:
//
//   - Service-backed (existing): ServiceID + Port are set; Host/Scheme
//     are zero-valued. Caddyfile upstream resolves to the service's
//     container name on the stacked docker network.
//
//   - Port-bound (new in this minor version): Host + Port + Scheme are
//     set; ServiceID is empty. Caddyfile upstream is a raw host:port
//     (`reverse_proxy <host>:<port>` for http, or
//     `reverse_proxy <scheme>://<host>:<port>` for https). Stacked does
//     not manage the upstream container; the user does.
//
// Older agents reading the persisted file just ignore unknown fields
// (encoding/json default), which means a downgrade after this lands
// keeps service-backed entries working and silently drops port-bound
// ones. That's acceptable: the server will resend the full set on the
// next proxy_config op anyway.
type cachedDomain struct {
	Domain    string `json:"domain"`
	ServiceID string `json:"serviceId,omitempty"`
	Port      int    `json:"port"`
	Host      string `json:"host,omitempty"`
	Scheme    string `json:"scheme,omitempty"`

	// Multi-path routing (server payload_version 2+). Absent on
	// v1 payloads; parseDomains fills in defaults ('/' + strip=true)
	// so the rest of the renderer can branch on these fields
	// unconditionally. Two cachedDomain entries with the same
	// Domain and different Path produce a single Caddy site block
	// with one `handle`/`handle_path` per row.
	Path string `json:"path,omitempty"`
	// Pointer so we can tell "absent" (legacy payload) from
	// "explicitly false". Absent collapses to true in normalisePath
	// — default-strip matches what most backends-on-/api want.
	StripPrefix *bool `json:"stripPrefix,omitempty"`

	// On-demand TLS (server agent-feature ON_DEMAND_TLS+). When true
	// the site block gets `tls { on_demand }` and the file gets a
	// global `on_demand_tls { ask <server>/api/agent/tls/ask }` block,
	// so Caddy defers issuance to the first live request and only
	// issues for hostnames the ask endpoint authorizes. Absent on
	// older payloads → false → eager issuance (unchanged behavior).
	OnDemandTLS bool `json:"onDemandTls,omitempty"`

	// Auth gate fields. When AuthGateMode is non-empty, Caddy emits
	// forward_auth to the gate sidecar for this domain.
	AuthGateMode         string `json:"authGateMode,omitempty"`
	AuthGateUsername     string `json:"authGateUsername,omitempty"`
	AuthGatePasswordHash string `json:"authGatePasswordHash,omitempty"`
	ServiceName          string `json:"serviceName,omitempty"`
}

// effectivePath returns the path this entry routes, defaulting to
// `/` when absent (legacy v1 payloads). Always non-empty after this
// call so the renderer can compare straight against "/".
func (d cachedDomain) effectivePath() string {
	if d.Path == "" {
		return "/"
	}
	return d.Path
}

// effectiveStripPrefix returns the strip flag for non-root paths.
// Forced true at "/" (no prefix to strip) and defaulted true when
// the field is absent on the payload.
func (d cachedDomain) effectiveStripPrefix() bool {
	if d.effectivePath() == "/" {
		return true
	}
	if d.StripPrefix == nil {
		return true
	}
	return *d.StripPrefix
}

// isPortBound returns true for entries whose upstream is a raw
// host:port rather than a Stacked-managed service container.
func (d cachedDomain) isPortBound() bool {
	return d.ServiceID == "" && d.Host != "" && d.Port > 0
}

// ReconcileProxy brings the on-disk proxy compose file and Caddy
// container in line with the current agent version's expectations.
// Intended to be called once at agent startup so that embedded-template
// changes (e.g. a new extra_hosts entry in proxyCompose) land on existing
// installs immediately after self-update, without waiting for the next
// proxy_config op or requiring a manual reinstall.
//
// Skipped on machines that have never run Setup: presence of
// `<proxyDir>/docker-compose.yml` is the signal that Caddy has been
// provisioned here at least once. On a brand-new machine we let the
// server-dispatched Setup op be the single source of truth for first
// provisioning, to avoid racing with it.
//
// Errors are returned for the caller to log. They must not stop the
// agent from booting — Docker may be slow to come up, the proxy may
// be in a transient bad state, etc. The poller will recover via the
// next proxy_config or Setup op.
// StartupProxyReconcileTimeout bounds the startup proxy reconcile so a
// hung docker daemon can't keep the poller from ever starting.
const StartupProxyReconcileTimeout = 10 * time.Minute

// ReconcileProxyWithTimeout runs ReconcileProxy as if it were an op with
// the given deadline: every command it starts is bound to that context
// and killed when it expires. Must not run concurrently with ops (it
// installs the package-level op context), so call it before the poller
// starts.
func ReconcileProxyWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	restore := setOpContext(ctx)
	defer restore()
	err := ReconcileProxy()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("timed out after %s: %w", timeout, ctxErr)
	}
	return err
}

func ReconcileProxy() error {
	composePath := filepath.Join(proxyDir, "docker-compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		if os.IsNotExist(err) {
			return nil // never set up here; nothing to reconcile
		}
		return fmt.Errorf("stat proxy compose: %w", err)
	}
	if _, err := runCommandSilent("", "docker", "info"); err != nil {
		return fmt.Errorf("docker not available")
	}
	if err := ensureProxy(); err != nil {
		return err
	}
	return migrateLegacyGateCaddyfile()
}

// migrateLegacyGateCaddyfile re-renders the live Caddyfile from the
// cached domains when it still points forward_auth at the pre-rename
// `gate:9876` sidecar (which ensureProxy just removed), so gated
// domains recover on the restart after self-update instead of waiting
// for the next proxy_config op. Goes through the same gate-first path
// as proxy_config.
func migrateLegacyGateCaddyfile() error {
	live, err := os.ReadFile(filepath.Join(proxyDir, "Caddyfile"))
	if err != nil || !strings.Contains(string(live), "forward_auth gate:9876") {
		return nil
	}
	parsed, err := loadDomains()
	if err != nil || parsed == nil {
		return err
	}
	parsed = sanitizeDomains(parsed)
	if err := applyGateConfig(buildGateConfig(parsed)); err != nil {
		return fmt.Errorf("auth gate: %w", err)
	}
	log.Printf("proxy: migrating Caddyfile to %s", gateUpstream)
	return writeAndReloadCaddyfile(parsed)
}

// ensureProxy ensures the Caddy proxy infrastructure is running.
// Idempotent — safe to call on every proxy_config.
//
// Port conflicts on :80/:443 are detected post-hoc by parsing the
// docker daemon's error from `docker compose up -d` (see
// parsePortInUseFromDocker). Docker is the only authoritative source
// for whether the bind succeeds — it runs as root, it uses the same
// IPv4/v6 semantics as the Caddy container's actual binds, and it
// owns the port from the moment it succeeds. Any independent
// preflight (e.g. an in-process net.Listen probe) is either wrong
// for unprivileged agents (EACCES on ports <1024 looks identical to
// EADDRINUSE), wrong on dual-stack hosts (Go binds v4+v6 by default,
// docker binds v4 only), or racy (port can change owner between
// probe and compose up). So we don't run one.
func ensureProxy() error {
	if err := ensureDir(proxyDir); err != nil {
		return fmt.Errorf("create proxy dir: %w", err)
	}
	// The gate's bind-mount source must exist (owned by the agent)
	// before compose runs, or docker creates it as root.
	if err := ensureGateDir(); err != nil {
		return err
	}

	// Ensure the stacked network exists
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	// Always reconcile the compose file to the current agent's
	// expected content. Older versions only wrote it if missing,
	// which meant compose changes (e.g. adding extra_hosts) never
	// landed on existing installs even after auto-update. Rewriting
	// when content differs makes `docker compose up -d` detect the
	// change and recreate the Caddy container automatically.
	composePath := filepath.Join(proxyDir, "docker-compose.yml")
	want := proxyCompose()
	existing, _ := os.ReadFile(composePath)
	if string(existing) != want {
		if err := writeFile(composePath, want); err != nil {
			return fmt.Errorf("write proxy compose: %w", err)
		}
	}

	// Self-heal the Caddyfile bind-mount source. If a prior `compose up`
	// ran before the file existed, docker would have auto-created it as a
	// directory and every subsequent `compose up` would fail with
	// "not a directory". Recover before docker compose up.
	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	if err := ensureRegularFile(caddyfilePath, caddyfileHeader); err != nil {
		return fmt.Errorf("ensure Caddyfile: %w", err)
	}

	// Record networks attached to the current Caddy at runtime (Dokploy
	// takeover) before `compose up` can recreate the container without
	// them. Best-effort: a failure here must not block routing.
	if err := recordCaddyRuntimeNetworks(); err != nil {
		log.Printf("proxy: record caddy runtime networks: %v", err)
	}

	// Start Caddy (no-op if already running). docker compose up -d is
	// idempotent against a running container, and the docker daemon is
	// the authoritative arbiter of port conflicts — if :80 or :443 is
	// held by something else, the daemon returns a recognizable error
	// string that parsePortInUseFromDocker turns into a typed
	// ProxyConfigError for the server to surface.
	//
	// Only Caddy is started here: a gate start failure must not take
	// down routing for ungated domains. (Compose ignores
	// --remove-orphans when a service is named, so the pre-rename
	// `gate` container is removed explicitly below.)
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "up", "-d", "caddy"); err != nil {
		if port, holder := parsePortInUseFromDocker(out); port != 0 {
			msg := fmt.Sprintf("port %d is already in use on this machine", port)
			if holder != "" {
				msg = fmt.Sprintf("port %d is held by container '%s'", port, holder)
			}
			return &ProxyConfigError{
				Code:    "port_in_use",
				Port:    port,
				Holder:  holder,
				Message: msg,
			}
		}
		return fmt.Errorf("start caddy: %s: %w", out, err)
	}
	removeLegacyGateContainer()

	// Re-attach runtime networks a recreate may have dropped.
	if err := reconnectCaddyNetworks(); err != nil {
		log.Printf("proxy: %v", err)
	}

	// Best-effort here; proxy_config requires the gate (and fails the
	// op) only when a domain is actually gated (applyGateConfig).
	if err := gateStartFn(); err != nil {
		log.Printf("proxy: auth gate not started: %v", err)
	}

	return nil
}

// lookupPortHolder is lookupPortHolderContainer, swappable in tests.
var lookupPortHolder = lookupPortHolderContainer

// lookupPortHolderContainer asks docker which container publishes the
// given port on the host, if any. Returns "" if no docker container
// claims it (the holder might be a systemd service, nginx on the
// host, etc., in which case we can't name it cheaply).
func lookupPortHolderContainer(port int) string {
	out, err := opCommand("docker", "ps",
		"--filter", fmt.Sprintf("publish=%d", port),
		"--format", "{{.Names}}").Output()
	if err != nil {
		return ""
	}
	names := strings.Fields(strings.TrimSpace(string(out)))
	if len(names) == 0 {
		return ""
	}
	// Skip our own Caddy if it shows up — we wouldn't be in this code
	// path if docker were happy with the bind, so a proxy-caddy entry
	// here is leftover bookkeeping, not the real holder.
	for _, n := range names {
		if !strings.Contains(n, "proxy-caddy") {
			return n
		}
	}
	return names[0]
}

// parsePortInUseFromDocker scrapes the docker daemon's stderr for the
// signature port-in-use message. Returns (port, holder) on match,
// (0, "") otherwise. Holder is looked up via `docker ps` if a port
// can be parsed out of the message.
func parsePortInUseFromDocker(out string) (int, string) {
	if !strings.Contains(out, "port is already allocated") &&
		!strings.Contains(out, "address already in use") {
		return 0, ""
	}
	var port int
	// docker error format: "Bind for 0.0.0.0:80 failed:"
	if _, err := fmt.Sscanf(strings.SplitN(out, "0.0.0.0:", 2)[1], "%d", &port); err != nil || port == 0 {
		return 0, ""
	}
	return port, lookupPortHolder(port)
}

// ProxyConfig signature returns a structured result alongside the
// error so the dispatcher can forward typed failure reasons to the
// server. On success the result is nil; on failure the result is
// either the unpacked *ProxyConfigError fields or nil for generic
// errors (which the dispatcher then wraps in `{error: ...}` as
// before).
func (e *Executor) ProxyConfig(op client.Operation) error {
	domainsRaw, ok := op.Payload["domains"]
	if !ok {
		return fmt.Errorf("proxy_config requires domains in payload")
	}

	domains, ok := domainsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("proxy_config domains must be an array")
	}

	parsed := sanitizeDomains(parseDomains(domains))
	gateCfg := buildGateConfig(parsed)

	if err := ensureProxyFn(); err != nil {
		return fmt.Errorf("ensure proxy: %w", err)
	}

	// The gate must know every gated domain before Caddy starts sending
	// forward_auth for it, so it is updated first. That also means a
	// failure after the gate write (the gate not loading it, or Caddy
	// rejecting or failing to reload its config) would leave Caddy on its
	// old routes behind a gate that no longer knows their domains (403).
	// So the previous gate config is kept and put back on any failure:
	// the gate and Caddy both end in their old state.
	prevGate, err := snapshotGateConfig()
	if err != nil {
		return fmt.Errorf("auth gate: read current config: %w", err)
	}
	rollbackGate := func(cause error) error {
		if rerr := restoreGateConfig(prevGate); rerr != nil {
			log.Printf("proxy_config: restore previous auth gate config: %v", rerr)
			return fmt.Errorf("%w (restoring the previous auth gate config also failed: %v)", cause, rerr)
		}
		return cause
	}
	if err := applyGateConfig(gateCfg); err != nil {
		return rollbackGate(fmt.Errorf("auth gate: %w", err))
	}

	if err := caddyApplyFn(parsed); err != nil {
		return rollbackGate(err)
	}

	// Cache the domains only once Caddy runs them, so a later
	// RegenerateCaddyfile (rolling flip) never installs a config whose
	// gate entries were rolled back above.
	if err := persistDomains(parsed); err != nil {
		// Caddy is already serving the new config; RegenerateCaddyfile
		// just works from a staler cache until the next proxy_config.
		log.Printf("proxy_config: persist domains.json failed (non-fatal): %v", err)
	}
	log.Printf("Caddy config updated for %d domain(s)", len(parsed))
	return nil
}

// Test seams for ProxyConfig's docker-touching steps.
var (
	ensureProxyFn = ensureProxy
	caddyApplyFn  = writeAndReloadCaddyfile
)

// RegenerateCaddyfile rewrites the Caddyfile from the persisted domains
// list using current slot state, validates it, and reloads Caddy. Used
// by the rolling deploy executor after slot state changes — the upstream
// for any of this service's domains needs to point at the new slot.
//
// If no domains have ever been configured (domains.json missing), this
// is a no-op: there's nothing to reload.
func RegenerateCaddyfile() error {
	parsed, err := loadDomains()
	if err != nil {
		return fmt.Errorf("load domains cache: %w", err)
	}
	if parsed == nil {
		// Never saw a proxy_config op; nothing to regenerate.
		return nil
	}
	parsed = sanitizeDomains(parsed)
	if err := ensureProxy(); err != nil {
		return fmt.Errorf("ensure proxy: %w", err)
	}
	return writeAndReloadCaddyfile(parsed)
}

// writeAndReloadCaddyfile is the shared finishing step for both the
// server-driven `proxy_config` op and the agent-internal flip during a
// rolling deploy. It:
//
//  1. Generates the Caddyfile content (slot-aware, via slots.All()).
//  2. `caddy validate`s the new file inside the running Caddy
//     container BEFORE writing it. Without this, a malformed file
//     could cause the next reload to fail and force a fall-back
//     restart that drops traffic for every service on the box.
//  3. Writes the file.
//  4. Reloads Caddy. On reload failure, restores the previous file
//     and re-reloads — we never let a bad Caddyfile linger on disk
//     because Caddy reloads on container restart at boot too.
//
// This function deliberately does NOT fall back to `docker compose
// restart caddy` on reload failure (the historical behavior). A restart
// drops traffic for every service the proxy fronts; we prefer to surface
// the error to the caller so a rolling deploy can roll back its slot
// state and let the previous slot keep serving.
func writeAndReloadCaddyfile(parsed []cachedDomain) error {
	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	prev, _ := os.ReadFile(caddyfilePath) // best-effort backup for rollback

	state := slots.All()
	content, err := generateCaddyfileChecked(parsed, state)
	if err != nil {
		return err
	}

	// Validate the candidate config inside the Caddy container before
	// touching the live file. The container's `/etc/caddy/Caddyfile` is
	// a single-file bind mount (see setup.go::proxyCompose), so a
	// sibling `Caddyfile.candidate` written to the host directory is
	// NOT visible inside the container. We instead pipe the candidate
	// to a container-only scratch path via `docker exec` stdin and
	// validate that path. `--config -` over stdin would be simpler but
	// isn't portable across all Caddy versions.
	composeFile := filepath.Join(proxyDir, "docker-compose.yml")
	const candidateInContainer = "/tmp/Caddyfile.candidate"
	writeCmd := opCommand(
		"docker", "compose", "-f", composeFile,
		"exec", "-T", "caddy",
		"sh", "-c", "cat > "+candidateInContainer,
	)
	writeCmd.Stdin = strings.NewReader(content)
	if out, err := writeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write candidate Caddyfile into container: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// Best-effort cleanup; `/tmp` doesn't survive container restart
	// anyway, but a tidy `rm` keeps `docker exec ls /tmp` boring.
	defer func() {
		_, _ = cleanupCommand(cleanupTimeout,
			"docker", "compose", "-f", composeFile,
			"exec", "-T", "caddy",
			"rm", "-f", candidateInContainer,
		)
	}()

	if err := opCommand(
		"docker", "compose", "-f", composeFile,
		"exec", "-T", "caddy",
		"caddy", "validate", "--config", candidateInContainer,
	).Run(); err != nil {
		// Validation failed. Don't write the live file. Surface the
		// validation error so the caller can decide what to do (rolling
		// deploy will roll back slot state).
		return fmt.Errorf("caddy validate rejected new config: %w", err)
	}

	if err := writeFile(caddyfilePath, content); err != nil {
		return fmt.Errorf("write Caddyfile: %w", err)
	}

	if err := opCommand(
		"docker", "compose", "-f", composeFile,
		"exec", "-T", "caddy",
		"caddy", "reload", "--config", "/etc/caddy/Caddyfile",
	).Run(); err != nil {
		// Reload failed despite validate passing — rare, but possible
		// (e.g. a runtime cert issue). Restore the previous file so
		// the next boot reload sees known-good config.
		if len(prev) > 0 {
			if werr := writeFile(caddyfilePath, string(prev)); werr != nil {
				log.Printf("restore previous Caddyfile after failed reload: %v", werr)
			}
		}
		return fmt.Errorf("caddy reload: %w", err)
	}
	return nil
}

// parseDomains accepts both shapes from the server's proxy_config
// payload:
//
//   - service-backed: { domain, serviceId, port }
//   - port-bound:     { domain, host, port, scheme }
//
// Anything that doesn't match either shape is dropped silently. The
// server enforces a CHECK constraint that guarantees exactly-one-of
// shape; older servers that don't know about port-bound shape simply
// won't emit those entries, so this stays back-compatible.
func parseDomains(raw []interface{}) []cachedDomain {
	out := make([]cachedDomain, 0, len(raw))
	for _, d := range raw {
		dm, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		domain, _ := dm["domain"].(string)
		if domain == "" {
			continue
		}
		serviceID, _ := dm["serviceId"].(string)
		host, _ := dm["host"].(string)

		port := 0
		if p, ok := dm["port"].(float64); ok && p > 0 {
			port = int(p)
		}

		// Multi-path fields (payload_version 2+). Absence is
		// indistinguishable from default; we keep the pointer nil so
		// effectiveStripPrefix can fall back to true.
		path, _ := dm["path"].(string)
		var stripPtr *bool
		if sp, ok := dm["stripPrefix"].(bool); ok {
			stripCopy := sp
			stripPtr = &stripCopy
		}

		// On-demand TLS flag. Absent → false (eager issuance).
		onDemand, _ := dm["onDemandTls"].(bool)

		// Auth gate fields.
		authGateMode, _ := dm["authGateMode"].(string)
		authGateUsername, _ := dm["authGateUsername"].(string)
		authGatePasswordHash, _ := dm["authGatePasswordHash"].(string)
		serviceName, _ := dm["serviceName"].(string)

		switch {
		case serviceID != "":
			// Service-backed. Default port matches the historical
			// fallback (most services listen on 3000).
			if port == 0 {
				port = 3000
			}
			out = append(out, cachedDomain{
				Domain:               domain,
				ServiceID:            serviceID,
				Port:                 port,
				Path:                 path,
				StripPrefix:          stripPtr,
				OnDemandTLS:          onDemand,
				AuthGateMode:         authGateMode,
				AuthGateUsername:     authGateUsername,
				AuthGatePasswordHash: authGatePasswordHash,
				ServiceName:          serviceName,
			})
		case host != "" && port > 0:
			// Port-bound. Scheme defaults to http; only http and
			// https are accepted (the server validates this too).
			scheme, _ := dm["scheme"].(string)
			if scheme != "http" && scheme != "https" {
				scheme = "http"
			}
			out = append(out, cachedDomain{
				Domain:      domain,
				Host:        host,
				Port:        port,
				Scheme:      scheme,
				Path:        path,
				StripPrefix: stripPtr,
				OnDemandTLS: onDemand,
			})
		default:
			// Neither shape fully populated; skip.
			continue
		}
	}
	return out
}

// caddyDomainRe is a strict hostname: lowercase LDH labels (no
// wildcard; the server never sends one). Length is checked separately.
var caddyDomainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// caddyPathUnsafe are the characters (besides whitespace and control
// characters) that could break a route path out of its Caddyfile token
// or change how Caddy lexes it: `{`/`}` (blocks and placeholders), `"`
// and backtick (quoting), `\` (escapes), `#` (comments). `?` and `*`
// would change the matcher's meaning. Everything else the server
// accepts (printable ASCII) is allowed; paths outside the bare-token
// charset are rendered quoted (caddyPathToken).
const caddyPathUnsafe = "{}\"`\\#?*"

// caddyBareTokenRe is the charset that renders as an unquoted token.
var caddyBareTokenRe = regexp.MustCompile(`^[A-Za-z0-9._~/-]+$`)

const maxCaddyPathLen = 1024

func validCaddyDomain(d string) bool {
	return len(d) <= 253 && caddyDomainRe.MatchString(d)
}

func validCaddyPath(p string) bool {
	if len(p) == 0 || len(p) > maxCaddyPathLen || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		// Printable ASCII only, no space (0x20): this also rejects
		// every control character and non-ASCII byte.
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(caddyPathUnsafe, c) >= 0 {
			return false
		}
	}
	return true
}

// caddyPathMatcher renders a validated route path plus the trailing `*`
// as a Caddyfile token, quoted when it contains anything outside the
// bare-token charset. validCaddyPath has already excluded `"` and `\`,
// so plain double quotes need no escaping.
func caddyPathMatcher(path string) string {
	if caddyBareTokenRe.MatchString(path) {
		return path + "*"
	}
	return `"` + path + `*"`
}

// validateDomainRow checks that a row's domain and path are safe to
// splice into the Caddyfile.
func validateDomainRow(d cachedDomain) error {
	if !validCaddyDomain(d.Domain) {
		return fmt.Errorf("invalid domain %q", d.Domain)
	}
	if !validCaddyPath(d.effectivePath()) {
		return fmt.Errorf("invalid path %q for domain %s", d.effectivePath(), d.Domain)
	}
	return nil
}

// sanitizeDomains lowercases domains and drops (with a logged error)
// rows whose domain or path isn't a safe Caddyfile token, or whose
// port-bound upstream host is rejected by validateUpstreamHost. Skipping
// a row instead of failing the whole op keeps every other site on the
// machine updatable (one bad row must not fail every proxy_config, or
// RegenerateCaddyfile and with it a blue/green flip), and is safe
// because the gate config and the Caddyfile are both derived from the
// same filtered list: a dropped row simply isn't routed. The server
// validates these fields too; this is defence in depth.
func sanitizeDomains(parsed []cachedDomain) []cachedDomain {
	out := make([]cachedDomain, 0, len(parsed))
	for _, d := range parsed {
		d.Domain = strings.ToLower(d.Domain)
		if err := validateDomainRow(d); err != nil {
			log.Printf("proxy: skipping domain row: %v", err)
			continue
		}
		if d.isPortBound() {
			if err := validateUpstreamHost(d.Host); err != nil {
				log.Printf("proxy: skipping domain row: invalid port-bound upstream host for %s: %v", d.Domain, err)
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

func persistDomains(parsed []cachedDomain) error {
	data, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(domainsCachePath, string(data))
}

// loadDomains returns the cached domains list, or nil when the file
// has never been written. An empty slice is distinct: it means
// proxy_config ran but with no domains.
func loadDomains() ([]cachedDomain, error) {
	data, err := os.ReadFile(domainsCachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var parsed []cachedDomain
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// generateCaddyfile writes one upstream block per domain. The upstream
// host depends on the service's active slot:
//
//   - No entry in `state` (recreate mode, or a rolling service that
//     hasn't completed its first flip yet): upstream is `<serviceID>:<port>`.
//     This matches the historical container_name and keeps existing
//     services working untouched.
//
//   - Active slot Blue/Green: upstream is `<serviceID>-<slot>:<port>`,
//     pointing at the slot container running on the stacked network.
//
//   - Active slot Legacy: same as "no entry" — the legacy container
//     name is the bare serviceID. Used during the very first rolling
//     deploy of a service migrating off recreate.
func generateCaddyfile(parsed []cachedDomain, state map[string]slots.Slot) string {
	content, err := generateCaddyfileChecked(parsed, state)
	if err != nil {
		log.Printf("proxy: rejected unsafe Caddyfile payload: %v", err)
		return caddyfileHeader + "# invalid proxy config rejected\n"
	}
	return content
}

func generateCaddyfileChecked(parsed []cachedDomain, state map[string]slots.Slot) (string, error) {
	var b strings.Builder
	b.WriteString("# Managed by Stacked \u2014 do not edit manually\n\n")

	// Group rows by hostname so we emit exactly one site block per
	// host, even when multi-path routing splits a host across
	// several rows. Preserve first-seen order for the outer host
	// list (deterministic given the server's ORDER BY on domain)
	// so the rendered Caddyfile is stable across renders.
	hostOrder := make([]string, 0)
	byHost := make(map[string][]cachedDomain)
	// A host opts into on-demand TLS if any of its rows do — on_demand
	// is a per-hostname (TLS) concern, not per-path, so we OR the flag
	// across the rows that share a hostname.
	onDemandHost := make(map[string]bool)
	for _, d := range parsed {
		if err := validateDomainRow(d); err != nil {
			return "", err
		}
		if _, seen := byHost[d.Domain]; !seen {
			hostOrder = append(hostOrder, d.Domain)
		}
		byHost[d.Domain] = append(byHost[d.Domain], d)
		if d.OnDemandTLS {
			onDemandHost[d.Domain] = true
		}
	}

	// Global options block for on-demand TLS. Caddy requires the
	// `ask` endpoint so issuance is gated to authorized hostnames —
	// without it the box would issue a cert for any hostname pointed
	// at it. We therefore only emit on_demand (here AND per-site
	// below) when the ask URL is known; if the server origin is
	// unset, on-demand silently degrades to eager issuance rather
	// than rendering an unguarded (dangerous) on_demand_tls block.
	askURL := onDemandAskURL()
	anyOnDemand := askURL != "" && len(onDemandHost) > 0
	if anyOnDemand {
		b.WriteString("{\n")
		b.WriteString("\ton_demand_tls {\n")
		fmt.Fprintf(&b, "\t\task %s\n", askURL)
		b.WriteString("\t}\n")
		b.WriteString("}\n\n")
	}

	for _, host := range hostOrder {
		rows := byHost[host]
		// Order paths longest-first so a hand-read Caddyfile
		// matches Caddy's own longest-prefix matcher precedence.
		// (Caddy 2's `handle` directives auto-sort, but the
		// human reader shouldn't have to know that.)
		sortedRows := make([]cachedDomain, len(rows))
		copy(sortedRows, rows)
		sort.SliceStable(sortedRows, func(i, j int) bool {
			pi, pj := sortedRows[i].effectivePath(), sortedRows[j].effectivePath()
			if pi == pj {
				return false
			}
			if pi == "/" {
				return false // root last
			}
			if pj == "/" {
				return true
			}
			return len(pi) > len(pj)
		})

		fmt.Fprintf(&b, "%s {\n", host)

		// On-demand TLS for this host: defer issuance to the first
		// live request, gated by the global `ask` endpoint. Only
		// emitted when the ask URL is known (see anyOnDemand above).
		if anyOnDemand && onDemandHost[host] {
			b.WriteString("    tls {\n")
			b.WriteString("        on_demand\n")
			b.WriteString("    }\n")
		}

		// Check if any row on this host has an auth gate enabled.
		hostHasGate := false
		for _, d := range sortedRows {
			if d.AuthGateMode != "" {
				hostHasGate = true
				break
			}
		}

		if hostHasGate {
			// Gate-protected host: proxy /__stacked/* to the gate
			// sidecar (login page, form POST, logout), then forward_auth
			// everything else through the gate's /check endpoint.
			//
			// X-Stacked-Gate-Domain carries the configured domain
			// literal (validated by validCaddyDomain, so it's a bare
			// LDH token), not {host}: the gate keys on it, so Host
			// case, trailing dots or ports can't select a different
			// (or no) gate entry. header_up replaces any value the
			// client sent.
			b.WriteString("    handle /__stacked/* {\n")
			fmt.Fprintf(&b, "        reverse_proxy %s {\n", gateUpstream)
			fmt.Fprintf(&b, "            header_up X-Stacked-Gate-Domain %s\n", host)
			b.WriteString("        }\n")
			b.WriteString("    }\n")
			b.WriteString("    handle {\n")
			fmt.Fprintf(&b, "        forward_auth %s {\n", gateUpstream)
			b.WriteString("            uri /check\n")
			b.WriteString("            header_up X-Original-URI {uri}\n")
			fmt.Fprintf(&b, "            header_up X-Stacked-Gate-Domain %s\n", host)
			b.WriteString("        }\n")
			// Emit upstream(s) inside the gated handle block
			if len(sortedRows) == 1 && sortedRows[0].effectivePath() == "/" {
				if err := writeUpstream(&b, sortedRows[0], state, "        "); err != nil {
					return "", err
				}
			} else {
				for _, d := range sortedRows {
					if err := writePathHandle(&b, d, state, "        "); err != nil {
						return "", err
					}
				}
			}
			b.WriteString("    }\n")
		} else {
			// No gate — original rendering path.
			// Fast path: single row at root — emit a bare
			// `reverse_proxy` (no `handle` wrapper).
			if len(sortedRows) == 1 && sortedRows[0].effectivePath() == "/" {
				if err := writeUpstream(&b, sortedRows[0], state, "    "); err != nil {
					return "", err
				}
			} else {
				for _, d := range sortedRows {
					if err := writePathHandle(&b, d, state, "    "); err != nil {
						return "", err
					}
				}
			}
		}

		// Brand the proxy once per host, outside the handle
		// blocks so it applies uniformly to every route.
		b.WriteString("    header Server Stacked\n")
		fmt.Fprintf(&b, "}\n\n")
	}
	return b.String(), nil
}

// writeUpstream emits the single `reverse_proxy` line for a row,
// indented with `indent`. Factored out so the single-row fast path
// and the multi-row handle path share one code path — keeps the
// upstream-resolution rules (slots, IPv6 brackets, loopback rewrite)
// in exactly one place.
func writeUpstream(b *strings.Builder, d cachedDomain, state map[string]slots.Slot, indent string) error {
	if d.isPortBound() {
		hp, err := renderUpstreamHostPort(d.Host, d.Port)
		if err != nil {
			return fmt.Errorf("invalid port-bound upstream host for %s: %w", d.Domain, err)
		}
		if d.Scheme == "https" {
			fmt.Fprintf(b, "%sreverse_proxy https://%s\n", indent, hp)
		} else {
			fmt.Fprintf(b, "%sreverse_proxy %s\n", indent, hp)
		}
		return nil
	}
	host := d.ServiceID
	if slot, ok := state[d.ServiceID]; ok && slot != slots.Legacy {
		host = d.ServiceID + "-" + string(slot)
	}
	fmt.Fprintf(b, "%sreverse_proxy %s:%d\n", indent, host, d.Port)
	return nil
}

// writePathHandle emits a single handle/handle_path block for a multi-path row.
// Factored out so both gated and ungated code paths share the logic.
func writePathHandle(b *strings.Builder, d cachedDomain, state map[string]slots.Slot, indent string) error {
	path := d.effectivePath()
	if path == "/" {
		fmt.Fprintf(b, "%shandle {\n", indent)
	} else if d.effectiveStripPrefix() {
		fmt.Fprintf(b, "%shandle_path %s {\n", indent, caddyPathMatcher(path))
	} else {
		fmt.Fprintf(b, "%shandle %s {\n", indent, caddyPathMatcher(path))
	}
	if err := writeUpstream(b, d, state, indent+"    "); err != nil {
		return err
	}
	fmt.Fprintf(b, "%s}\n", indent)
	return nil
}

// renderUpstreamHostPort produces a Caddy-safe "host:port" token for a
// port-bound upstream. Two non-obvious rewrites happen here:
//
//  1. Loopback rewrite (loopbackRewrite). The Caddy container is on a
//     docker bridge network, so the user-typed "127.0.0.1" and
//     "localhost" resolve to the *container itself*, not the host. We
//     rewrite them to "host.docker.internal", which the compose file
//     pins to the host's gateway via `extra_hosts: host-gateway`. This
//     is the only place the user's intent ("this VPS") matches what
//     they typed without it.
//
//  2. IPv6 bracketing. Caddy expects `[2001:db8::1]:443` for IPv6
//     literals. A bare `2001:db8::1:443` is ambiguous and rejected
//     by the parser. Detected by presence of ":" in the host string
//     and absence of a leading "[".
func renderUpstreamHostPort(host string, port int) (string, error) {
	if err := validateUpstreamHost(host); err != nil {
		return "", err
	}
	if rewritten, ok := loopbackRewrite(host); ok {
		host = rewritten
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port), nil
	}
	return fmt.Sprintf("%s:%d", host, port), nil
}

// dockerHostAlias is the extra_hosts name for the VPS itself inside the
// Caddy container (see proxyCompose).
const dockerHostAlias = "host.docker.internal"

// loopbackRewrite is the one intentional exception to "no loopback
// upstreams": these exact spellings mean "a port on this VPS" and are
// rewritten to the docker host alias. The alias itself is accepted too
// (the dashboard allows typing it) and normalized to its canonical
// spelling. Every other loopback address (127.0.0.2, ::ffff:127.0.0.1,
// ...) is rejected by validateUpstreamHost.
func loopbackRewrite(host string) (string, bool) {
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "[::1]", dockerHostAlias, dockerHostAlias + ".":
		return dockerHostAlias, true
	}
	return "", false
}

// validateUpstreamHost checks a port-bound upstream host. Accepts IP
// literals and RFC-1123 hostnames that are safe Caddyfile tokens, and
// rejects addresses that would point Caddy somewhere the user can't
// mean: loopback (other than the loopbackRewrite spellings),
// unspecified, link-local (incl. cloud metadata 169.254.169.254) and
// multicast, with IPv4-mapped IPv6 unmapped first. Also rejects
// *.localhost and names reserved for Stacked infrastructure
// (stacked-gate, caddy...). UUID-shaped names are allowed: they are
// Stacked service container names on the shared network, which the
// dashboard lets users target directly.
func validateUpstreamHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is empty")
	}
	for _, r := range host {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("host contains whitespace or control characters")
		}
	}
	if strings.ContainsAny(host, "{}\"'#/\\") {
		return fmt.Errorf("host contains characters that are unsafe in Caddyfile upstream tokens")
	}
	if _, ok := loopbackRewrite(host); ok {
		return nil
	}

	addrHost := host
	bracketed := strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]")
	if bracketed {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
			return fmt.Errorf("invalid bracketed IPv6 host")
		}
		addrHost = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}

	if addr, err := netip.ParseAddr(addrHost); err == nil {
		if bracketed && !addr.Is6() {
			return fmt.Errorf("invalid bracketed IPv6 host")
		}
		if addr.Zone() != "" {
			return fmt.Errorf("IPv6 zone identifiers are not supported")
		}
		return validateUpstreamAddr(addr.Unmap())
	}
	if bracketed {
		return fmt.Errorf("invalid bracketed IPv6 host")
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("invalid IP literal")
	}
	if !isRFC1123Hostname(host) {
		return fmt.Errorf("host must be an IP literal or RFC-1123 hostname")
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return fmt.Errorf("host %q is reserved; use 127.0.0.1 or localhost for a port on this machine", host)
	}
	if uuidRe.MatchString(name) {
		return nil
	}
	if isReservedAlias(name) {
		return fmt.Errorf("host %q is reserved for Stacked infrastructure", host)
	}
	return nil
}

func validateUpstreamAddr(addr netip.Addr) error {
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("loopback address %s is not allowed; use 127.0.0.1 or localhost for a port on this machine", addr)
	case addr.IsUnspecified():
		return fmt.Errorf("unspecified address %s is not allowed", addr)
	case addr.IsLinkLocalUnicast():
		return fmt.Errorf("link-local address %s is not allowed", addr)
	case addr.IsMulticast(), addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("multicast address %s is not allowed", addr)
	case addr.Is4() && addr.As4()[0] == 255:
		return fmt.Errorf("broadcast address %s is not allowed", addr)
	}
	return nil
}

func isRFC1123Hostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			isLetter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			isDigit := r >= '0' && r <= '9'
			isHyphen := r == '-'
			if !isLetter && !isDigit && !isHyphen {
				return false
			}
			if isHyphen && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}
