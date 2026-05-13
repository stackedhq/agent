package executor

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	return ensureProxy()
}

// ensureProxy ensures the Caddy proxy infrastructure is running.
// Idempotent — safe to call on every proxy_config.
//
// Before invoking `docker compose up` we run a port preflight on
// the host's :80 and :443 listeners. A successful `compose up` is
// idempotent when ports are already bound by *our* Caddy (the
// existing process owns them), but fails fatally when *another*
// process owns them — the docker daemon returns a raw
// "Bind for 0.0.0.0:80 failed: port is already allocated" string.
//
// We catch that case up-front and return a typed *ProxyConfigError
// so the server can render an actionable banner ("port 80 in use by
// '<container>'") instead of leaving every domain stuck on
// "Origin cert: issuing".
func ensureProxy() error {
	if err := ensureDir(proxyDir); err != nil {
		return fmt.Errorf("create proxy dir: %w", err)
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

	// Port preflight — see doc comment above. Skip if our Caddy
	// container is already running, since *we* are the legitimate
	// owner of those binds in that case and `compose up` will be a
	// no-op.
	if !caddyContainerRunning() {
		if perr := checkPortConflict(); perr != nil {
			return perr
		}
	}

	// Start Caddy (no-op if already running)
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "up", "-d"); err != nil {
		// Last-line check: in case the preflight missed something
		// (race window, IPv6-only bind, etc.), surface a typed
		// port_in_use error if the daemon's message looks like one.
		if port, holder := parsePortInUseFromDocker(out); port != 0 {
			return &ProxyConfigError{
				Code:    "port_in_use",
				Port:    port,
				Holder:  holder,
				Message: fmt.Sprintf("start caddy: port %d already in use", port),
			}
		}
		return fmt.Errorf("start caddy: %s: %w", out, err)
	}

	return nil
}

// checkPortConflict tries to bind 80 and 443 briefly. A successful
// bind proves no one else is on the port. A bind error is the signal
// to identify the docker container holding it (best-effort) and
// return a typed ProxyConfigError.
func checkPortConflict() *ProxyConfigError {
	for _, port := range []int{80, 443} {
		if err := probePort(port); err != nil {
			holder := lookupPortHolderContainer(port)
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
	}
	return nil
}

// probePort attempts a transient listen on the given port (IPv4 +
// IPv6) and immediately closes. Any error means something owns it.
func probePort(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	_ = l.Close()
	// Tiny pause to ensure the socket is fully released before we
	// hand the port back to docker compose up.
	time.Sleep(20 * time.Millisecond)
	return nil
}

// caddyContainerRunning checks whether our Caddy container is
// currently up. A `compose up -d` on an already-running container
// re-uses the existing binds without conflict, so we can skip the
// preflight in that case.
func caddyContainerRunning() bool {
	out, err := exec.Command("docker", "compose", "-f",
		filepath.Join(proxyDir, "docker-compose.yml"),
		"ps", "--status=running", "--quiet").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// lookupPortHolderContainer asks docker which container publishes the
// given port on the host, if any. Returns "" if no docker container
// claims it (the holder might be a systemd service, nginx on the
// host, etc., in which case we can't name it cheaply).
func lookupPortHolderContainer(port int) string {
	out, err := exec.Command("docker", "ps",
		"--filter", fmt.Sprintf("publish=%d", port),
		"--format", "{{.Names}}").Output()
	if err != nil {
		return ""
	}
	names := strings.Fields(strings.TrimSpace(string(out)))
	if len(names) == 0 {
		return ""
	}
	// Filter out our own Caddy if it shows up (it shouldn't given the
	// caddyContainerRunning guard, but belt-and-braces).
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
	return port, lookupPortHolderContainer(port)
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

	if err := ensureProxy(); err != nil {
		return fmt.Errorf("ensure proxy: %w", err)
	}

	parsed := parseDomains(domains)
	if err := persistDomains(parsed); err != nil {
		// Persistence failure shouldn't block the reload — the in-memory
		// regen below still works. Log and continue.
		log.Printf("proxy_config: persist domains.json failed (non-fatal): %v", err)
	}

	if err := writeAndReloadCaddyfile(parsed); err != nil {
		return err
	}
	log.Printf("Caddy config updated for %d domain(s)", len(parsed))
	return nil
}

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
	if err := ensureProxy(); err != nil {
		return fmt.Errorf("ensure proxy: %w", err)
	}
	return writeAndReloadCaddyfile(parsed)
}

// writeAndReloadCaddyfile is the shared finishing step for both the
// server-driven `proxy_config` op and the agent-internal flip during a
// rolling deploy. It:
//
//   1. Generates the Caddyfile content (slot-aware, via slots.All()).
//   2. `caddy validate`s the new file inside the running Caddy
//      container BEFORE writing it. Without this, a malformed file
//      could cause the next reload to fail and force a fall-back
//      restart that drops traffic for every service on the box.
//   3. Writes the file.
//   4. Reloads Caddy. On reload failure, restores the previous file
//      and re-reloads — we never let a bad Caddyfile linger on disk
//      because Caddy reloads on container restart at boot too.
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
	content := generateCaddyfile(parsed, state)

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
	writeCmd := exec.Command(
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
		_ = exec.Command(
			"docker", "compose", "-f", composeFile,
			"exec", "-T", "caddy",
			"rm", "-f", candidateInContainer,
		).Run()
	}()

	if err := exec.Command(
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

	if err := exec.Command(
		"docker", "compose", "-f", composeFile,
		"exec", "-T", "caddy",
		"caddy", "reload", "--config", "/etc/caddy/Caddyfile",
	).Run(); err != nil {
		// Reload failed despite validate passing — rare, but possible
		// (e.g. a runtime cert issue). Restore the previous file so
		// the next boot reload sees known-good config.
		if len(prev) > 0 {
			_ = os.WriteFile(caddyfilePath, prev, 0644)
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

		switch {
		case serviceID != "":
			// Service-backed. Default port matches the historical
			// fallback (most services listen on 3000).
			if port == 0 {
				port = 3000
			}
			out = append(out, cachedDomain{
				Domain:    domain,
				ServiceID: serviceID,
				Port:      port,
			})
		case host != "" && port > 0:
			// Port-bound. Scheme defaults to http; only http and
			// https are accepted (the server validates this too).
			scheme, _ := dm["scheme"].(string)
			if scheme != "http" && scheme != "https" {
				scheme = "http"
			}
			out = append(out, cachedDomain{
				Domain: domain,
				Host:   host,
				Port:   port,
				Scheme: scheme,
			})
		default:
			// Neither shape fully populated; skip.
			continue
		}
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
	var b strings.Builder
	b.WriteString("# Managed by Stacked \u2014 do not edit manually\n\n")
	for _, d := range parsed {
		fmt.Fprintf(&b, "%s {\n", d.Domain)
		if d.isPortBound() {
			// Port-bound. Resolve the user-typed host to something
			// reachable from *inside* the Caddy container. Then
			// format with proper IPv6 bracketing. See
			// renderUpstreamHostPort for the rules.
			hp := renderUpstreamHostPort(d.Host, d.Port)
			if d.Scheme == "https" {
				fmt.Fprintf(&b, "    reverse_proxy https://%s\n", hp)
			} else {
				fmt.Fprintf(&b, "    reverse_proxy %s\n", hp)
			}
		} else {
			host := d.ServiceID
			if slot, ok := state[d.ServiceID]; ok && slot != slots.Legacy {
				host = d.ServiceID + "-" + string(slot)
			}
			fmt.Fprintf(&b, "    reverse_proxy %s:%d\n", host, d.Port)
		}
		fmt.Fprintf(&b, "}\n\n")
	}
	return b.String()
}

// renderUpstreamHostPort produces a Caddy-safe "host:port" token for a
// port-bound upstream. Two non-obvious rewrites happen here:
//
//   1. Loopback rewrite. The Caddy container is on a docker bridge
//      network, so the user-typed "127.0.0.1" and "localhost" resolve
//      to the *container itself*, not the host. We rewrite both to
//      "host.docker.internal", which the compose file pins to the
//      host's gateway via `extra_hosts: host-gateway`. This is the
//      only place the user's intent ("this VPS") matches what they
//      typed without it.
//
//   2. IPv6 bracketing. Caddy expects `[2001:db8::1]:443` for IPv6
//      literals. A bare `2001:db8::1:443` is ambiguous and rejected
//      by the parser. Detected by presence of ":" in the host string
//      and absence of a leading "[".
func renderUpstreamHostPort(host string, port int) string {
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		host = "host.docker.internal"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
