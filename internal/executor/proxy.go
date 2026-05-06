package executor

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/slots"
)

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
type cachedDomain struct {
	Domain    string `json:"domain"`
	ServiceID string `json:"serviceId"`
	Port      int    `json:"port"`
}

// ensureProxy ensures the Caddy proxy infrastructure is running.
// Idempotent — safe to call on every proxy_config.
func ensureProxy() error {
	if err := ensureDir(proxyDir); err != nil {
		return fmt.Errorf("create proxy dir: %w", err)
	}

	// Ensure the stacked network exists
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	composePath := filepath.Join(proxyDir, "docker-compose.yml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		if err := writeFile(composePath, proxyCompose()); err != nil {
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

	// Start Caddy (no-op if already running)
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "up", "-d"); err != nil {
		return fmt.Errorf("start caddy: %s: %w", out, err)
	}

	return nil
}

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

	// Validate by writing the candidate to a sibling path and asking
	// Caddy to validate it inside the container. We can't use
	// `--config -` over stdin reliably across all Caddy versions, so
	// the side-file approach is portable.
	tmpPath := caddyfilePath + ".candidate"
	if err := writeFile(tmpPath, content); err != nil {
		return fmt.Errorf("write candidate Caddyfile: %w", err)
	}
	defer os.Remove(tmpPath)

	if err := exec.Command(
		"docker", "compose", "-f", filepath.Join(proxyDir, "docker-compose.yml"),
		"exec", "-T", "caddy",
		"caddy", "validate", "--config", "/etc/caddy/Caddyfile.candidate",
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
		"docker", "compose", "-f", filepath.Join(proxyDir, "docker-compose.yml"),
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

func parseDomains(raw []interface{}) []cachedDomain {
	out := make([]cachedDomain, 0, len(raw))
	for _, d := range raw {
		dm, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		domain, _ := dm["domain"].(string)
		serviceID, _ := dm["serviceId"].(string)
		if domain == "" || serviceID == "" {
			continue
		}
		port := 3000
		if p, ok := dm["port"].(float64); ok && p > 0 {
			port = int(p)
		}
		out = append(out, cachedDomain{Domain: domain, ServiceID: serviceID, Port: port})
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
		host := d.ServiceID
		if slot, ok := state[d.ServiceID]; ok && slot != slots.Legacy {
			host = d.ServiceID + "-" + string(slot)
		}
		fmt.Fprintf(&b, "%s {\n", d.Domain)
		fmt.Fprintf(&b, "    reverse_proxy %s:%d\n", host, d.Port)
		fmt.Fprintf(&b, "}\n\n")
	}
	return b.String()
}
