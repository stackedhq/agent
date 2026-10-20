package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- Auth gate sidecar lifecycle ---
//
// The gate (cmd/gate) runs as the `stacked-gate` service in the proxy
// compose project (see proxyCompose). The agent owns its config file;
// proxy_config writes it atomically, signals the gate, and waits until
// the gate reports it loaded exactly those bytes before reloading Caddy,
// so Caddy never forward_auths a domain the gate doesn't know yet. If the
// op then fails (the gate doesn't load it, or Caddy rejects or fails to
// reload its config), the previous gate config is restored the same way
// (restoreGateConfig), so Caddy's retained routes keep working.

const (
	// gateServiceName is the compose service, container name and DNS
	// name of the gate sidecar. Reserved as a network alias (aliases.go).
	gateServiceName = "stacked-gate"
	// gateUpstream is what Caddy dials for forward_auth and /__stacked/*.
	gateUpstream = gateServiceName + ":9876"
	// gateNetworkName is the internal network shared by Caddy and the gate.
	gateNetworkName = "stacked-gate-internal"
	// legacyGateService is the pre-rename compose service name. Its
	// container (proxy-gate-1, DNS name `gate`) is removed on reconcile.
	legacyGateService = "gate"
)

var (
	gateDir        = "/opt/stacked/gate"
	gateConfigPath = filepath.Join(gateDir, "config.json")

	// Test seams for the docker-touching steps of applyGateConfig.
	gateStartFn     = startGate
	gateSignalFn    = signalGate
	gateStatusFn    = queryGateStatus
	gateLoadTimeout = 15 * time.Second
	gatePollEvery   = 500 * time.Millisecond
)

// gateConfig mirrors cmd/gate's GateConfig for JSON serialization.
type gateConfig struct {
	Domains map[string]gateDomainEntry `json:"domains"`
}

type gateDomainEntry struct {
	Mode         string `json:"mode"`
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	ServiceName  string `json:"serviceName"`
}

// gateStatus is the JSON the gate prints for `stacked-agent gate status`.
type gateStatus struct {
	Loaded     bool   `json:"loaded"`
	ConfigHash string `json:"configHash"`
	Domains    int    `json:"domains"`
	Error      string `json:"error"`
}

// buildGateConfig derives the per-domain gate config from the (already
// sanitized) domain rows.
//
// The gate (and the Caddy site block) is per host, while the server's
// auth gate is per service, and multi-path routing can put several
// services on one host. Rather than key the gate on host+path (which
// would need per-path cookies and login routing), one host has one set
// of credentials. When two rows on the same host carry different gate
// credentials the host is left out of the gate config entirely and an
// error naming it is logged: the Caddyfile still sends that host through
// forward_auth, so the gate answers 403 for it (fail closed), while
// every other domain on the machine keeps working. Failing the whole op
// instead would brick proxy_config (and blue/green flips) for every
// site, including from an old domains.json. Rows on a gated host
// without a gate of their own stay behind the host's gate.
func buildGateConfig(parsed []cachedDomain) gateConfig {
	cfg := gateConfig{Domains: make(map[string]gateDomainEntry)}
	conflicted := make(map[string]bool)
	for _, d := range parsed {
		if d.AuthGateMode == "" || conflicted[d.Domain] {
			continue
		}
		name := d.ServiceName
		if name == "" {
			name = d.Domain
		}
		entry := gateDomainEntry{
			Mode:         d.AuthGateMode,
			Username:     d.AuthGateUsername,
			PasswordHash: d.AuthGatePasswordHash,
			ServiceName:  name,
		}
		if prev, ok := cfg.Domains[d.Domain]; ok {
			if prev.Mode != entry.Mode || prev.Username != entry.Username || prev.PasswordHash != entry.PasswordHash {
				delete(cfg.Domains, d.Domain)
				conflicted[d.Domain] = true
				log.Printf("proxy: auth gate disabled for %s (every request gets 403): it routes paths to services "+
					"with different auth gate credentials; use the same credentials for every gated service on "+
					"this domain or move one to its own domain", d.Domain)
			}
			continue
		}
		cfg.Domains[d.Domain] = entry
	}
	return cfg
}

// applyGateConfig writes config.json atomically (0600, readable by the
// gate, which runs as the agent's uid) and, when any domain is gated,
// makes sure the gate is running and has loaded exactly these bytes.
// With no gated domains the file is cleared to an empty config (the
// gate then denies everything) and nothing is waited on.
func applyGateConfig(cfg gateConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode gate config: %w", err)
	}
	return applyGateConfigBytes(data, len(cfg.Domains) > 0)
}

// applyGateConfigBytes is applyGateConfig for already-encoded config.
// gated says whether data gates any domain (so the gate must run and be
// seen to load it).
func applyGateConfigBytes(data []byte, gated bool) error {
	if err := ensureGateDir(); err != nil {
		return err
	}
	if err := writeFileAtomic(gateConfigPath, data, 0o600); err != nil {
		return fmt.Errorf("write gate config: %w", err)
	}
	if !gated {
		if err := gateSignalFn(); err != nil {
			log.Printf("proxy_config: auth gate reload signal (no gated domains): %v", err)
		}
		return nil
	}

	if err := gateStartFn(); err != nil {
		return fmt.Errorf("start auth gate: %w", err)
	}
	sigErr := gateSignalFn()
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	deadline := time.Now().Add(gateLoadTimeout)
	last := "no status"
	for {
		st, err := gateStatusFn()
		switch {
		case err != nil:
			last = err.Error()
		case st.ConfigHash == want:
			return nil
		case !st.Loaded:
			last = "not loaded: " + st.Error
		default:
			last = "loaded a different config"
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(gatePollEvery)
	}
	if sigErr != nil {
		return fmt.Errorf("auth gate did not load the new config within %s (reload signal failed: %v; last status: %s)", gateLoadTimeout, sigErr, last)
	}
	return fmt.Errorf("auth gate did not load the new config within %s (last status: %s)", gateLoadTimeout, last)
}

// gateConfigSnapshot is the gate config file as it was before a
// proxy_config op touched it, so a failed op can put it back.
type gateConfigSnapshot struct {
	data   []byte
	exists bool
}

// snapshotGateConfig reads the current gate config file. A missing file
// is a valid (deny-all) state and is recorded as such.
func snapshotGateConfig() (gateConfigSnapshot, error) {
	data, err := os.ReadFile(gateConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return gateConfigSnapshot{}, nil
	}
	if err != nil {
		return gateConfigSnapshot{}, err
	}
	return gateConfigSnapshot{data: data, exists: true}, nil
}

// restoreGateConfig puts the gate config back to snap the same way a
// normal apply does (atomic write, SIGHUP, and for a config that gates
// anything, waiting until the gate reports exactly those bytes), so the
// gate again knows every domain the previous Caddy config forward_auths.
// No-op when the file already holds snap. A snapshot of a missing file
// removes the file (the gate then denies everything, as before).
//
// The docker calls run under a fresh deadline (gateLoadTimeout plus the
// cleanup budget): restoring is cleanup and must work even when the op
// deadline is what made the Caddy step fail.
func restoreGateConfig(snap gateConfigSnapshot) error {
	cur, err := snapshotGateConfig()
	if err == nil && cur.exists == snap.exists && bytes.Equal(cur.data, snap.data) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), gateLoadTimeout+cleanupTimeout)
	defer cancel()
	restoreCtx := setOpContext(ctx)
	defer restoreCtx()

	if !snap.exists {
		if err := os.Remove(gateConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove gate config: %w", err)
		}
		if err := gateSignalFn(); err != nil {
			log.Printf("proxy_config: auth gate reload signal (restored missing config): %v", err)
		}
		return nil
	}
	var cfg gateConfig
	gated := json.Unmarshal(snap.data, &cfg) == nil && len(cfg.Domains) > 0
	return applyGateConfigBytes(snap.data, gated)
}

// ensureGateDir creates the gate's state dir owned by the agent, 0700.
// Created before any `compose up` so docker never auto-creates the bind
// source as root.
func ensureGateDir() error {
	if err := os.MkdirAll(gateDir, 0o700); err != nil {
		return fmt.Errorf("create gate dir: %w", err)
	}
	if err := os.Chmod(gateDir, 0o700); err != nil {
		log.Printf("proxy: chmod %s: %v", gateDir, err)
	}
	return nil
}

// startGate brings up the gate service (no-op when already running with
// the current definition).
func startGate() error {
	info, err := os.Stat(agentBinaryPath)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("agent binary %s not found; the gate runs from it", agentBinaryPath)
	}
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "up", "-d", gateServiceName); err != nil {
		return fmt.Errorf("compose up %s: %s: %w", gateServiceName, strings.TrimSpace(out), err)
	}
	return nil
}

// signalGate asks the gate to re-read its config now (it also polls
// every 5s).
func signalGate() error {
	if out, err := runCommandSilent("", "docker", "kill", "--signal", "HUP", gateServiceName); err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(out), err)
	}
	return nil
}

// queryGateStatus runs `stacked-agent gate status` inside the gate
// container, which reads the running gate's /healthz over loopback.
func queryGateStatus() (gateStatus, error) {
	out, err := runCommandSilent("", "docker", "exec", gateServiceName, "/stacked-agent", "gate", "status")
	if err != nil {
		return gateStatus{}, fmt.Errorf("%s: %w", strings.TrimSpace(out), err)
	}
	var st gateStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &st); err != nil {
		return gateStatus{}, fmt.Errorf("decode gate status %q: %w", strings.TrimSpace(out), err)
	}
	return st, nil
}

// removeLegacyGateContainer removes the pre-rename gate container
// (compose service `gate` in the proxy project, DNS name `gate` on the
// stacked network). Idempotent. Done explicitly because ensureProxy
// runs `compose up -d caddy`, and compose skips orphan removal when a
// service is named (verified on Compose v5).
func removeLegacyGateContainer() {
	out, err := runCommandSilent("", "docker", "ps", "-aq",
		"--filter", "label=com.docker.compose.project="+filepath.Base(proxyDir),
		"--filter", "label=com.docker.compose.service="+legacyGateService)
	if err != nil {
		return
	}
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return
	}
	args := append([]string{"rm", "-f"}, ids...)
	if out, err := runCommandSilent("", "docker", args...); err != nil {
		log.Printf("proxy: remove legacy gate container: %s: %v", strings.TrimSpace(out), err)
		return
	}
	log.Printf("proxy: removed legacy gate container(s) %s", strings.Join(ids, ", "))
}

// writeFileAtomic writes data to path via a temp file in the same
// directory (fsync, then rename), so readers see either the old or the
// new content, never a partial file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
