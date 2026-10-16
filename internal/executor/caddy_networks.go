package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// --- Runtime-attached Caddy networks ---
//
// DokployCaddyAttachNetwork joins the Stacked Caddy container to a network
// with `docker network connect`. That attachment lives only on the
// container: when `docker compose up -d` recreates Caddy (new image
// digest, new gate network, any compose change after a self-update) the
// new container comes up with just the compose-defined networks, and
// Dokploy-takeover sites go dark. The attached names are therefore
// persisted in caddyNetworksPath and re-applied by ensureProxy after
// every `compose up`.

// caddyNetworksPath is the state file listing networks attached to Caddy
// at runtime. Package var so tests can point it at a temp dir.
var caddyNetworksPath = filepath.Join(proxyDir, "caddy-networks.json")

type caddyNetworksState struct {
	Networks []string `json:"networks"`
}

// Test seams for the docker-touching steps.
var (
	caddyContainerAnyFn   = stackedCaddyContainerAnyID
	caddyRunningIDFn      = stackedCaddyContainerID
	inspectNetworksFn     = inspectContainerNetworks
	connectCaddyNetworkFn = connectNetwork
)

// isComposeOwnedCaddyNetwork reports networks that Caddy gets from the
// proxy compose file itself and that must never be recorded as runtime
// attachments.
func isComposeOwnedCaddyNetwork(name string) bool {
	return name == "stacked" || name == gateNetworkName || name == filepath.Base(proxyDir)+"_default"
}

func loadCaddyNetworks() ([]string, error) {
	data, err := os.ReadFile(caddyNetworksPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var st caddyNetworksState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode %s: %w", caddyNetworksPath, err)
	}
	out := make([]string, 0, len(st.Networks))
	for _, n := range st.Networks {
		if isSafeNetworkName(n) && !isComposeOwnedCaddyNetwork(n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func saveCaddyNetworks(names []string) error {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		if isSafeNetworkName(n) && !isComposeOwnedCaddyNetwork(n) {
			set[n] = true
		}
	}
	st := caddyNetworksState{Networks: make([]string, 0, len(set))}
	for n := range set {
		st.Networks = append(st.Networks, n)
	}
	sort.Strings(st.Networks)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(caddyNetworksPath, append(data, '\n'), 0o600)
}

// rememberCaddyNetwork records name as a runtime attachment.
func rememberCaddyNetwork(name string) error {
	cur, err := loadCaddyNetworks()
	if err != nil {
		return err
	}
	for _, n := range cur {
		if n == name {
			return nil
		}
	}
	return saveCaddyNetworks(append(cur, name))
}

// forgetCaddyNetwork removes name from the runtime attachments.
func forgetCaddyNetwork(name string) error {
	cur, err := loadCaddyNetworks()
	if err != nil {
		return err
	}
	keep := cur[:0]
	found := false
	for _, n := range cur {
		if n == name {
			found = true
			continue
		}
		keep = append(keep, n)
	}
	if !found {
		return nil
	}
	return saveCaddyNetworks(keep)
}

// recordCaddyRuntimeNetworks runs before `compose up` in ensureProxy: it
// reads the networks of the existing Caddy container (running or not)
// and persists any that the compose file doesn't define. This migrates
// machines that attached a network before the state file existed, so the
// recreate that follows doesn't lose it. No Caddy container yet is fine.
func recordCaddyRuntimeNetworks() error {
	id, err := caddyContainerAnyFn()
	if err != nil || id == "" {
		return err
	}
	nets, err := inspectNetworksFn(id)
	if err != nil {
		return err
	}
	var extra []string
	for _, n := range nets {
		if isSafeNetworkName(n) && !isComposeOwnedCaddyNetwork(n) {
			extra = append(extra, n)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	cur, err := loadCaddyNetworks()
	if err != nil {
		return err
	}
	merged := append(cur, extra...)
	if len(dedupe(merged)) == len(cur) {
		return nil // nothing new
	}
	log.Printf("proxy: recording runtime caddy network(s) %s", strings.Join(extra, ", "))
	return saveCaddyNetworks(merged)
}

// reconnectCaddyNetworks runs after `compose up` in ensureProxy and
// re-attaches Caddy to every persisted runtime network. A network that
// no longer exists is logged and kept (it may come back, e.g. when
// Dokploy's swarm is restarted); a detach op is what forgets it.
func reconnectCaddyNetworks() error {
	nets, err := loadCaddyNetworks()
	if err != nil || len(nets) == 0 {
		return err
	}
	id, err := caddyRunningIDFn()
	if err != nil {
		return err
	}
	var errs []string
	for _, n := range nets {
		if err := connectCaddyNetworkFn(n, id); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", n, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("reconnect caddy networks: %s", strings.Join(errs, "; "))
	}
	return nil
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// stackedCaddyContainerAnyID is stackedCaddyContainerID without the
// "must be running" requirement. Returns "" when there's no container.
func stackedCaddyContainerAnyID() (string, error) {
	out, err := runCommandSilent(proxyDir, "docker", "compose", "ps", "-a", "-q", "caddy")
	if err != nil {
		return "", fmt.Errorf("locate stacked caddy container: %s: %w", strings.TrimSpace(out), err)
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

// inspectContainerNetworks returns the names of the networks a container
// is attached to.
func inspectContainerNetworks(container string) ([]string, error) {
	out, err := runDockerSilent("inspect", "--format", "{{json .NetworkSettings.Networks}}", container)
	if err != nil {
		return nil, fmt.Errorf("inspect %s networks: %s: %w", container, strings.TrimSpace(out), err)
	}
	var nets map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &nets); err != nil {
		return nil, fmt.Errorf("decode %s networks: %w", container, err)
	}
	names := make([]string, 0, len(nets))
	for n := range nets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// connectNetwork attaches container to network; already attached is
// success.
func connectNetwork(network, container string) error {
	out, err := runDockerSilent("network", "connect", network, container)
	if err != nil {
		if isAlreadyAttached(out) {
			return nil
		}
		return fmt.Errorf("%s: %w", strings.TrimSpace(out), err)
	}
	return nil
}

func isAlreadyAttached(out string) bool {
	return strings.Contains(out, "already exists in network") || strings.Contains(out, "is already attached")
}
