package executor

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Dokploy → Stacked routing takeover.
//
// Three operations back the dashboard's "route-only" import flow when
// the user's Dokploy install routes via its internal Traefik (the
// common case — no host-published ports on the app containers):
//
//   - dokploy_takeover_probe (read-only): report Traefik container
//     state, who holds 80/443, and per-container `docker inspect`
//     port bindings. The dashboard uses this to resolve the *real*
//     host port for each Dokploy domain instead of trusting Dokploy's
//     `ports[]` database record (which is often empty for
//     Traefik-routed apps).
//
//   - dokploy_traefik_stop: `docker stop dokploy-traefik` and clear
//     the restart policy so it doesn't come back on daemon restart.
//     Reversible — see start. This is destructive: it breaks every
//     Dokploy domain that hasn't been migrated yet, so the dashboard
//     only enqueues this op behind an explicit user confirmation.
//
//   - dokploy_traefik_start: the inverse. Restores restart policy
//     and starts the container. One-click rollback affordance on the
//     wizard's done step.
//
// Container name is hardcoded to `dokploy-traefik`. Some self-hosted
// or older Dokploy variants name it differently (e.g. plain
// `traefik`); the probe falls back to looking for any container whose
// image is a known Traefik image and whose name contains "traefik" if
// the canonical name isn't present. The stop/start handlers only
// operate on `dokploy-traefik` — if the install uses a non-default
// name, the dashboard will surface the probe result and the user can
// stop it themselves.

// dokployTraefikContainer is the canonical name Dokploy gives its
// Traefik container. Self-hosted variants occasionally rename it;
// the probe reports `state: null` in that case so the dashboard can
// surface a precise "no Traefik container found" message.
const dokployTraefikContainer = "dokploy-traefik"

// DokployTakeoverProbe inspects the host for everything the
// dashboard's route-select step needs to render real upstream ports
// and warn about port conflicts. Read-only — does not modify any
// container.
//
// Payload:
//
//	{ "containerNames": ["<dokploy-app-name>", ...] }
//
// Result:
//
//	{
//	  "traefik": {
//	    "state":       "running" | "stopped" | null,
//	    "containerId": string | null,
//	  },
//	  "ports": {
//	    "80":  { "free": bool, "heldBy": string | null },
//	    "443": { "free": bool, "heldBy": string | null },
//	  },
//	  "containers": {
//	    "<name>": {
//	      "found":    bool,
//	      "bindings": [ { "containerPort": int, "protocol": "tcp"|"udp",
//	                      "hostIp": string,    "hostPort": int }, ... ]
//	    }
//	  }
//	}
func (e *Executor) DokployTakeoverProbe(op client.Operation) (map[string]interface{}, error) {
	containerNamesRaw, _ := op.Payload["containerNames"].([]interface{})
	containerNames := make([]string, 0, len(containerNamesRaw))
	for _, raw := range containerNamesRaw {
		name, ok := raw.(string)
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		// Defensive: container names follow [a-zA-Z0-9_.-]+. Anything
		// outside that set is either a typo or a payload tampering
		// attempt — skip rather than feed to docker inspect.
		if name == "" || !isSafeContainerName(name) {
			continue
		}
		containerNames = append(containerNames, name)
	}

	swarmInfo := probeSwarm()
	result := map[string]interface{}{
		"traefik":    probeTraefik(),
		"ports":      probePortHolders(),
		"swarm":      swarmInfo,
		"containers": probeContainerBindings(containerNames),
	}
	return result, nil
}

// probeSwarm reports whether this docker daemon is a swarm node and,
// if so, which network the Dokploy stack uses. The dashboard branches
// the takeover wizard on `active`: in swarm mode there are no
// host-published ports for app containers (Traefik dials over the
// overlay), so the soft-migration flow attaches Stacked Caddy to the
// same overlay network instead of expecting loopback host ports.
//
// `network` is best-effort: we read it off the `dokploy-traefik`
// container's `NetworkSettings.Networks` map and pick the first
// non-default entry. Returns null if Traefik isn't present (then the
// dashboard has no install to migrate from anyway).
func probeSwarm() map[string]interface{} {
	active := false
	if out, err := runCommandSilent("", "docker", "info", "--format", "{{.Swarm.LocalNodeState}}"); err == nil {
		if strings.TrimSpace(out) == "active" {
			active = true
		}
	}
	var network interface{} = nil
	if name := detectDokployNetwork(); name != "" {
		network = name
	}
	return map[string]interface{}{
		"active":  active,
		"network": network,
	}
}

// detectDokployNetwork reads `dokploy-traefik`'s attached networks
// and returns the first non-default one. Default docker bridges
// (bridge/host/none/ingress/docker_gwbridge) are skipped so we don't
// mistake them for the app overlay. Empty string if Traefik isn't
// present or has no usable network.
func detectDokployNetwork() string {
	raw, err := runDockerInspect("--format", "{{json .NetworkSettings.Networks}}", dokployTraefikContainer)
	if err != nil {
		return ""
	}
	var networks map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &networks); err != nil {
		return ""
	}
	defaults := map[string]bool{
		"bridge":          true,
		"host":            true,
		"none":            true,
		"ingress":         true,
		"docker_gwbridge": true,
	}
	// Sort for determinism — docker's JSON output isn't ordered.
	names := make([]string, 0, len(networks))
	for n := range networks {
		names = append(names, n)
	}
	sort.Strings(names)
	// Prefer anything containing "dokploy" first, then fall back to
	// any non-default network. Some self-hosted setups rename the
	// network; the dokploy substring catches the canonical case
	// without hardcoding `dokploy-network`.
	for _, n := range names {
		if defaults[n] {
			continue
		}
		if strings.Contains(n, "dokploy") {
			return n
		}
	}
	for _, n := range names {
		if defaults[n] {
			continue
		}
		return n
	}
	return ""
}

// DokployCaddyAttachNetwork connects the Stacked Caddy container to
// the Dokploy overlay network so it can dial app services by name
// (`<service>:<port>`) over docker's embedded DNS — the same path
// Dokploy's own Traefik uses. Idempotent: re-running after a
// successful attach is a no-op.
//
// Payload:
//
//	{ "network": "<network-name>" }
//
// The dashboard sources `network` from a prior probe result so we
// don't have to redetect here. If the payload omits it we fall back
// to detection for safety.
func (e *Executor) DokployCaddyAttachNetwork(op client.Operation) error {
	network, _ := op.Payload["network"].(string)
	network = strings.TrimSpace(network)
	if network == "" {
		network = detectDokployNetwork()
	}
	if network == "" {
		return fmt.Errorf("no dokploy overlay network detected on this host")
	}
	if !isSafeNetworkName(network) {
		return fmt.Errorf("unsafe network name: %q", network)
	}
	container, err := stackedCaddyContainerID()
	if err != nil {
		return err
	}
	out, err := runDockerSilent("network", "connect", network, container)
	if err != nil {
		// docker errors with "already exists in network" when the
		// container is already attached. That's the desired end
		// state — treat as success.
		if strings.Contains(out, "already exists in network") || strings.Contains(out, "is already attached") {
			log.Printf("dokploy_caddy_attach_network: caddy already attached to %s", network)
			return nil
		}
		return fmt.Errorf("network connect %s: %s: %w", network, strings.TrimSpace(out), err)
	}
	log.Printf("dokploy_caddy_attach_network: attached caddy to %s", network)
	return nil
}

// DokployCaddyDetachNetwork is the inverse, used on rollback. Also
// idempotent — disconnecting a container that isn't on the network
// returns success.
func (e *Executor) DokployCaddyDetachNetwork(op client.Operation) error {
	network, _ := op.Payload["network"].(string)
	network = strings.TrimSpace(network)
	if network == "" {
		network = detectDokployNetwork()
	}
	if network == "" {
		return nil // nothing to detach from
	}
	if !isSafeNetworkName(network) {
		return fmt.Errorf("unsafe network name: %q", network)
	}
	container, err := stackedCaddyContainerID()
	if err != nil {
		return err
	}
	out, err := runDockerSilent("network", "disconnect", network, container)
	if err != nil {
		if strings.Contains(out, "is not connected to network") || strings.Contains(out, "not connected") {
			return nil
		}
		return fmt.Errorf("network disconnect %s: %s: %w", network, strings.TrimSpace(out), err)
	}
	log.Printf("dokploy_caddy_detach_network: detached caddy from %s", network)
	return nil
}

// stackedCaddyContainerID resolves the Stacked Caddy container ID via
// `docker compose ps -q` in the proxy compose project. Returns an
// error if Caddy isn't running — the takeover path requires Caddy
// up so it can hold 80/443 the instant Dokploy Traefik releases them.
func stackedCaddyContainerID() (string, error) {
	out, err := runCommandSilent(proxyDir, "docker", "compose", "ps", "-q", "caddy")
	if err != nil {
		return "", fmt.Errorf("locate stacked caddy container: %s: %w", strings.TrimSpace(out), err)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		return "", fmt.Errorf("stacked caddy is not running on this host")
	}
	// `docker compose ps -q` can emit multiple lines if the service
	// has >1 replica. Caddy is single-replica; take the first.
	if nl := strings.IndexByte(id, '\n'); nl >= 0 {
		id = id[:nl]
	}
	return id, nil
}

// isSafeNetworkName mirrors isSafeContainerName but accepts the
// slightly broader docker network naming rules (same charset in
// practice). Defense-in-depth even though we pass via exec.Command,
// not a shell.
func isSafeNetworkName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// DokployTraefikStop stops the dokploy-traefik container and clears
// its restart policy so a docker daemon restart doesn't bring it back.
//
// We deliberately do NOT remove the container — leaving it stopped
// preserves its config, mounts, and network attachments so the
// inverse `start` op restores the exact same Traefik instance.
// Removing it would force the user to redeploy from Dokploy to
// recover routing, which is far more disruptive than they probably
// expect from a button labeled "Re-enable Dokploy Traefik".
func (e *Executor) DokployTraefikStop(op client.Operation) error {
	if !dokployTraefikExists() {
		// Idempotent: nothing to do. The dashboard treats this as
		// success because the user's intent ("Traefik should not be
		// running") is already satisfied.
		log.Printf("dokploy_traefik_stop: container %q not present, nothing to do",
			dokployTraefikContainer)
		return nil
	}

	// Clear restart policy first. If we stopped the container before
	// flipping the policy, a daemon hiccup could race-restart it
	// before our update lands. Order matters.
	if out, err := runDockerSilent("update", "--restart=no", dokployTraefikContainer); err != nil {
		return fmt.Errorf("clear restart policy on %s: %s: %w",
			dokployTraefikContainer, strings.TrimSpace(out), err)
	}
	if out, err := runDockerSilent("stop", dokployTraefikContainer); err != nil {
		return fmt.Errorf("stop %s: %s: %w",
			dokployTraefikContainer, strings.TrimSpace(out), err)
	}
	log.Printf("dokploy_traefik_stop: stopped and disabled %s", dokployTraefikContainer)
	return nil
}

// DokployTraefikStart restarts dokploy-traefik with its restart
// policy back to `unless-stopped` (Dokploy's default). Rollback
// counterpart to DokployTraefikStop.
//
// If Stacked Caddy is currently bound to 80/443, this op will
// fail at the docker level (port already in use) — which is what we
// want. The dashboard renders the error inline; the user knows to
// stop Stacked Caddy first if they really want full rollback.
func (e *Executor) DokployTraefikStart(op client.Operation) error {
	if !dokployTraefikExists() {
		// No container to start. Surface clearly so the dashboard
		// can tell the user the Traefik install was removed and
		// they need to reinstall it via Dokploy.
		return fmt.Errorf("container %q does not exist on this host", dokployTraefikContainer)
	}
	if out, err := runDockerSilent("update", "--restart=unless-stopped", dokployTraefikContainer); err != nil {
		return fmt.Errorf("restore restart policy on %s: %s: %w",
			dokployTraefikContainer, strings.TrimSpace(out), err)
	}
	if out, err := runDockerSilent("start", dokployTraefikContainer); err != nil {
		return fmt.Errorf("start %s: %s: %w",
			dokployTraefikContainer, strings.TrimSpace(out), err)
	}
	log.Printf("dokploy_traefik_start: restarted %s", dokployTraefikContainer)
	return nil
}

// --- helpers ---------------------------------------------------------

// probeTraefik reports the dokploy-traefik container's state. Returns
// JSON with `state: null` when the container doesn't exist at all so
// the dashboard can distinguish "stopped" from "never installed".
func probeTraefik() map[string]interface{} {
	out, err := runDockerInspect("--format", "{{.Id}}|{{.State.Status}}", dokployTraefikContainer)
	if err != nil {
		return map[string]interface{}{"state": nil, "containerId": nil}
	}
	line := strings.TrimSpace(out)
	parts := strings.SplitN(line, "|", 2)
	if len(parts) != 2 {
		return map[string]interface{}{"state": nil, "containerId": nil}
	}
	id, status := parts[0], parts[1]
	// docker reports states like running, exited, paused, restarting.
	// Collapse to the two states the dashboard cares about; anything
	// not "running" is treated as "stopped" because from the routing
	// perspective the port is free either way.
	state := "stopped"
	if status == "running" {
		state = "running"
	}
	return map[string]interface{}{"state": state, "containerId": id}
}

// probePortHolders reports who (if anyone) holds 80 and 443. Reuses
// the existing lookupPortHolderContainer helper from proxy.go for
// docker-managed holders. Non-docker holders (systemd nginx, etc.)
// surface as `free: false` with `heldBy: null`.
func probePortHolders() map[string]interface{} {
	check := func(port int) map[string]interface{} {
		free := portIsFree(port)
		heldBy := interface{}(nil)
		if !free {
			if name := lookupPortHolderContainer(port); name != "" {
				heldBy = name
			}
		}
		return map[string]interface{}{"free": free, "heldBy": heldBy}
	}
	return map[string]interface{}{
		"80":  check(80),
		"443": check(443),
	}
}

// portIsFree tests whether the agent can bind 0.0.0.0:<port>. A bind
// that fails means somebody holds it (which is what the dashboard
// wants to know). We bind + close immediately; the window is too
// short for a meaningful race with a Caddy reload.
func portIsFree(port int) bool {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// dockerPortBinding mirrors a row of `docker inspect`'s
// NetworkSettings.Ports map after we flatten it.
type dockerPortBinding struct {
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIp"`
	HostPort      int    `json:"hostPort"`
}

// probeContainerBindings inspects each requested container and
// returns a map keyed by container name. Containers that don't exist
// on this host get `found: false, bindings: []` — the dashboard uses
// that to render a "container not on this machine" reason next to
// the row, which is far more actionable than a generic probe error.
func probeContainerBindings(names []string) map[string]interface{} {
	out := make(map[string]interface{}, len(names))
	for _, name := range names {
		out[name] = inspectOneContainer(name)
	}
	return out
}

// inspectSwarmService falls back to `docker service inspect` when
// `docker inspect` (which only matches containers) misses. Dokploy in
// swarm mode names each app as a service whose actual task containers
// are `<name>.<replica>.<taskid>` — `docker inspect <name>` returns
// the "No such object" error and the wizard would otherwise report
// the app as missing.
//
// On hit we return `swarm: true` and the service's first declared
// target port (best-effort, sourced from `Endpoint.Spec.Ports` if
// published, otherwise from `ContainerSpec` exposed ports). The
// dashboard already knows the canonical app port from Dokploy's DB
// (`services[].port`), so `targetPort` here is informational — what
// matters is that `found: true, swarm: true` lets the wizard pick
// the overlay-network upstream path instead of the loopback one.
func inspectSwarmService(name string) (map[string]interface{}, bool) {
	raw, err := runDockerSilent("service", "inspect", "--format", "{{json .Endpoint.Spec.Ports}}", name)
	if err != nil {
		return nil, false
	}
	targetPort := 0
	var ports []struct {
		TargetPort    int    `json:"TargetPort"`
		PublishedPort int    `json:"PublishedPort"`
		Protocol      string `json:"Protocol"`
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" && trimmed != "null" {
		if err := json.Unmarshal([]byte(trimmed), &ports); err == nil && len(ports) > 0 {
			targetPort = ports[0].TargetPort
		}
	}
	result := map[string]interface{}{
		"found":    true,
		"swarm":    true,
		"bindings": []dockerPortBinding{},
	}
	if targetPort > 0 {
		result["targetPort"] = targetPort
	}
	return result, true
}

func inspectOneContainer(name string) map[string]interface{} {
	// `docker inspect --format '{{json .NetworkSettings.Ports}}'`
	// gives us the binding table verbatim. Format is:
	//   { "3000/tcp": [ {"HostIp": "0.0.0.0", "HostPort": "8081"} ],
	//     "9090/tcp": null }
	// `null` means the port is exposed by the image but not
	// published — exactly the case the dashboard needs to flag as
	// unresolvable for traefik-target rows.
	raw, err := runDockerInspect("--format", "{{json .NetworkSettings.Ports}}", name)
	if err != nil {
		// `docker inspect` returns non-zero when the container is
		// absent. Before reporting missing, check whether the name
		// matches a swarm service — Dokploy in swarm mode names apps
		// as services, not containers.
		if svc, ok := inspectSwarmService(name); ok {
			return svc
		}
		return map[string]interface{}{
			"found":    false,
			"bindings": []dockerPortBinding{},
		}
	}
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		// We found the container but couldn't parse its port table.
		// That's a real bug — log it loudly and report empty
		// bindings so the wizard at least surfaces "no host
		// binding" rather than silently mismatching.
		log.Printf("dokploy_takeover_probe: parse ports for %s: %v", name, err)
		return map[string]interface{}{
			"found":    true,
			"bindings": []dockerPortBinding{},
		}
	}
	return map[string]interface{}{
		"found":    true,
		"bindings": bindings,
	}
}

// parseDockerPorts turns the raw JSON from
// `.NetworkSettings.Ports` into a flat list of bindings. Sorted for
// stable test output. Ignores rows with null/empty host bindings
// (the wizard correctly treats those as "no host port published").
func parseDockerPorts(raw string) ([]dockerPortBinding, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return []dockerPortBinding{}, nil
	}
	var portMap map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	if err := json.Unmarshal([]byte(raw), &portMap); err != nil {
		return nil, fmt.Errorf("unmarshal NetworkSettings.Ports: %w", err)
	}
	out := make([]dockerPortBinding, 0, len(portMap))
	for spec, hostBindings := range portMap {
		// spec looks like "3000/tcp"
		slash := strings.IndexByte(spec, '/')
		if slash < 0 {
			continue
		}
		containerPort, err := parsePositiveInt(spec[:slash])
		if err != nil {
			continue
		}
		proto := spec[slash+1:]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		for _, hb := range hostBindings {
			port, err := parsePositiveInt(hb.HostPort)
			if err != nil {
				continue
			}
			out = append(out, dockerPortBinding{
				ContainerPort: containerPort,
				Protocol:      proto,
				HostIP:        hb.HostIP,
				HostPort:      port,
			})
		}
	}
	// Stable order: by containerPort, then hostPort. The dashboard
	// picks the IPv4 binding itself; we just need determinism.
	sort.Slice(out, func(i, j int) bool {
		if out[i].ContainerPort != out[j].ContainerPort {
			return out[i].ContainerPort < out[j].ContainerPort
		}
		return out[i].HostPort < out[j].HostPort
	})
	return out, nil
}

// dokployTraefikExists checks whether the canonical container is
// present (running OR stopped). Cheap: one docker inspect.
func dokployTraefikExists() bool {
	_, err := runDockerInspect("--format", "{{.Id}}", dokployTraefikContainer)
	return err == nil
}

// runDockerSilent runs `docker <args...>` and returns combined output.
// Mirrors the shape of `runCommandSilent` from proxy.go but without
// requiring a working directory — we operate on container names, not
// compose projects.
func runDockerSilent(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// isSafeContainerName matches docker's own naming rules:
// [a-zA-Z0-9][a-zA-Z0-9_.-]*. Cheap rejection of anything that could
// be interpreted as a shell metacharacter, even though we pass these
// to exec.Command directly (which doesn't shell-out, but defense in
// depth costs nothing).
func isSafeContainerName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
			if i == 0 {
				// docker rejects leading separators
				return false
			}
		default:
			return false
		}
	}
	return true
}

// parsePositiveInt parses a port-shaped string. Empty / non-numeric /
// negative → error. Used both for container-side port specs ("3000")
// and host-side bindings.
func parsePositiveInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("non-numeric: %q", s)
		}
		n = n*10 + int(r-'0')
		if n > 65535 {
			return 0, fmt.Errorf("port out of range: %q", s)
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("non-positive: %q", s)
	}
	return n, nil
}
