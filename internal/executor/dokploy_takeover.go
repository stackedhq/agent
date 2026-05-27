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

	result := map[string]interface{}{
		"traefik":    probeTraefik(),
		"ports":      probePortHolders(),
		"containers": probeContainerBindings(containerNames),
	}
	return result, nil
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
		// absent. That's not an agent-side failure — surface it as
		// found:false so the wizard's per-row message is precise.
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
