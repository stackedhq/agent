package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/logs"
)

// ProbeResult is the post-deploy health check summary the agent attaches
// to the deploy operation's StatusUpdate.Result. It feeds the dashboard's
// port-mismatch banner so users don't have to SSH in to discover that
// their app is binding to a different port than Caddy is forwarding to.
type ProbeResult struct {
	Ok           bool   `json:"probeOk"`
	Error        string `json:"probeError,omitempty"`
	ExposedPorts []int  `json:"exposedPorts"`
}

// probeTimeoutBudget defines the 3-retry, 1s-spacing TCP probe schedule.
// Total worst case ~5s (3 dials at 1s timeout + 2 sleep gaps).
const (
	probeAttempts    = 3
	probeDialTimeout = 1500 * time.Millisecond
	probeRetryDelay  = 1 * time.Second
)

// dialTCP attempts a single TCP connect with a bounded timeout.
func dialTCP(addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeDialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// probeTCP retries a TCP dial against addr up to probeAttempts times.
func probeTCP(addr string) error {
	var lastErr error
	for i := 0; i < probeAttempts; i++ {
		if i > 0 {
			time.Sleep(probeRetryDelay)
		}
		if err := dialTCP(addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// containerIPOnNetwork returns the IPv4 address that `serviceID` is
// assigned on the named docker network. The host can route to docker
// bridge IPs directly, so we dial that instead of relying on DNS
// resolution of the service name (which only works inside the network).
func containerIPOnNetwork(serviceID, network string) (string, error) {
	format := fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).IPAddress}}`, network)
	out, err := exec.Command("docker", "inspect", "--format", format, serviceID).Output()
	if err != nil {
		return "", fmt.Errorf("docker inspect: %w", err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("no IP on network %q", network)
	}
	return ip, nil
}

// inspectExposedPorts reads `Config.ExposedPorts` from the container.
// Returns an empty slice (never nil) when the image declares none.
func inspectExposedPorts(serviceID string) ([]int, error) {
	out, err := exec.Command("docker", "inspect", "--format", "{{json .Config.ExposedPorts}}", serviceID).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" || raw == "null" {
		return []int{}, nil
	}
	var m map[string]struct{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("parse exposed ports: %w", err)
	}
	ports := make([]int, 0, len(m))
	for k := range m {
		// Keys look like "3000/tcp"; strip the proto suffix.
		portStr := strings.SplitN(k, "/", 2)[0]
		p, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// HealthProbe performs the post-deploy health check: it inspects the
// container's declared ExposedPorts and TCP-probes the configured port.
// Both findings stream into the deploy log (so users see them in the UI)
// and are returned for inclusion in the op's StatusUpdate.Result.
//
// Failures here do not abort the deploy — the container may have started
// successfully but be listening on a different port. The dashboard turns
// the result into actionable guidance.
func (e *Executor) HealthProbe(streamer *logs.Streamer, serviceID string, port int) ProbeResult {
	res := ProbeResult{ExposedPorts: []int{}}

	// 1. Read declared ExposedPorts (best-effort).
	if ports, err := inspectExposedPorts(serviceID); err != nil {
		streamer.AddLine(fmt.Sprintf("Health: could not read exposed ports: %v", err))
	} else {
		res.ExposedPorts = ports
		if len(ports) == 0 {
			streamer.AddLine("Health: image declares no exposed ports.")
		} else {
			strs := make([]string, len(ports))
			for i, p := range ports {
				strs[i] = strconv.Itoa(p)
			}
			streamer.AddLine("Health: image exposes ports " + strings.Join(strs, ", ") + ".")
		}
	}

	// 2. TCP-probe the configured port via the container's bridge IP.
	streamer.AddLine(fmt.Sprintf("Health: probing %s:%d on the stacked network...", serviceID, port))
	streamer.Flush()

	ip, err := containerIPOnNetwork(serviceID, "stacked")
	if err != nil {
		res.Ok = false
		res.Error = err.Error()
		streamer.AddLine(fmt.Sprintf("Health: probe FAILED — %v", err))
		streamer.Flush()
		return res
	}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	if err := probeTCP(addr); err != nil {
		res.Ok = false
		res.Error = err.Error()
		streamer.AddLine(fmt.Sprintf("Health: probe FAILED on port %d — %v", port, err))
		if len(res.ExposedPorts) > 0 {
			streamer.AddLine(fmt.Sprintf("Health: hint — image exposes %v but service is configured for %d.", res.ExposedPorts, port))
		}
	} else {
		res.Ok = true
		streamer.AddLine(fmt.Sprintf("Health: probe OK — container responded on port %d.", port))
	}
	streamer.Flush()
	return res
}
