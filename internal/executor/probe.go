package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	// ExposedPortsUnknown is true when `docker inspect` itself failed and we
	// could not determine the image's declared ports. Distinct from "image
	// legitimately exposes none", which keeps this false with an empty slice.
	ExposedPortsUnknown bool `json:"exposedPortsUnknown"`
}

// probeTimeoutBudget defines the 3-retry, 1s-spacing TCP probe schedule.
// Total worst case ~5s (3 dials at 1s timeout + 2 sleep gaps).
const (
	probeAttempts    = 3
	probeDialTimeout = 1500 * time.Millisecond
	probeRetryDelay  = 1 * time.Second

	// inspectAttempts covers the brief race between `docker compose up -d`
	// returning and the container fully attaching to the `stacked` network.
	inspectAttempts   = 3
	inspectRetryDelay = 500 * time.Millisecond
)

// runDockerInspect runs `docker inspect` capturing both stdout and stderr.
// `Output()` would discard stderr, leaving callers with an opaque
// `exit status 1` and no way to surface docker's actual reason. We trim
// stderr (newlines, the boilerplate "Error response from daemon: " prefix)
// and fold it into the returned error so the dashboard banner can show it.
func runDockerInspect(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"inspect"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		msg = strings.TrimPrefix(msg, "Error response from daemon: ")
		msg = strings.TrimPrefix(msg, "Error: ")
		if msg != "" {
			return "", fmt.Errorf("docker inspect: %s (%w)", msg, err)
		}
		return "", fmt.Errorf("docker inspect: %w", err)
	}
	return stdout.String(), nil
}

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

// httpProbe issues a single GET against http://addr<path> with a short
// timeout. Returns nil iff the response status is in [200, 400). 4xx and
// 5xx are treated as failures — a healthy app should respond 2xx (or
// occasionally a 3xx redirect on `/`) on its health endpoint. We deliberately
// don't follow redirects: if /healthz redirects to /login the app is not
// ready, regardless of the eventual final status.
func httpProbe(addr, path string) error {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	client := &http.Client{
		Timeout: probeDialTimeout * 2, // small budget per attempt; outer loop bounds total wait
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "http://" + addr + path
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return nil
}

// HealthGate runs a blocking probe loop against the container's bridge IP
// on the configured port, retrying until either the probe passes or the
// caller's timeout budget is exhausted. Used by rolling deploys to gate
// the Caddy traffic flip on "new container is actually serving requests."
//
// `path` is optional. When empty, gates on TCP connect alone (matching
// the post-deploy probe semantics). When set, also requires a 2xx/3xx
// response from `GET path`. The gate emits human-readable progress to
// the deploy log streamer so the user can see why a long gate is taking
// time — "connection refused" vs. "503 from /healthz" are very different
// debugging stories.
//
// Returns nil iff the gate passed within the budget.
func HealthGate(streamer *logs.Streamer, serviceID, network string, port int, path string, totalTimeout time.Duration) error {
	ip, err := containerIPOnNetwork(serviceID, network)
	if err != nil {
		return fmt.Errorf("resolve container IP: %w", err)
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	deadline := time.Now().Add(totalTimeout)
	attempt := 0
	var lastErr error
	for {
		attempt++
		if err := dialTCP(addr); err != nil {
			lastErr = err
		} else if path != "" {
			if err := httpProbe(addr, path); err != nil {
				lastErr = err
			} else {
				streamer.AddLine(fmt.Sprintf("Health: gate passed on attempt %d (%s%s 2xx).", attempt, addr, path))
				streamer.Flush()
				return nil
			}
		} else {
			streamer.AddLine(fmt.Sprintf("Health: gate passed on attempt %d (TCP %s).", attempt, addr))
			streamer.Flush()
			return nil
		}

		// Surface progress every few attempts so a long wait isn't silent.
		if attempt%5 == 1 {
			streamer.AddLine(fmt.Sprintf("Health: still waiting (attempt %d): %v", attempt, lastErr))
			streamer.Flush()
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("health gate timed out after %s: %w", totalTimeout, lastErr)
		}
		time.Sleep(probeRetryDelay)
	}
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
	// `with index` (vs bare `index`) makes a missing network key produce
	// empty output instead of a `nil pointer evaluating *EndpointSettings.IPAddress`
	// template error — letting the empty-string retry path below recover
	// when the container attaches to the network a moment later.
	format := fmt.Sprintf(`{{with index .NetworkSettings.Networks %q}}{{.IPAddress}}{{end}}`, network)
	var lastErr error
	for i := 0; i < inspectAttempts; i++ {
		if i > 0 {
			time.Sleep(inspectRetryDelay)
		}
		out, err := runDockerInspect("--format", format, serviceID)
		if err != nil {
			lastErr = err
			continue
		}
		ip := strings.TrimSpace(out)
		if ip == "" {
			lastErr = fmt.Errorf("no IP on network %q", network)
			continue
		}
		// Defensive: docker has been observed returning non-empty,
		// non-parseable strings (e.g. the literal "invalid IP") for
		// `.IPAddress` in edge cases where the endpoint exists on the
		// network but no IPv4 has been allocated. Dialing such a value
		// would produce a confusing `dial tcp: lookup <garbage>: no such host`
		// DNS error; surface a clear message instead.
		if net.ParseIP(ip) == nil {
			lastErr = fmt.Errorf("no valid IP on network %q (got %q)", network, ip)
			continue
		}
		return ip, nil
	}
	return "", lastErr
}

// inspectExposedPorts reads `Config.ExposedPorts` from the container.
// Returns an empty slice (never nil) when the image declares none.
func inspectExposedPorts(serviceID string) ([]int, error) {
	out, err := runDockerInspect("--format", "{{json .Config.ExposedPorts}}", serviceID)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(out)
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

// containsInt reports whether n is present in xs.
func containsInt(xs []int, n int) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
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
	// On error we mark ExposedPortsUnknown so the dashboard can distinguish
	// "image declares none" from "we couldn't tell" — those have very
	// different remediation paths.
	if ports, err := inspectExposedPorts(serviceID); err != nil {
		res.ExposedPortsUnknown = true
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

	// Worker services (port <= 0) expose no port. There's nothing to
	// TCP-probe, so report healthy after the best-effort EXPOSE read.
	// The server sends port=0 for these in the credentials response.
	if port <= 0 {
		res.Ok = true
		streamer.AddLine("Health: worker service — no port to probe.")
		streamer.Flush()
		return res
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
		// Only surface the port-mismatch hint when the configured port is
		// genuinely absent from the image's declared ports. Firing it when
		// they match (e.g. exposes [3000], configured 3000) misleads users
		// into chasing a port-config problem when the real cause is
		// networking or the app failing to bind.
		if len(res.ExposedPorts) > 0 && !containsInt(res.ExposedPorts, port) {
			streamer.AddLine(fmt.Sprintf("Health: hint — image exposes %v but service is configured for %d.", res.ExposedPorts, port))
		}
	} else {
		res.Ok = true
		streamer.AddLine(fmt.Sprintf("Health: probe OK — container responded on port %d.", port))
	}
	streamer.Flush()
	return res
}
