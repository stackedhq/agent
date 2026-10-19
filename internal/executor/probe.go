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

	// ipWaitTimeout is how long HealthProbe waits for a real address on
	// the stacked network after compose/run returns. Attach and IPAM can
	// lag well past the old 1.5s inspect budget, especially on a loaded
	// VPS or while a container is bouncing through restart.
	ipWaitTimeout = 20 * time.Second

	// inspectNetworkFormat is one inspect for state + networks so we can
	// wait on "running with an address" instead of guessing at timing.
	// Tabs are used as separators because the JSON payload can contain
	// spaces but not tabs.
	inspectNetworkFormat = `{{.State.Status}}{{"\t"}}{{.State.Running}}{{"\t"}}{{.State.Restarting}}{{"\t"}}{{json .NetworkSettings.Networks}}`
)

// ipPollInterval is the wait between inspects while an address is missing.
// Tests shrink this so the retry loop doesn't sleep in real time.
var ipPollInterval = 250 * time.Millisecond

// sleep / dockerInspect / dockerNetworkConnect are vars so tests can stub
// the docker CLI and the retry clock without a live daemon.
var sleep = time.Sleep

var dockerInspect = runDockerInspect

func dockerNetworkConnectArgs(network, container string) []string {
	// Re-attach with the container name as a DNS alias. Rolling slots are
	// named <serviceID>-blue/green but siblings reach them at <serviceID>,
	// so strip the slot suffix and alias that too.
	args := []string{"network", "connect", "--alias", container}
	if base, ok := strings.CutSuffix(container, "-blue"); ok {
		args = append(args, "--alias", base)
	} else if base, ok := strings.CutSuffix(container, "-green"); ok {
		args = append(args, "--alias", base)
	}
	return append(args, network, container)
}

var dockerNetworkConnect = func(network, container string) error {
	cmd := exec.Command("docker", dockerNetworkConnectArgs(network, container)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		msg = strings.TrimPrefix(msg, "Error response from daemon: ")
		if msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

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

// dialTCP is a var so HealthGate tests can stub the TCP connect without
// opening a real socket. Production uses dialTCPOnce.
var dialTCP = dialTCPOnce

// dialTCPOnce attempts a single TCP connect with a bounded timeout.
func dialTCPOnce(addr string) error {
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
// IP resolution is inside the loop, not a one-shot before it. A missing
// stacked address at t=0 used to fail the gate immediately even when the
// remaining budget was 60s; attach lag and restart windows now consume
// that budget the same way a slow TCP handshake does.
//
// Returns nil iff the gate passed within the budget.
func HealthGate(streamer *logs.Streamer, serviceID, network string, port int, path string, totalTimeout time.Duration) error {
	deadline := time.Now().Add(totalTimeout)
	attempt := 0
	var lastErr error
	for {
		attempt++
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if lastErr == nil {
				lastErr = fmt.Errorf("timed out")
			}
			return fmt.Errorf("health gate timed out after %s: %w", totalTimeout, lastErr)
		}

		// Cap a single IP wait so a missing address can't swallow the
		// whole gate budget in one silent poll. Remaining time still
		// belongs to later attempts (TCP / HTTP) once an address exists.
		// Restarting containers keep retrying until deadline.
		ipWait := remaining
		if ipWait > ipWaitTimeout {
			ipWait = ipWaitTimeout
		}
		ip, err := waitForContainerIP(serviceID, network, ipWait)
		if err != nil {
			lastErr = fmt.Errorf("resolve container IP: %w", err)
			// Dead/exited containers will never grow an address. Don't
			// spend the remaining gate budget polling a corpse.
			if isTerminalIPError(err) {
				return lastErr
			}
		} else {
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
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
		}

		// Surface progress every few attempts so a long wait isn't silent.
		if attempt%5 == 1 {
			streamer.AddLine(fmt.Sprintf("Health: still waiting (attempt %d): %v", attempt, lastErr))
			streamer.Flush()
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("health gate timed out after %s: %w", totalTimeout, lastErr)
		}
		sleep(probeRetryDelay)
	}
}

// probeTCP retries a TCP dial against addr up to probeAttempts times.
func probeTCP(addr string) error {
	var lastErr error
	for i := 0; i < probeAttempts; i++ {
		if i > 0 {
			sleep(probeRetryDelay)
		}
		if err := dialTCP(addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

type inspectNetworkInfo struct {
	Status     string
	Running    bool
	Restarting bool
	OnNetwork  bool
	IP         string
}

type dockerEndpoint struct {
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
}

func parseInspectNetwork(out, network string) (inspectNetworkInfo, error) {
	line := strings.TrimSpace(out)
	parts := strings.SplitN(line, "\t", 4)
	if len(parts) != 4 {
		return inspectNetworkInfo{}, fmt.Errorf("unexpected inspect output %q", line)
	}
	info := inspectNetworkInfo{
		Status:     parts[0],
		Running:    parts[1] == "true",
		Restarting: parts[2] == "true",
	}
	raw := strings.TrimSpace(parts[3])
	if raw == "" || raw == "null" || raw == "<no value>" {
		return info, nil
	}
	var networks map[string]dockerEndpoint
	if err := json.Unmarshal([]byte(raw), &networks); err != nil {
		return inspectNetworkInfo{}, fmt.Errorf("parse networks: %w", err)
	}
	ep, ok := networks[network]
	if !ok {
		return info, nil
	}
	info.OnNetwork = true
	if ip := parseDockerIP(ep.IPAddress); ip != "" {
		info.IP = ip
		return info, nil
	}
	if ip := parseDockerIP(ep.GlobalIPv6Address); ip != "" {
		info.IP = ip
	}
	return info, nil
}

func parseDockerIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func terminalContainerStatus(status string) bool {
	switch status {
	case "exited", "dead", "paused":
		return true
	default:
		return false
	}
}

func isTerminalIPError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status=exited") ||
		strings.Contains(msg, "status=dead") ||
		strings.Contains(msg, "status=paused")
}

func alreadyOnNetwork(err error) bool {
	if err == nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists in network") ||
		strings.Contains(msg, "already connected")
}

// waitForContainerIP polls inspect until the container has a usable
// address on `network`, reconnecting a running-but-detached container
// once Docker is ready. Prefers IPv4 and falls back to IPv6 so an
// IPv6-only endpoint is still reachable from the host.
func waitForContainerIP(container, network string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = ipWaitTimeout
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	triedConnect := false
	for {
		out, err := dockerInspect("--format", inspectNetworkFormat, container)
		if err != nil {
			lastErr = err
		} else if info, err := parseInspectNetwork(out, network); err != nil {
			lastErr = err
		} else if info.IP != "" {
			return info.IP, nil
		} else if terminalContainerStatus(info.Status) && !info.Restarting {
			return "", fmt.Errorf("no IP on network %q (status=%s)", network, info.Status)
		} else {
			lastErr = fmt.Errorf("no IP on network %q (status=%s)", network, info.Status)
			if info.Running && !info.OnNetwork && !triedConnect {
				triedConnect = true
				if cerr := dockerNetworkConnect(network, container); cerr != nil && !alreadyOnNetwork(cerr) {
					lastErr = fmt.Errorf("%v; reconnect %q: %w", lastErr, network, cerr)
				}
			}
		}
		if !time.Now().Before(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("no IP on network %q", network)
			}
			return "", lastErr
		}
		sleep(ipPollInterval)
	}
}

// containerIPOnNetwork returns the address that `container` is assigned
// on the named docker network, waiting through attach/IPAM lag. The
// host can route to docker bridge IPs directly, so we dial that instead
// of relying on DNS resolution of the service name (which only works
// inside the network).
func containerIPOnNetwork(container, network string) (string, error) {
	return waitForContainerIP(container, network, ipWaitTimeout)
}

// inspectExposedPorts reads `Config.ExposedPorts` from the container.
// Returns an empty slice (never nil) when the image declares none.
func inspectExposedPorts(serviceID string) ([]int, error) {
	out, err := dockerInspect("--format", "{{json .Config.ExposedPorts}}", serviceID)
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
func (e *Executor) HealthProbe(streamer *logs.Streamer, serviceID, network string, port int) ProbeResult {
	if network == "" {
		network = probeNetworkFor(serviceID)
	}
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
	streamer.AddLine(fmt.Sprintf("Health: probing %s:%d on network %s...", serviceID, port, network))
	streamer.Flush()

	ip, err := containerIPOnNetwork(serviceID, network)
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
