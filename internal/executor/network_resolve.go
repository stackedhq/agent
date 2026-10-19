package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// The agent runs on the host, not inside a container, so its DNS lookups go
// through the host resolver (systemd-resolved, Tailscale MagicDNS, ...).
// Container names and `--network-alias` values on the `stacked` network are
// only answered by Docker's embedded DNS server (127.0.0.11), which is
// reachable from inside attached containers and nowhere else. A request to
// `http://<serviceID>:3000/...` from the agent therefore fails with
// "no such host" even though every sibling container resolves it fine.
//
// stackedNetworkDialer closes that gap for agent-side HTTP (HTTP-mode cron
// jobs): before falling back to normal DNS it asks the Docker daemon which
// container on the network answers to the hostname and dials its bridge IP
// directly. The host routes to bridge IPs natively on Linux (the health
// probe relies on the same thing), so no published ports are needed. The
// lookup order mirrors Docker's embedded DNS: network names first, then the
// upstream resolver.

// stackedNetworkInspectFormat emits one line per container: ID, name and
// the JSON endpoint for the target network. The network name is spliced in
// by networkInspectFormat. Tabs separate fields because none of them can
// contain one.
func networkInspectFormat(network string) string {
	return fmt.Sprintf(`{{.Id}}{{"\t"}}{{.Name}}{{"\t"}}{{json (index .NetworkSettings.Networks %q)}}`, network)
}

type networkEndpoint struct {
	Aliases           []string `json:"Aliases"`
	DNSNames          []string `json:"DNSNames"`
	IPAddress         string   `json:"IPAddress"`
	GlobalIPv6Address string   `json:"GlobalIPv6Address"`
}

// listNetworkContainers / inspectContainers are vars so tests can stub the
// docker CLI.
var listNetworkContainers = func(network string) ([]string, error) {
	out, err := runCommandSilent("", "docker", "ps", "-q", "--no-trunc",
		"--filter", "network="+network,
		"--filter", "status=running")
	if err != nil {
		return nil, fmt.Errorf("docker ps: %s (%w)", strings.TrimSpace(out), err)
	}
	return strings.Fields(out), nil
}

var inspectContainers = func(format string, ids []string) (string, error) {
	return dockerInspect(append([]string{"--format", format}, ids...)...)
}

// resolveOnDockerNetwork returns the bridge IPs of every running container
// on `network` that Docker's embedded DNS would answer `host` with: the
// container name, a network alias, any DNSNames entry (Docker 25+), or the
// short container ID. Multiple matches are normal: blue/green slots share
// the bare `<serviceID>` alias during a flip. Returns an empty slice (no
// error) when nothing on the network matches.
func resolveOnDockerNetwork(host, network string) ([]string, error) {
	ids, err := listNetworkContainers(network)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	out, err := inspectContainers(networkInspectFormat(network), ids)
	if err != nil {
		return nil, err
	}
	return matchNetworkHost(out, host), nil
}

// matchNetworkHost parses networkInspectFormat output and returns the IPs
// of containers answering to `host`. Matching is case-insensitive, like DNS.
// IPv4 addresses come first so callers dial them before IPv6.
func matchNetworkHost(out, host string) []string {
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if want == "" {
		return nil
	}
	var v4, v6 []string
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		raw := strings.TrimSpace(parts[2])
		if raw == "" || raw == "null" || raw == "<no value>" {
			continue
		}
		var ep networkEndpoint
		if err := json.Unmarshal([]byte(raw), &ep); err != nil {
			continue
		}
		names := make([]string, 0, 2+len(ep.Aliases)+len(ep.DNSNames))
		names = append(names, strings.TrimPrefix(parts[1], "/"))
		if id := parts[0]; len(id) >= 12 {
			names = append(names, id[:12])
		}
		names = append(names, ep.Aliases...)
		names = append(names, ep.DNSNames...)
		if !containsFold(names, want) {
			continue
		}
		if ip := parseDockerIP(ep.IPAddress); ip != "" {
			v4 = append(v4, ip)
		}
		if ip := parseDockerIP(ep.GlobalIPv6Address); ip != "" {
			v6 = append(v6, ip)
		}
	}
	return append(v4, v6...)
}

func containsFold(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(strings.TrimSpace(x), want) {
			return true
		}
	}
	return false
}

// resolveDockerHost is a var so dialer tests can stub the docker lookup.
var resolveDockerHost = resolveOnDockerNetwork

// stackedNetworkDialer returns a DialContext that resolves hostnames against
// containers on `network` before falling back to the system resolver.
// `onResolve` (optional) is called once per successful network-name match so
// callers can log which container address a name mapped to.
func stackedNetworkDialer(network string, onResolve func(host string, ips []string)) func(ctx context.Context, netw, addr string) (net.Conn, error) {
	base := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, netw, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host == "" || net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") {
			return base.DialContext(ctx, netw, addr)
		}

		ips, rerr := resolveDockerHost(host, network)
		if rerr != nil || len(ips) == 0 {
			// Not a container on the network (or the daemon is
			// unreachable): treat it as a normal public/LAN hostname.
			return base.DialContext(ctx, netw, addr)
		}
		if onResolve != nil {
			onResolve(host, ips)
		}

		var lastErr error
		for _, ip := range ips {
			conn, err := base.DialContext(ctx, netw, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, fmt.Errorf("dial %s (container on %q network at %s): %w",
			host, network, strings.Join(ips, ", "), lastErr)
	}
}
