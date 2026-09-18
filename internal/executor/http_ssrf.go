package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTP cron SSRF policy
//
// HTTP jobs run on the agent host, so a raw URL is host-level SSRF.
// Internal jobs (http://my-service:3000/…) are a supported product
// feature; unrestricted access to the host and cloud metadata is not.
//
// Always blocked (no override):
//   - schemes other than http/https
//   - cloud metadata (link-local 169.254/16, fe80::/10, well-known
//     metadata names/IPs including Aliyun 100.100.100.200 and AWS
//     fd00:ec2::254, plus IPv4-mapped / 6to4 / NAT64 embeddings)
//   - unspecified (0.0.0.0/8, ::), multicast, broadcast, reserved
//
// Explicitly authorized:
//   - httpAllowPrivate (default true): RFC1918, Tailscale/CGNAT
//     100.64.0.0/10 (except metadata), IPv6 ULA fc00::/7 (except
//     metadata). Default-on so Docker / stacked-network and Tailscale
//     service URLs keep working. Send false to pin a job to the public
//     internet only.
//   - httpAllowLoopback (default false): 127.0.0.0/8 and ::1. Off
//     because those are the agent host itself. The server must set
//     true only for a job that is supposed to hit localhost.
//
// Every hop is re-resolved and re-validated. The dialer pins the
// chosen IP so a later DNS answer cannot rebind to a blocked address.
const (
	httpJobTimeout          = 60 * time.Second
	httpJobMaxRedirects     = 5
	httpJobMaxResponseBytes = 4096
	httpJobAllowPrivateKey  = "httpAllowPrivate"
	httpJobAllowLoopbackKey = "httpAllowLoopback"
)

type httpJobPolicy struct {
	AllowPrivate  bool
	AllowLoopback bool
}

func httpJobPolicyFromPayload(payload map[string]interface{}) httpJobPolicy {
	return httpJobPolicy{
		AllowPrivate:  getBoolPayload(payload, httpJobAllowPrivateKey, true),
		AllowLoopback: getBoolPayload(payload, httpJobAllowLoopbackKey, false),
	}
}

type ipClass int

const (
	ipPublic ipClass = iota
	ipPrivate
	ipLoopback
	ipBlocked
)

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type ssrfDialer struct {
	policy   httpJobPolicy
	resolver ipResolver
	dialer   *net.Dialer
}

func newHTTPJobClient(policy httpJobPolicy) *http.Client {
	return newHTTPJobClientWithResolver(policy, net.DefaultResolver)
}

func newHTTPJobClientWithResolver(policy httpJobPolicy, resolver ipResolver) *http.Client {
	d := &ssrfDialer{
		policy:   policy,
		resolver: resolver,
		dialer:   &net.Dialer{Timeout: 10 * time.Second},
	}
	return &http.Client{
		Timeout: httpJobTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= httpJobMaxRedirects {
				return fmt.Errorf("blocked redirect: exceeded %d hops", httpJobMaxRedirects)
			}
			if err := validateHTTPJobURL(req.URL.String(), policy); err != nil {
				return err
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy:                 nil, // never honor HTTP_PROXY from the host env
			DialContext:           d.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

func validateHTTPJobURL(raw string, policy httpJobPolicy) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("blocked URL: empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("blocked URL: %w", err)
	}
	return validateParsedHTTPJobURL(u, policy)
}

func validateParsedHTTPJobURL(u *url.URL, policy httpJobPolicy) error {
	if u == nil {
		return fmt.Errorf("blocked URL: missing host")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("blocked URL: scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("blocked URL: missing host")
	}
	host := hostnameOf(u)
	if host == "" {
		return fmt.Errorf("blocked URL: missing host")
	}
	if isBlockedMetadataHost(host) {
		return fmt.Errorf("blocked URL: metadata host %q", host)
	}
	if ip := parseLiteralIP(host); ip != nil {
		if err := allowIP(ip, policy); err != nil {
			return err
		}
	}
	return nil
}

func (d *ssrfDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("blocked dial: network %q", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("blocked dial: %w", err)
	}
	if isBlockedMetadataHost(host) {
		return nil, fmt.Errorf("blocked URL: metadata host %q", host)
	}

	candidates, err := d.lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastDenied error
	for _, ip := range candidates {
		if err := allowIP(ip, d.policy); err != nil {
			lastDenied = err
			continue
		}
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	if lastDenied != nil {
		return nil, lastDenied
	}
	return nil, fmt.Errorf("blocked URL: no resolved addresses for %q", host)
}

func (d *ssrfDialer) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := parseLiteralIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			out = append(out, a.IP)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	return out, nil
}

func hostnameOf(u *url.URL) string {
	host := u.Hostname()
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func allowIP(ip net.IP, policy httpJobPolicy) error {
	switch classifyIP(ip) {
	case ipPublic:
		return nil
	case ipPrivate:
		if policy.AllowPrivate {
			return nil
		}
		return fmt.Errorf("blocked URL: private address %s (set %s=true)", ip, httpJobAllowPrivateKey)
	case ipLoopback:
		if policy.AllowLoopback {
			return nil
		}
		return fmt.Errorf("blocked URL: loopback address %s (set %s=true)", ip, httpJobAllowLoopbackKey)
	default:
		return fmt.Errorf("blocked URL: non-routable address %s", ip)
	}
}

func classifyIP(ip net.IP) ipClass {
	if ip == nil {
		return ipBlocked
	}
	ip4 := ip.To4()
	if ip4 != nil {
		return classifyIPv4(ip4)
	}
	return classifyIPv6(ip)
}

func classifyIPv4(ip net.IP) ipClass {
	if isAlwaysBlockedIPv4(ip) {
		return ipBlocked
	}
	if ip.IsLoopback() {
		return ipLoopback
	}
	if ip.IsPrivate() || isCGNAT(ip) {
		return ipPrivate
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ipBlocked
	}
	return ipPublic
}

func classifyIPv6(ip net.IP) ipClass {
	if ip.IsLoopback() {
		return ipLoopback
	}
	if embedded := embeddedIPv4(ip); embedded != nil {
		return classifyIPv4(embedded)
	}
	if isAWSIMDSv6(ip) {
		return ipBlocked
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return ipBlocked
	}
	if ip.IsPrivate() { // ULA fc00::/7
		return ipPrivate
	}
	return ipPublic
}

func isAlwaysBlockedIPv4(ip net.IP) bool {
	if ip.Equal(net.IPv4(100, 100, 100, 200)) { // Aliyun metadata
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip[0] == 0 { // 0.0.0.0/8
		return true
	}
	if ip[0] >= 240 { // 240.0.0.0/4 incl. broadcast
		return true
	}
	return false
}

func isCGNAT(ip net.IP) bool {
	// RFC 6598 / Tailscale: 100.64.0.0/10
	return ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127
}

func isAWSIMDSv6(ip net.IP) bool {
	// fd00:ec2::254
	want := net.ParseIP("fd00:ec2::254")
	return want != nil && ip.Equal(want)
}

func embeddedIPv4(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	if len(ip) != net.IPv6len {
		return nil
	}
	// NAT64 well-known prefix 64:ff9b::/96
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	// 6to4 2002:AABB:CCDD::/48
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	return nil
}

func isBlockedMetadataHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch host {
	case "metadata",
		"metadata.google.internal",
		"metadata.goog",
		"metadata.amazonaws.com",
		"metadata.azure.com",
		"metadata.alibabacloud.com":
		return true
	}
	return false
}

// parseLiteralIP accepts canonical IPs plus the alternate IPv4 forms
// browsers historically accepted (decimal, hex, octal, short dotted).
func parseLiteralIP(host string) net.IP {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	return parseIPv4Literal(host)
}

func parseIPv4Literal(host string) net.IP {
	if strings.ContainsAny(host, ":/") {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil
	}
	var vals [4]uint32
	for i, p := range parts {
		n, ok := parseIPv4Octet(p)
		if !ok {
			return nil
		}
		vals[i] = n
	}
	var addr uint32
	switch len(parts) {
	case 1:
		if vals[0] > 0xffffffff {
			return nil
		}
		addr = vals[0]
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil
		}
		addr = vals[0]<<24 | vals[1]
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil
		}
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		for i := 0; i < 4; i++ {
			if vals[i] > 0xff {
				return nil
			}
		}
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).To4()
}

func parseIPv4Octet(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	rest := s
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		rest = s[2:]
		if rest == "" {
			return 0, false
		}
	} else if len(s) > 1 && s[0] == '0' {
		base = 8
		rest = s[1:]
	}
	n, err := strconv.ParseUint(rest, base, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func getBoolPayload(payload map[string]interface{}, key string, defaultVal bool) bool {
	v, ok := payload[key]
	if !ok || v == nil {
		return defaultVal
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return defaultVal
}
