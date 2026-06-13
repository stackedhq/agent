package executor

import (
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/slots"
)

func TestGenerateCaddyfileNoSlotState(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "reverse_proxy svc-1:3000") {
		t.Fatalf("expected legacy upstream svc-1:3000, got:\n%s", out)
	}
	if strings.Contains(out, "svc-1-blue") || strings.Contains(out, "svc-1-green") {
		t.Fatalf("did not expect slot-suffixed upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfileBlueActive(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if !strings.Contains(out, "reverse_proxy svc-1-blue:3000") {
		t.Fatalf("expected upstream svc-1-blue:3000, got:\n%s", out)
	}
}

func TestGenerateCaddyfileLegacyKeepsBareName(t *testing.T) {
	// During the first rolling deploy of a service migrating off
	// recreate, state momentarily reads `legacy` — the upstream must
	// still resolve to the bare serviceID until the flip writes a
	// real slot.
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Legacy})
	if !strings.Contains(out, "reverse_proxy svc-1:3000") {
		t.Fatalf("expected legacy upstream svc-1:3000, got:\n%s", out)
	}
}

func TestGenerateCaddyfileMixedRecreateAndRolling(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "a.example.com", ServiceID: "svc-rec", Port: 3000},
		{Domain: "b.example.com", ServiceID: "svc-roll", Port: 8080},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-roll": slots.Green})
	if !strings.Contains(out, "reverse_proxy svc-rec:3000") {
		t.Fatalf("recreate service should keep bare upstream, got:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy svc-roll-green:8080") {
		t.Fatalf("rolling service should use slot upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfilePortBoundHTTP(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "plex.example.com", Host: "127.0.0.1", Port: 32400, Scheme: "http"},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	// 127.0.0.1 must be rewritten to host.docker.internal because
	// Caddy runs inside a bridged container — see
	// renderUpstreamHostPort. The user typed "this VPS"; we deliver
	// "this VPS" rather than the container's own loopback.
	if !strings.Contains(out, "reverse_proxy host.docker.internal:32400") {
		t.Fatalf("expected loopback rewrite to host.docker.internal, got:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1") {
		t.Fatalf("127.0.0.1 should have been rewritten, got:\n%s", out)
	}
	if strings.Contains(out, "https://") {
		t.Fatalf("http upstream should not emit https scheme, got:\n%s", out)
	}
}

func TestRenderUpstreamHostPortRewritesLoopback(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1": "host.docker.internal:80",
		"localhost": "host.docker.internal:80",
		"LocalHost": "host.docker.internal:80",
		"::1":       "host.docker.internal:80",
	}
	for input, want := range cases {
		if got := renderUpstreamHostPort(input, 80); got != want {
			t.Errorf("%s -> %s, want %s", input, got, want)
		}
	}
}

func TestRenderUpstreamHostPortLeavesOtherHostsAlone(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5":             "10.0.0.5:443",
		"host.docker.internal": "host.docker.internal:443",
		"plex":                 "plex:443",
		"upstream.lan":         "upstream.lan:443",
	}
	for input, want := range cases {
		if got := renderUpstreamHostPort(input, 443); got != want {
			t.Errorf("%s -> %s, want %s", input, got, want)
		}
	}
}

func TestRenderUpstreamHostPortBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"2001:db8::1":   "[2001:db8::1]:8080",
		"fe80::1234":    "[fe80::1234]:8080",
		"[2001:db8::1]": "[2001:db8::1]:8080", // already-bracketed passes through
	}
	for input, want := range cases {
		if got := renderUpstreamHostPort(input, 8080); got != want {
			t.Errorf("%s -> %s, want %s", input, got, want)
		}
	}
}

func TestGenerateCaddyfilePortBoundHTTPS(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "upstream.example.com", Host: "10.0.0.5", Port: 8443, Scheme: "https"},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "reverse_proxy https://10.0.0.5:8443") {
		t.Fatalf("expected port-bound https upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfilePortBoundIPv6HTTPS(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "v6.example.com", Host: "2001:db8::5", Port: 8443, Scheme: "https"},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "reverse_proxy https://[2001:db8::5]:8443") {
		t.Fatalf("IPv6 upstream must be bracketed, got:\n%s", out)
	}
}

func TestGenerateCaddyfileMixedServiceAndPortBound(t *testing.T) {
	// Slot state for the rolling service must not leak into the
	// port-bound row's upstream.
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
		{Domain: "plex.example.com", Host: "127.0.0.1", Port: 32400, Scheme: "http"},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if !strings.Contains(out, "reverse_proxy svc-1-blue:3000") {
		t.Fatalf("service-backed row should use slot upstream, got:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy host.docker.internal:32400") {
		t.Fatalf("port-bound row should use host.docker.internal upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfileEmitsServerHeader(t *testing.T) {
	// `Server: Stacked` should be emitted exactly once per site block,
	// for both service-backed and port-bound domains, regardless of
	// slot state. This is the Vercel-parity brand header.
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
		{Domain: "plex.example.com", Host: "127.0.0.1", Port: 32400, Scheme: "http"},
		{Domain: "upstream.example.com", Host: "10.0.0.5", Port: 8443, Scheme: "https"},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if n := strings.Count(out, "header Server Stacked"); n != len(parsed) {
		t.Fatalf("expected %d `header Server Stacked` lines (one per site), got %d in:\n%s", len(parsed), n, out)
	}
	// Header must be inside the site block, after `reverse_proxy`,
	// before the closing brace. Check that ordering holds for each
	// site by walking the rendered output.
	for _, d := range parsed {
		idxOpen := strings.Index(out, d.Domain+" {")
		if idxOpen < 0 {
			t.Fatalf("site block for %s missing in:\n%s", d.Domain, out)
		}
		rest := out[idxOpen:]
		idxClose := strings.Index(rest, "}")
		if idxClose < 0 {
			t.Fatalf("site block for %s not closed in:\n%s", d.Domain, out)
		}
		block := rest[:idxClose]
		if !strings.Contains(block, "reverse_proxy ") {
			t.Fatalf("site block for %s missing reverse_proxy:\n%s", d.Domain, block)
		}
		if !strings.Contains(block, "header Server Stacked") {
			t.Fatalf("site block for %s missing brand header:\n%s", d.Domain, block)
		}
		if strings.Index(block, "reverse_proxy ") > strings.Index(block, "header Server Stacked") {
			t.Fatalf("brand header should follow reverse_proxy in site %s:\n%s", d.Domain, block)
		}
	}
}

func TestParseDomainsAcceptsBothShapes(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"domain":    "a.example.com",
			"serviceId": "svc-1",
			"port":      float64(3000),
		},
		map[string]interface{}{
			"domain": "b.example.com",
			"host":   "127.0.0.1",
			"port":   float64(32400),
			"scheme": "http",
		},
		// Neither shape — should be dropped.
		map[string]interface{}{
			"domain": "c.example.com",
		},
	}
	parsed := parseDomains(raw)
	if len(parsed) != 2 {
		t.Fatalf("expected 2 valid domains, got %d: %+v", len(parsed), parsed)
	}
	if parsed[0].ServiceID != "svc-1" || parsed[0].Port != 3000 {
		t.Errorf("service-backed parse wrong: %+v", parsed[0])
	}
	if !parsed[1].isPortBound() {
		t.Errorf("second row should be detected as port-bound: %+v", parsed[1])
	}
	if parsed[1].Host != "127.0.0.1" || parsed[1].Port != 32400 || parsed[1].Scheme != "http" {
		t.Errorf("port-bound parse wrong: %+v", parsed[1])
	}
}

func TestParseDomainsDefaultsSchemeToHTTP(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"domain": "a.example.com",
			"host":   "127.0.0.1",
			"port":   float64(8080),
			// scheme omitted
		},
	}
	parsed := parseDomains(raw)
	if len(parsed) != 1 || parsed[0].Scheme != "http" {
		t.Fatalf("missing scheme should default to http, got: %+v", parsed)
	}
}

func TestProxyConfigErrorResult(t *testing.T) {
	err := &ProxyConfigError{
		Code:    "port_in_use",
		Port:    80,
		Holder:  "dokploy-traefik",
		Message: "port 80 is held by container 'dokploy-traefik'",
	}
	res := err.Result()
	if res["error_code"] != "port_in_use" {
		t.Errorf("missing error_code: %+v", res)
	}
	if res["port"] != 80 {
		t.Errorf("missing port: %+v", res)
	}
	if res["holder"] != "dokploy-traefik" {
		t.Errorf("missing holder: %+v", res)
	}
	if res["error"] == nil {
		t.Errorf("missing legacy error field: %+v", res)
	}
}

func TestParsePortInUseFromDocker(t *testing.T) {
	out := `Container proxy-caddy-1  Starting
Error response from daemon: driver failed programming external connectivity on endpoint proxy-caddy-1 (abc): Bind for 0.0.0.0:80 failed: port is already allocated
`
	port, _ := parsePortInUseFromDocker(out)
	if port != 80 {
		t.Errorf("expected port 80, got %d", port)
	}
	// Holder lookup runs docker ps which won't be available in tests;
	// we tolerate empty holder. Production path is exercised by
	// integration.
}

func TestParsePortInUseFromDockerNoMatch(t *testing.T) {
	out := "some unrelated docker error"
	port, holder := parsePortInUseFromDocker(out)
	if port != 0 || holder != "" {
		t.Errorf("expected zero values, got port=%d holder=%q", port, holder)
	}
}

func TestGetIntPayloadOrFallback(t *testing.T) {
	cases := []struct {
		name     string
		payload  map[string]interface{}
		key      string
		fallback int
		want     int
	}{
		{"missing key", map[string]interface{}{}, "k", 60, 60},
		{"nil value", map[string]interface{}{"k": nil}, "k", 60, 60},
		{"zero float (treated as unset)", map[string]interface{}{"k": float64(0)}, "k", 60, 60},
		{"positive float", map[string]interface{}{"k": float64(42)}, "k", 60, 42},
		{"int", map[string]interface{}{"k": 7}, "k", 60, 7},
		{"wrong type", map[string]interface{}{"k": "thirty"}, "k", 60, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := getIntPayloadOr(c.payload, c.key, c.fallback); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

// boolPtr is a test helper so cases can express
// `StripPrefix: boolPtr(false)` without ceremony.
func boolPtr(b bool) *bool { return &b }

// TestGenerateCaddyfileSinglePathRootIsBackCompat verifies the fast
// path: a single row with path="/" (or empty, simulating a v1
// payload) renders the historical bare `reverse_proxy` shape with
// no `handle` wrapper. Diffing rendered Caddyfiles across this
// upgrade for any unchanged domain must produce an empty diff.
func TestGenerateCaddyfileSinglePathRootIsBackCompat(t *testing.T) {
	cases := []struct {
		name string
		row  cachedDomain
	}{
		{"v1 payload (no Path)", cachedDomain{Domain: "a.example.com", ServiceID: "svc", Port: 3000}},
		{"v2 payload explicit /", cachedDomain{Domain: "a.example.com", ServiceID: "svc", Port: 3000, Path: "/", StripPrefix: boolPtr(true)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := generateCaddyfile([]cachedDomain{c.row}, map[string]slots.Slot{})
			if strings.Contains(out, "handle") {
				t.Fatalf("expected no handle wrapper for single-root row, got:\n%s", out)
			}
			if !strings.Contains(out, "    reverse_proxy svc:3000") {
				t.Fatalf("expected bare reverse_proxy, got:\n%s", out)
			}
		})
	}
}

// TestGenerateCaddyfileMultiPathRootAndApi verifies the canonical
// two-row scenario from the feature spec: `/` → service A, `/api`
// → service B on the same host. Output must be one site block,
// /api emitted first (longest-prefix-first), `handle_path /api*`
// for the stripping route, and `handle {}` for the root fallback.
func TestGenerateCaddyfileMultiPathRootAndApi(t *testing.T) {
	parsed := []cachedDomain{
		// Intentionally insert root first so the sort is exercised.
		{Domain: "r.example.com", Host: "127.0.0.1", Port: 3002, Scheme: "http", Path: "/", StripPrefix: boolPtr(true)},
		{Domain: "r.example.com", Host: "127.0.0.1", Port: 3001, Scheme: "http", Path: "/api", StripPrefix: boolPtr(true)},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})

	// One outer site block per host (count opening braces with the host token).
	if got := strings.Count(out, "r.example.com {"); got != 1 {
		t.Fatalf("expected exactly one site block for r.example.com, got %d:\n%s", got, out)
	}
	// handle_path for the prefix-strip route.
	if !strings.Contains(out, "handle_path /api* {") {
		t.Fatalf("expected handle_path /api* block, got:\n%s", out)
	}
	// Bare `handle {` for the root fallback (no prefix matcher).
	if !strings.Contains(out, "handle {") {
		t.Fatalf("expected root handle {} block, got:\n%s", out)
	}
	// Longest-prefix-first ordering: /api before /.
	apiIdx := strings.Index(out, "handle_path /api*")
	rootIdx := strings.Index(out, "handle {")
	if apiIdx < 0 || rootIdx < 0 || apiIdx > rootIdx {
		t.Fatalf("expected /api block before root block, got:\n%s", out)
	}
	// Both upstreams present, loopback rewritten to host.docker.internal.
	if !strings.Contains(out, "reverse_proxy host.docker.internal:3001") {
		t.Fatalf("missing /api upstream, got:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy host.docker.internal:3002") {
		t.Fatalf("missing root upstream, got:\n%s", out)
	}
	// Branding stays once per site block, outside any handle.
	if got := strings.Count(out, "header Server Stacked"); got != 1 {
		t.Fatalf("expected one header directive per host, got %d:\n%s", got, out)
	}
}

// TestGenerateCaddyfileNestedPathsLongestFirst verifies that a
// nested pair like /api + /api/v1 sort longest-first so the
// human-readable output mirrors Caddy's matcher precedence.
func TestGenerateCaddyfileNestedPathsLongestFirst(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "h.example.com", Host: "127.0.0.1", Port: 3001, Scheme: "http", Path: "/api", StripPrefix: boolPtr(true)},
		{Domain: "h.example.com", Host: "127.0.0.1", Port: 3002, Scheme: "http", Path: "/api/v1", StripPrefix: boolPtr(true)},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	v1Idx := strings.Index(out, "handle_path /api/v1*")
	apiIdx := strings.Index(out, "handle_path /api*")
	if v1Idx < 0 || apiIdx < 0 || v1Idx > apiIdx {
		t.Fatalf("expected /api/v1 before /api in output, got:\n%s", out)
	}
}

// TestGenerateCaddyfileStripPrefixFalseUsesHandle verifies the
// opt-out: stripPrefix=false on a non-root path emits bare `handle`
// (matcher only, no rewrite) instead of `handle_path` (matcher +
// strip). The upstream still resolves the same way.
func TestGenerateCaddyfileStripPrefixFalseUsesHandle(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "k.example.com", Host: "127.0.0.1", Port: 4000, Scheme: "http", Path: "/keep", StripPrefix: boolPtr(false)},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "handle /keep* {") {
		t.Fatalf("expected bare handle /keep*, got:\n%s", out)
	}
	if strings.Contains(out, "handle_path") {
		t.Fatalf("did not expect handle_path when stripPrefix=false, got:\n%s", out)
	}
}

// TestGenerateCaddyfileMixedServiceAndPortBoundSameHost verifies
// that a single host can mix a service-backed root with a
// port-bound /api row. Both end up in the same site block.
func TestGenerateCaddyfileMixedServiceAndPortBoundSameHost(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "m.example.com", ServiceID: "svc-1", Port: 3000, Path: "/", StripPrefix: boolPtr(true)},
		{Domain: "m.example.com", Host: "127.0.0.1", Port: 5000, Scheme: "http", Path: "/api", StripPrefix: boolPtr(true)},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if got := strings.Count(out, "m.example.com {"); got != 1 {
		t.Fatalf("expected one site block, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "reverse_proxy svc-1-blue:3000") {
		t.Fatalf("expected blue-slot service upstream, got:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy host.docker.internal:5000") {
		t.Fatalf("expected port-bound upstream, got:\n%s", out)
	}
}

// TestParseDomainsAcceptsV2Fields ensures parseDomains carries
// path + stripPrefix through from the wire payload. Absence
// collapses to defaults via effective*().
func TestParseDomainsAcceptsV2Fields(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"domain":      "x.example.com",
			"host":        "127.0.0.1",
			"port":        float64(3001),
			"scheme":      "http",
			"path":        "/api",
			"stripPrefix": false,
		},
	}
	parsed := parseDomains(raw)
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed row, got %d", len(parsed))
	}
	if parsed[0].effectivePath() != "/api" {
		t.Fatalf("expected path /api, got %q", parsed[0].effectivePath())
	}
	if parsed[0].effectiveStripPrefix() {
		t.Fatalf("expected stripPrefix=false to propagate, got true")
	}
}

// TestParseDomainsLegacyPayloadDefaults ensures a v1 payload (no
// path / stripPrefix fields) parses cleanly with the defaults the
// renderer expects.
func TestParseDomainsLegacyPayloadDefaults(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"domain":    "y.example.com",
			"serviceId": "svc-1",
			"port":      float64(3000),
		},
	}
	parsed := parseDomains(raw)
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed row, got %d", len(parsed))
	}
	if parsed[0].effectivePath() != "/" {
		t.Fatalf("expected default path /, got %q", parsed[0].effectivePath())
	}
	if !parsed[0].effectiveStripPrefix() {
		t.Fatalf("expected default stripPrefix=true, got false")
	}
}

// --- On-demand TLS ---

// withServerBaseURL sets the package-level server origin for the
// duration of a test and restores it after. Necessary because on-demand
// TLS rendering reads the global serverBaseURL to build the `ask` URL.
func withServerBaseURL(t *testing.T, u string) {
	t.Helper()
	prev := serverBaseURL
	SetServerBaseURL(u)
	t.Cleanup(func() { serverBaseURL = prev })
}

func TestParseDomainsOnDemandTLSFlag(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"domain":      "od.example.com",
			"serviceId":   "svc-1",
			"port":        float64(3000),
			"onDemandTls": true,
		},
		map[string]interface{}{
			"domain":    "eager.example.com",
			"serviceId": "svc-2",
			"port":      float64(3000),
		},
	}
	parsed := parseDomains(raw)
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed rows, got %d", len(parsed))
	}
	if !parsed[0].OnDemandTLS {
		t.Fatalf("expected onDemandTls=true on first row")
	}
	if parsed[1].OnDemandTLS {
		t.Fatalf("expected onDemandTls=false (absent) on second row")
	}
}

func TestGenerateCaddyfileOnDemandEmitsGlobalAndSiteBlocks(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest")
	parsed := []cachedDomain{
		{Domain: "od.example.com", ServiceID: "svc-1", Port: 3000, OnDemandTLS: true},
		{Domain: "eager.example.com", ServiceID: "svc-2", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})

	// Global options block with the ask endpoint.
	if !strings.Contains(out, "on_demand_tls {") {
		t.Fatalf("expected global on_demand_tls block, got:\n%s", out)
	}
	if !strings.Contains(out, "ask https://stacked.rest/api/agent/tls/ask") {
		t.Fatalf("expected ask URL, got:\n%s", out)
	}
	// The on-demand host gets a per-site tls { on_demand } block.
	odIdx := strings.Index(out, "od.example.com {")
	if odIdx < 0 {
		t.Fatalf("missing od.example.com site block, got:\n%s", out)
	}
	eagerIdx := strings.Index(out, "eager.example.com {")
	if eagerIdx < 0 {
		t.Fatalf("missing eager.example.com site block, got:\n%s", out)
	}
	// `on_demand` (the per-site directive) must appear once, inside the
	// od.example.com block — i.e. after its opening brace and before the
	// eager block (which is rendered later in host order).
	siteOnDemand := strings.Index(out, "tls {\n        on_demand")
	if siteOnDemand < 0 {
		t.Fatalf("expected per-site tls { on_demand }, got:\n%s", out)
	}
	if siteOnDemand < odIdx {
		t.Fatalf("per-site on_demand should be inside od.example.com block, got:\n%s", out)
	}
	// The eager host must NOT get a per-site on_demand directive.
	eagerBlock := out[eagerIdx:]
	if strings.Contains(eagerBlock, "on_demand") {
		t.Fatalf("eager host should not get on_demand, got:\n%s", eagerBlock)
	}
}

func TestGenerateCaddyfileNoOnDemandWithoutServerURL(t *testing.T) {
	// Without a known server origin we can't render a guarded ask
	// endpoint, so on-demand must degrade to eager issuance rather than
	// emit an unguarded (open-relay) on_demand_tls block.
	withServerBaseURL(t, "")
	parsed := []cachedDomain{
		{Domain: "od.example.com", ServiceID: "svc-1", Port: 3000, OnDemandTLS: true},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if strings.Contains(out, "on_demand") {
		t.Fatalf("expected no on_demand when server URL is unset, got:\n%s", out)
	}
}

func TestGenerateCaddyfileNoGlobalBlockWhenNoOnDemand(t *testing.T) {
	// A normal (no on-demand) config must not gain a global options
	// block — keeps the rendered file byte-identical to pre-feature
	// output for every existing install.
	withServerBaseURL(t, "https://stacked.rest")
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if strings.Contains(out, "on_demand_tls") {
		t.Fatalf("did not expect global on_demand_tls block, got:\n%s", out)
	}
}
