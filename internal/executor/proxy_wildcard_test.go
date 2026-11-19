package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/slots"
)

// legacyPayload is a proxy_config payload without any tlsMode field,
// exactly as servers before the wildcard feature send it: plain,
// multi-path, on-demand and gated rows.
func legacyPayload() []interface{} {
	return []interface{}{
		map[string]interface{}{"domain": "app.example.com", "serviceId": "svc-1", "port": float64(3000)},
		map[string]interface{}{"domain": "multi.example.com", "serviceId": "svc-2", "port": float64(8080), "path": "/api", "stripPrefix": false},
		map[string]interface{}{"domain": "multi.example.com", "serviceId": "svc-1", "port": float64(3000), "path": "/"},
		map[string]interface{}{"domain": "od.example.com", "host": "127.0.0.1", "port": float64(9000), "scheme": "http", "onDemandTls": true},
		map[string]interface{}{"domain": "gated.example.com", "serviceId": "svc-3", "port": float64(4000), "authGateMode": "password", "authGateUsername": "u", "authGatePasswordHash": "h", "serviceName": "s"},
	}
}

// legacyCaddyfile is what agent v0.27.x rendered for legacyPayload
// (captured from that code before the wildcard change). Any byte of
// difference means existing installs would see their Caddyfile change
// on upgrade.
const legacyCaddyfile = "# Managed by Stacked \u2014 do not edit manually\n\n{\n\ton_demand_tls {\n\t\task https://stacked.rest/api/agent/tls/ask\n\t}\n}\n\napp.example.com {\n    reverse_proxy svc-1-blue:3000\n    header Server Stacked\n}\n\nmulti.example.com {\n    handle /api* {\n        reverse_proxy svc-2:8080\n    }\n    handle {\n        reverse_proxy svc-1-blue:3000\n    }\n    header Server Stacked\n}\n\nod.example.com {\n    tls {\n        on_demand\n    }\n    reverse_proxy host.docker.internal:9000\n    header Server Stacked\n}\n\ngated.example.com {\n    handle /__stacked/* {\n        reverse_proxy stacked-gate:9876 {\n            header_up X-Stacked-Gate-Domain gated.example.com\n        }\n    }\n    handle {\n        forward_auth stacked-gate:9876 {\n            uri /check\n            header_up X-Original-URI {uri}\n            header_up X-Stacked-Gate-Domain gated.example.com\n        }\n        reverse_proxy svc-3:4000\n    }\n    header Server Stacked\n}\n\n"

func TestLegacyPayloadRendersExactlyAsBefore(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest")
	parsed := sanitizeDomains(parseDomains(legacyPayload()))
	out, err := generateCaddyfileChecked(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out != legacyCaddyfile {
		t.Fatalf("legacy payload rendering changed.\n--- got ---\n%s\n--- want ---\n%s", out, legacyCaddyfile)
	}
}

func TestLegacyDomainsCacheHasNoTLSMode(t *testing.T) {
	// The persisted domains.json for an old payload must not gain a
	// tlsMode key (omitempty), so a downgrade reads the same file.
	data, err := json.Marshal(parseDomains(legacyPayload()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "tlsMode") {
		t.Fatalf("legacy rows should not persist tlsMode, got %s", data)
	}
}

func TestParseDomainsTLSMode(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{"domain": "*.example.com", "serviceId": "svc-1", "port": float64(7480), "tlsMode": "internal"},
		map[string]interface{}{"domain": "*.ports.example.com", "host": "127.0.0.1", "port": float64(7480), "scheme": "http", "tlsMode": "internal"},
		map[string]interface{}{"domain": "a.example.com", "serviceId": "svc-1", "port": float64(3000), "tlsMode": "something-new"},
		map[string]interface{}{"domain": "b.example.com", "serviceId": "svc-1", "port": float64(3000)},
	}
	parsed := parseDomains(raw)
	want := []string{"internal", "internal", "", ""}
	if len(parsed) != len(want) {
		t.Fatalf("expected %d rows, got %d", len(want), len(parsed))
	}
	for i, w := range want {
		if parsed[i].TLSMode != w {
			t.Errorf("row %d (%s): TLSMode = %q, want %q", i, parsed[i].Domain, parsed[i].TLSMode, w)
		}
	}
}

func TestValidateDomainRowWildcard(t *testing.T) {
	good := []string{"*.example.com", "*.supercolony.run", "*.a.b.example.co.uk", "*.xn--bcher-kva.example"}
	for _, d := range good {
		row := cachedDomain{Domain: d, ServiceID: "svc", Port: 3000, TLSMode: tlsModeInternal}
		if err := validateDomainRow(row); err != nil {
			t.Errorf("validateDomainRow(%q) = %v, want nil", d, err)
		}
	}
	bad := []string{
		"*.com", "*", "*.", "**.example.com", "*.*.example.com", "a.*.example.com", "*example.com",
		"*.example.com.", "*.Example.com", "*.example.com {", "*.example.com\nrespond 200",
		"*.-a.example.com", "*.example.com:443", "*." + strings.Repeat("abcdefghi.", 25) + "com",
		"*.example.com, b.example.com", "*.{host}.com",
	}
	for _, d := range bad {
		row := cachedDomain{Domain: d, ServiceID: "svc", Port: 3000, TLSMode: tlsModeInternal}
		if err := validateDomainRow(row); err == nil {
			t.Errorf("validateDomainRow(%q) = nil, want error", d)
		}
	}
}

func TestValidateDomainRowWildcardRequiresInternalTLS(t *testing.T) {
	for _, row := range []cachedDomain{
		{Domain: "*.example.com", ServiceID: "svc", Port: 3000},
		{Domain: "*.example.com", ServiceID: "svc", Port: 3000, OnDemandTLS: true},
		{Domain: "*.example.com", ServiceID: "svc", Port: 3000, TLSMode: "acme"},
	} {
		err := validateDomainRow(row)
		if err == nil || !strings.Contains(err.Error(), "tlsMode") {
			t.Errorf("validateDomainRow(%+v) = %v, want tlsMode error", row, err)
		}
	}
}

func TestValidateDomainRowWildcardRefusesAuthGate(t *testing.T) {
	row := cachedDomain{Domain: "*.example.com", ServiceID: "svc", Port: 3000, TLSMode: tlsModeInternal, AuthGateMode: "password"}
	err := validateDomainRow(row)
	if err == nil || !strings.Contains(err.Error(), "auth gate") {
		t.Fatalf("validateDomainRow = %v, want auth gate error", err)
	}
}

func TestSanitizeDomainsDropsUnsafeWildcardsOnly(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "*.Example.com", ServiceID: "svc-1", Port: 7480, TLSMode: tlsModeInternal},
		{Domain: "*.nomode.example.com", ServiceID: "svc-1", Port: 7480},
		{Domain: "*.gated.example.com", ServiceID: "svc-1", Port: 7480, TLSMode: tlsModeInternal, AuthGateMode: "password"},
		{Domain: "app.example.com", ServiceID: "svc-2", Port: 3000},
	}
	out := sanitizeDomains(parsed)
	var got []string
	for _, d := range out {
		got = append(got, d.Domain)
	}
	want := []string{"*.example.com", "app.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sanitizeDomains kept %v, want %v", got, want)
	}
	// A refused gated wildcard never reaches the gate config either.
	if cfg := buildGateConfig(out); len(cfg.Domains) != 0 {
		t.Fatalf("expected no gate entries, got %v", cfg.Domains)
	}
}

func TestGenerateCaddyfileWildcardInternalTLS(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest")
	parsed := []cachedDomain{
		{Domain: "*.supercolony.run", ServiceID: "svc-prev", Port: 7480, TLSMode: tlsModeInternal},
	}
	out, err := generateCaddyfileChecked(parsed, map[string]slots.Slot{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "# Managed by Stacked \u2014 do not edit manually\n\n" +
		"*.supercolony.run {\n" +
		"    tls internal\n" +
		"    reverse_proxy svc-prev:7480\n" +
		"    header Server Stacked\n" +
		"}\n\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	// reverse_proxy passes the client's Host through by default; the
	// preview proxy routes on it, so nothing may rewrite it.
	if strings.Contains(out, "header_up Host") {
		t.Fatalf("wildcard upstream must keep the original Host header, got:\n%s", out)
	}
}

func TestGenerateCaddyfileWildcardFollowsActiveSlot(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "*.example.com", ServiceID: "svc-1", Port: 7480, TLSMode: tlsModeInternal},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Green})
	if !strings.Contains(out, "reverse_proxy svc-1-green:7480") {
		t.Fatalf("expected slot-aware upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfileWildcardPortBound(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "*.example.com", Host: "127.0.0.1", Port: 7480, Scheme: "http", TLSMode: tlsModeInternal},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "*.example.com {\n    tls internal\n    reverse_proxy host.docker.internal:7480\n") {
		t.Fatalf("unexpected port-bound wildcard rendering:\n%s", out)
	}
}

func TestGenerateCaddyfileWildcardMultiPath(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "*.example.com", ServiceID: "svc-web", Port: 3000, Path: "/", TLSMode: tlsModeInternal},
		{Domain: "*.example.com", ServiceID: "svc-api", Port: 8080, Path: "/api", TLSMode: tlsModeInternal},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if strings.Count(out, "*.example.com {") != 1 {
		t.Fatalf("expected one site block, got:\n%s", out)
	}
	if strings.Count(out, "tls internal") != 1 {
		t.Fatalf("expected one tls internal, got:\n%s", out)
	}
	apiIdx := strings.Index(out, "handle_path /api* {\n        reverse_proxy svc-api:8080")
	rootIdx := strings.Index(out, "handle {\n        reverse_proxy svc-web:3000")
	if apiIdx < 0 || rootIdx < 0 || apiIdx > rootIdx {
		t.Fatalf("expected /api handle before root handle, got:\n%s", out)
	}
}

func TestGenerateCaddyfileWildcardCoexistsWithConcreteAndOnDemand(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest")
	parsed := []cachedDomain{
		{Domain: "*.example.com", ServiceID: "svc-prev", Port: 7480, TLSMode: tlsModeInternal},
		// A concrete host under the wildcard keeps its own block and
		// its normal certificate; Caddy prefers the exact match.
		{Domain: "api.example.com", ServiceID: "svc-api", Port: 3000},
		{Domain: "od.other.com", ServiceID: "svc-od", Port: 3000, OnDemandTLS: true},
	}
	out, err := generateCaddyfileChecked(parsed, map[string]slots.Slot{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	blocks := siteBlocks(out)
	if got := blocks["*.example.com"]; !strings.Contains(got, "tls internal") || strings.Contains(got, "on_demand") {
		t.Fatalf("wildcard block wrong:\n%s", got)
	}
	if got := blocks["api.example.com"]; strings.Contains(got, "tls") || !strings.Contains(got, "reverse_proxy svc-api:3000") {
		t.Fatalf("concrete block wrong:\n%s", got)
	}
	if got := blocks["od.other.com"]; !strings.Contains(got, "on_demand") || strings.Contains(got, "tls internal") {
		t.Fatalf("on-demand block wrong:\n%s", got)
	}
	// The on-demand row still gets its global ask block.
	if strings.Count(out, "on_demand_tls {") != 1 {
		t.Fatalf("expected one global on_demand_tls block, got:\n%s", out)
	}
}

func TestGenerateCaddyfileWildcardAddsNoOnDemandBlock(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest")
	parsed := []cachedDomain{
		// Even with the on-demand flag set, an internal-TLS host needs no
		// ACME issuance and so no `ask` endpoint.
		{Domain: "*.example.com", ServiceID: "svc-prev", Port: 7480, TLSMode: tlsModeInternal, OnDemandTLS: true},
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if strings.Contains(out, "on_demand") {
		t.Fatalf("wildcard must not add on_demand config, got:\n%s", out)
	}
	if strings.HasPrefix(strings.TrimPrefix(out, "# Managed by Stacked \u2014 do not edit manually\n\n"), "{") {
		t.Fatalf("wildcard must not add a global options block, got:\n%s", out)
	}
}

func TestGenerateCaddyfileCheckedRejectsWildcardWithoutInternalTLS(t *testing.T) {
	parsed := []cachedDomain{{Domain: "*.example.com", ServiceID: "svc", Port: 3000}}
	if _, err := generateCaddyfileChecked(parsed, map[string]slots.Slot{}); err == nil {
		t.Fatal("expected an error for a wildcard row without internal TLS")
	}
}

// siteBlocks splits a rendered Caddyfile into its top-level site
// blocks, keyed by site address.
func siteBlocks(caddyfile string) map[string]string {
	out := map[string]string{}
	for _, chunk := range strings.Split(caddyfile, "\n}\n") {
		lines := strings.SplitN(strings.TrimLeft(chunk, "\n"), "\n", 2)
		if len(lines) < 2 || !strings.HasSuffix(lines[0], " {") {
			continue
		}
		out[strings.TrimSuffix(lines[0], " {")] = lines[1]
	}
	return out
}
