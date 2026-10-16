package executor

import (
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/slots"
)

func TestValidCaddyDomain(t *testing.T) {
	for _, d := range []string{"app.example.com", "a.b", "xn--bcher-kva.example", "1-2.example.co.uk", strings.Repeat("a", 63) + ".com"} {
		if !validCaddyDomain(d) {
			t.Errorf("validCaddyDomain(%q) = false, want true", d)
		}
	}
	for _, d := range []string{
		"", "localhost", "App.example.com", "*.example.com", "app.example.com.", "-a.example.com",
		"a-.example.com", "a..b", "app.example.com:443", "app.example.com {", "app.example.com\nrespond 200",
		"app_1.example.com", "{host}.example.com", "a.example.com, b.example.com", "http://a.example.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("abcdefghi.", 26) + "com",
	} {
		if validCaddyDomain(d) {
			t.Errorf("validCaddyDomain(%q) = true, want false", d)
		}
	}
}

func TestValidCaddyPath(t *testing.T) {
	for _, p := range []string{"/", "/api", "/api/v1", "/a-b_c.d~e", "/%20x", "/@me", "/a:b"} {
		if !validCaddyPath(p) {
			t.Errorf("validCaddyPath(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"", "api", "/api {", "/{path}", "/a}", "/a b", "/a\tb", "/a\nrespond 200", "/a#b", "/a?b", `/a"b`, "/a\\b", "/" + strings.Repeat("a", maxCaddyPathLen)} {
		if validCaddyPath(p) {
			t.Errorf("validCaddyPath(%q) = true, want false", p)
		}
	}
}

func TestSanitizeDomainsLowercasesAndSkipsBadRows(t *testing.T) {
	in := []cachedDomain{
		{Domain: "APP.Example.com", ServiceID: "svc-1", Port: 3000},
		{Domain: "evil.example.com {\n}", ServiceID: "svc-2", Port: 3000},
		{Domain: "ok.example.com", ServiceID: "svc-3", Port: 3000, Path: "/api {"},
		{Domain: "ok.example.com", ServiceID: "svc-4", Port: 3000, Path: "/v1"},
	}
	got := sanitizeDomains(in)
	if len(got) != 2 || got[0].Domain != "app.example.com" || got[1].ServiceID != "svc-4" {
		t.Fatalf("sanitizeDomains = %+v", got)
	}
}

func TestGenerateCaddyfileCheckedRejectsUnsanitizedDomain(t *testing.T) {
	_, err := generateCaddyfileChecked([]cachedDomain{{Domain: "a.example.com {\n}", ServiceID: "s", Port: 1}}, nil)
	if err == nil {
		t.Fatal("expected error for unsafe domain")
	}
	_, err = generateCaddyfileChecked([]cachedDomain{{Domain: "a.example.com", ServiceID: "s", Port: 1, Path: "/x {"}}, nil)
	if err == nil {
		t.Fatal("expected error for unsafe path")
	}
}

func TestGenerateCaddyfileGateUsesFixedDomainHeader(t *testing.T) {
	parsed := []cachedDomain{
		gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa"),
		{Domain: "open.example.com", ServiceID: "svc-open", Port: 3000},
	}
	out, err := generateCaddyfileChecked(parsed, map[string]slots.Slot{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"reverse_proxy stacked-gate:9876 {",
		"forward_auth stacked-gate:9876 {",
		"header_up X-Stacked-Gate-Domain app.example.com",
		"header_up X-Original-URI {uri}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "header_up X-Stacked-Gate-Domain app.example.com") != 2 {
		t.Errorf("domain header must be set on both the login proxy and forward_auth:\n%s", out)
	}
	if strings.Contains(out, " gate:9876") || strings.Contains(out, "{host}") {
		t.Errorf("legacy gate upstream or {host} keying still present:\n%s", out)
	}
	openBlock := out[strings.Index(out, "open.example.com {"):]
	if strings.Contains(openBlock, "forward_auth") {
		t.Errorf("ungated host got forward_auth:\n%s", openBlock)
	}
}

func TestValidateUpstreamHostRejectsDangerousAddresses(t *testing.T) {
	for _, h := range []string{
		"127.0.0.2", "127.1.2.3", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]", "0.0.0.0", "::", "[::]",
		"169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "[fe80::1]", "224.0.0.1", "ff02::1",
		"255.255.255.255", "host.docker.internal", "HOST.DOCKER.INTERNAL", "host.docker.internal.",
		"foo.localhost", "stacked-gate", "caddy", "fe80::1%eth0",
	} {
		if err := validateUpstreamHost(h); err == nil {
			t.Errorf("validateUpstreamHost(%q) accepted, want rejection", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "10.0.0.5", "192.168.1.10", "100.64.0.1", "2001:db8::1", "plex", "nas.lan"} {
		if err := validateUpstreamHost(h); err != nil {
			t.Errorf("validateUpstreamHost(%q) = %v, want ok", h, err)
		}
	}
}

func TestRenderUpstreamHostPortLoopbackRewriteIsExplicit(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1", "[::1]"} {
		got, err := renderUpstreamHostPort(h, 8080)
		if err != nil || got != "host.docker.internal:8080" {
			t.Errorf("%s -> %q, %v; want host.docker.internal:8080", h, got, err)
		}
	}
	if _, err := renderUpstreamHostPort("::ffff:127.0.0.1", 8080); err == nil {
		t.Error("v4-mapped loopback must be rejected, not rewritten")
	}
}

func withMachineID(t *testing.T, id string) {
	t.Helper()
	prev := currentMachineID()
	machineID.Store("")
	NoteMachineID(id)
	t.Cleanup(func() { machineID.Store(prev) })
}

func TestOnDemandAskURLIncludesMachineID(t *testing.T) {
	withServerBaseURL(t, "https://stacked.rest/")

	withMachineID(t, "")
	if got := onDemandAskURL(); got != "https://stacked.rest/api/agent/tls/ask" {
		t.Fatalf("no machine id: %q", got)
	}

	withMachineID(t, "not-a-uuid {")
	if got := onDemandAskURL(); got != "https://stacked.rest/api/agent/tls/ask" {
		t.Fatalf("invalid machine id must be ignored: %q", got)
	}

	withMachineID(t, "3F2A1B4C-1D2E-4F5A-8B9C-0D1E2F3A4B5C")
	want := "https://stacked.rest/api/agent/tls/ask?m=3f2a1b4c-1d2e-4f5a-8b9c-0d1e2f3a4b5c"
	if got := onDemandAskURL(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	out := generateCaddyfile([]cachedDomain{{Domain: "od.example.com", ServiceID: "s", Port: 3000, OnDemandTLS: true}}, nil)
	if !strings.Contains(out, "ask "+want+"\n") {
		t.Fatalf("Caddyfile ask line missing machine id:\n%s", out)
	}
}
