package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateServerOriginAcceptsHTTPSOrigins(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://stacked.rest", "https://stacked.rest"},
		{"https://stacked.rest/", "https://stacked.rest"},
		{"  https://stacked.rest/  ", "https://stacked.rest"},
		{"https://stacked.rest:8443", "https://stacked.rest:8443"},
		{"https://127.0.0.1", "https://127.0.0.1"},
		{"https://[::1]", "https://[::1]"},
		{"https://[::1]:8443", "https://[::1]:8443"},
		{"https://localhost", "https://localhost"},
	}
	for _, tc := range cases {
		got, err := ValidateServerOrigin(tc.in, false)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateServerOriginRejectsUnsafeOrAmbiguous(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "required"},
		{"http://stacked.rest", "http is not allowed"},
		{"http://example.com", "http is not allowed"},
		{"https://user:pass@stacked.rest", "userinfo"},
		{"https://user@stacked.rest", "userinfo"},
		{"https://stacked.rest?x=1", "query"},
		{"https://stacked.rest?", "query"},
		{"https://stacked.rest#frag", "fragment"},
		{"https://stacked.rest#", "fragment"},
		{"https://stacked.rest/api", "origin"},
		{"https://stacked.rest/api/agent", "origin"},
		{"https://stacked.rest/.", "origin"},
		{"https://stacked.rest//evil.com", "origin"},
		{"https://stacked.rest/%2fadmin", "origin"},
		{"https://", "host"},
		{"https:///path", "host"},
		{"stacked.rest", "https"},
		{"ftp://stacked.rest", "https"},
		{"//stacked.rest", "https"},
		{"https://stacked.rest:0", "port"},
		{"https://stacked.rest:65536", "port"},
		{"https://stacked.rest:abc", "invalid URL"},
		{"https://-foo.com", "malformed host"},
		{"https://foo-.com", "malformed host"},
		{"https://foo..com", "malformed host"},
		{"https://.", "malformed host"},
		{"https://foo_bar.com", "malformed host"},
		{"https://127.0.0.1@evil.com", "userinfo"},
		{"https://stacked .rest", "whitespace"},
	}
	for _, tc := range cases {
		_, err := ValidateServerOrigin(tc.in, false)
		if err == nil {
			t.Errorf("%q: accepted, want error containing %q", tc.in, tc.want)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
			t.Errorf("%q: error %q, want substring %q", tc.in, err, tc.want)
		}
	}
}

func TestValidateServerOriginHTTPLoopbackRequiresOptIn(t *testing.T) {
	loopbacks := []string{
		"http://127.0.0.1",
		"http://127.0.0.1:8787",
		"http://localhost",
		"http://localhost:3000",
		"http://[::1]",
		"http://[::1]:8787",
		"http://127.0.0.8",
	}
	for _, in := range loopbacks {
		if _, err := ValidateServerOrigin(in, false); err == nil {
			t.Errorf("%q: http loopback accepted without opt-in", in)
		}
		got, err := ValidateServerOrigin(in, true)
		if err != nil {
			t.Errorf("%q: opt-in loopback rejected: %v", in, err)
			continue
		}
		if !strings.HasPrefix(got, "http://") {
			t.Errorf("%q: got %q", in, got)
		}
	}

	if _, err := ValidateServerOrigin("http://stacked.rest", true); err == nil {
		t.Fatal("http non-loopback accepted with opt-in")
	}
	if _, err := ValidateServerOrigin("http://192.168.1.10", true); err == nil {
		t.Fatal("http LAN address accepted with opt-in")
	}
	if _, err := ValidateServerOrigin("http://[::ffff:127.0.0.1]", true); err != nil {
		t.Fatalf("IPv4-mapped loopback should be allowed with opt-in: %v", err)
	}
}

func TestLoadValidatesServer(t *testing.T) {
	t.Setenv(AllowInsecureHTTPEnv, "")

	cfg := loadTOML(t, `
[agent]
token = "stk_testtoken"
server = "https://stacked.rest/"
`)
	if cfg.Agent.Server != "https://stacked.rest" {
		t.Fatalf("server = %q", cfg.Agent.Server)
	}

	_, err := loadTOMLErr(t, `
[agent]
token = "stk_testtoken"
server = "http://stacked.rest"
`)
	if err == nil || !strings.Contains(err.Error(), "http is not allowed") {
		t.Fatalf("want http rejection, got %v", err)
	}
}

func TestLoadAllowsLoopbackHTTPWithEnvOptIn(t *testing.T) {
	t.Setenv(AllowInsecureHTTPEnv, "1")
	cfg := loadTOML(t, `
[agent]
token = "stk_testtoken"
server = "http://127.0.0.1:8787"
`)
	if cfg.Agent.Server != "http://127.0.0.1:8787" {
		t.Fatalf("server = %q", cfg.Agent.Server)
	}

	_, err := loadTOMLErr(t, `
[agent]
token = "stk_testtoken"
server = "http://example.com"
`)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("want loopback rejection, got %v", err)
	}
}

func TestLoad_VolumesAllowlist(t *testing.T) {
	t.Setenv(AllowInsecureHTTPEnv, "")
	cfg := loadTOML(t, `
[agent]
token = "stk_testtoken"
server = "https://stacked.example/"

[volumes]
allowed_host_roots = ["/srv/data", "/mnt/storage"]
`)
	if cfg.Agent.Server != "https://stacked.example" {
		t.Fatalf("server = %q", cfg.Agent.Server)
	}
	if len(cfg.Volumes.AllowedHostRoots) != 2 || cfg.Volumes.AllowedHostRoots[0] != "/srv/data" {
		t.Fatalf("allowlist = %#v", cfg.Volumes.AllowedHostRoots)
	}
}

func TestLoad_VolumesOptional(t *testing.T) {
	t.Setenv(AllowInsecureHTTPEnv, "")
	cfg := loadTOML(t, `
[agent]
token = "stk_testtoken"
server = "https://stacked.example"
`)
	if len(cfg.Volumes.AllowedHostRoots) != 0 {
		t.Fatalf("expected empty allowlist, got %#v", cfg.Volumes.AllowedHostRoots)
	}
}

func loadTOML(t *testing.T, body string) *Config {
	t.Helper()
	cfg, err := loadTOMLErr(t, body)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func loadTOMLErr(t *testing.T, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKED_CONFIG", path)
	return Load()
}
