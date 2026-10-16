package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFrom(t *testing.T, server string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.toml")
	body := "[agent]\ntoken = \"stk_test\"\nserver = \"" + server + "\"\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKED_CONFIG", p)
	return Load()
}

// A non-loopback http:// URL is upgraded to https (with a warning)
// instead of failing startup, which would restart-loop the agent.
func TestLoadUpgradesRemoteHTTPToHTTPS(t *testing.T) {
	cases := map[string]string{
		"http://stacked.rest":             "https://stacked.rest",
		"http://stacked.rest/":            "https://stacked.rest",
		"http://example.com:8443/prefix/": "https://example.com:8443/prefix",
		"http://10.0.0.5:3000":            "https://10.0.0.5:3000",
	}
	for in, want := range cases {
		cfg, err := loadFrom(t, in)
		if err != nil {
			t.Fatalf("Load(%q): %v", in, err)
		}
		if cfg.Agent.Server != want {
			t.Fatalf("Load(%q).Server = %q, want %q", in, cfg.Agent.Server, want)
		}
	}
}

func TestLoadRejectsBrokenServerURL(t *testing.T) {
	for _, s := range []string{"ftp://stacked.rest", "stacked.rest", "https://user:pass@stacked.rest"} {
		if _, err := loadFrom(t, s); err == nil {
			t.Fatalf("Load(%q): want error", s)
		}
	}
}

func TestLoadAcceptsHTTPSAndLocalHTTP(t *testing.T) {
	for _, s := range []string{"https://stacked.rest/", "http://localhost:3000", "http://127.0.0.1:3000"} {
		cfg, err := loadFrom(t, s)
		if err != nil {
			t.Fatalf("Load(%q): %v", s, err)
		}
		if strings.HasPrefix(s, "http://") && !strings.HasPrefix(cfg.Agent.Server, "http://") {
			t.Fatalf("loopback http must stay http: %q", cfg.Agent.Server)
		}
		if strings.HasSuffix(cfg.Agent.Server, "/") {
			t.Fatalf("trailing slash not stripped: %q", cfg.Agent.Server)
		}
	}
}
