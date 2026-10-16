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

func TestLoadRequiresHTTPS(t *testing.T) {
	if _, err := loadFrom(t, "http://stacked.rest"); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("err = %v, want https requirement", err)
	}
}

func TestLoadAcceptsHTTPSAndLocalHTTP(t *testing.T) {
	for _, s := range []string{"https://stacked.rest/", "http://localhost:3000"} {
		cfg, err := loadFrom(t, s)
		if err != nil {
			t.Fatalf("Load(%q): %v", s, err)
		}
		if strings.HasSuffix(cfg.Agent.Server, "/") {
			t.Fatalf("trailing slash not stripped: %q", cfg.Agent.Server)
		}
	}
}
