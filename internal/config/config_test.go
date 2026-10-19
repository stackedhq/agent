package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_VolumesAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	content := `
[agent]
token = "stk_testtoken"
server = "https://stacked.example/"

[volumes]
allowed_host_roots = ["/srv/data", "/mnt/storage"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKED_CONFIG", path)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.Server != "https://stacked.example" {
		t.Fatalf("server = %q", cfg.Agent.Server)
	}
	if len(cfg.Volumes.AllowedHostRoots) != 2 || cfg.Volumes.AllowedHostRoots[0] != "/srv/data" {
		t.Fatalf("allowlist = %#v", cfg.Volumes.AllowedHostRoots)
	}
}

func TestLoad_VolumesOptional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.toml")
	if err := os.WriteFile(path, []byte(`
[agent]
token = "stk_testtoken"
server = "https://stacked.example"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKED_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Volumes.AllowedHostRoots) != 0 {
		t.Fatalf("expected empty allowlist, got %#v", cfg.Volumes.AllowedHostRoots)
	}
}
