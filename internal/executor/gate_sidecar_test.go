package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withGateFakes points the gate config at a temp dir and stubs the
// docker-touching steps. status returns whatever hash the fake reports.
func withGateFakes(t *testing.T, status func(written []byte) (gateStatus, error)) (cfgPath string, started, signaled *int) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gate")
	origDir, origPath := gateDir, gateConfigPath
	origStart, origSignal, origStatus := gateStartFn, gateSignalFn, gateStatusFn
	origTimeout, origPoll := gateLoadTimeout, gatePollEvery
	t.Cleanup(func() {
		gateDir, gateConfigPath = origDir, origPath
		gateStartFn, gateSignalFn, gateStatusFn = origStart, origSignal, origStatus
		gateLoadTimeout, gatePollEvery = origTimeout, origPoll
	})
	gateDir = dir
	gateConfigPath = filepath.Join(dir, "config.json")
	gateLoadTimeout = 50 * time.Millisecond
	gatePollEvery = 5 * time.Millisecond
	var s, g int
	gateStartFn = func() error { s++; return nil }
	gateSignalFn = func() error { g++; return nil }
	gateStatusFn = func() (gateStatus, error) {
		data, _ := os.ReadFile(gateConfigPath)
		return status(data)
	}
	return gateConfigPath, &s, &g
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func gatedRow(domain, path, user, hash string) cachedDomain {
	return cachedDomain{
		Domain: domain, ServiceID: "svc-" + strings.Trim(path, "/"), Port: 3000, Path: path,
		AuthGateMode: "password", AuthGateUsername: user, AuthGatePasswordHash: hash,
	}
}

// A host whose rows carry different gate credentials is left out of the
// gate config (so the gate denies it) without affecting other domains,
// and the Caddyfile still routes it through forward_auth.
func TestBuildGateConfigExcludesHostWithDifferingCreds(t *testing.T) {
	rows := []cachedDomain{
		gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa"),
		gatedRow("app.example.com", "/admin", "root", "$2a$10$bbbb"),
		gatedRow("app.example.com", "/api", "admin", "$2a$10$aaaa"),
		gatedRow("other.example.com", "/", "admin", "$2a$10$cccc"),
	}
	cfg := buildGateConfig(rows)
	if _, ok := cfg.Domains["app.example.com"]; ok {
		t.Fatalf("conflicting host must be excluded from the gate config: %+v", cfg)
	}
	if cfg.Domains["other.example.com"].PasswordHash != "$2a$10$cccc" {
		t.Fatalf("unrelated gated host must stay configured: %+v", cfg)
	}
	out, err := generateCaddyfileChecked(rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	block := out[strings.Index(out, "app.example.com {"):strings.Index(out, "other.example.com {")]
	if !strings.Contains(block, "forward_auth "+gateUpstream) {
		t.Fatalf("conflicting host must still go through the gate (fail closed):\n%s", block)
	}
}

func TestBuildGateConfigSameCredsAndUngatedRows(t *testing.T) {
	rows := []cachedDomain{
		gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa"),
		gatedRow("app.example.com", "/api", "admin", "$2a$10$aaaa"),
		{Domain: "app.example.com", ServiceID: "svc-docs", Port: 3000, Path: "/docs"},
		{Domain: "open.example.com", ServiceID: "svc-open", Port: 3000},
	}
	cfg := buildGateConfig(rows)
	if len(cfg.Domains) != 1 || cfg.Domains["app.example.com"].Username != "admin" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestApplyGateConfigWaitsForGateToLoad(t *testing.T) {
	path, started, signaled := withGateFakes(t, func(written []byte) (gateStatus, error) {
		return gateStatus{Loaded: true, ConfigHash: hashOf(written)}, nil
	})
	cfg := buildGateConfig([]cachedDomain{gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa")})
	if err := applyGateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if *started != 1 || *signaled != 1 {
		t.Fatalf("started=%d signaled=%d", *started, *signaled)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v, want 0600", info.Mode().Perm())
	}
	dirInfo, _ := os.Stat(filepath.Dir(path))
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("gate dir mode %v, want 0700", dirInfo.Mode().Perm())
	}
	var got gateConfig
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &got); err != nil || got.Domains["app.example.com"].PasswordHash != "$2a$10$aaaa" {
		t.Fatalf("written config %s (%v)", data, err)
	}
}

func TestApplyGateConfigFailsWhenGateDoesNotLoad(t *testing.T) {
	withGateFakes(t, func([]byte) (gateStatus, error) {
		return gateStatus{Loaded: true, ConfigHash: "stale"}, nil
	})
	cfg := buildGateConfig([]cachedDomain{gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa")})
	if err := applyGateConfig(cfg); err == nil {
		t.Fatal("expected error when the gate never reports the new config")
	}
}

func TestApplyGateConfigFailsWhenGateCannotStart(t *testing.T) {
	withGateFakes(t, func(written []byte) (gateStatus, error) {
		return gateStatus{Loaded: true, ConfigHash: hashOf(written)}, nil
	})
	gateStartFn = func() error { return errors.New("no binary") }
	cfg := buildGateConfig([]cachedDomain{gatedRow("app.example.com", "/", "admin", "$2a$10$aaaa")})
	if err := applyGateConfig(cfg); err == nil || !strings.Contains(err.Error(), "no binary") {
		t.Fatalf("expected start error, got %v", err)
	}
}

func TestApplyGateConfigClearsConfigWhenNoGates(t *testing.T) {
	path, started, _ := withGateFakes(t, func([]byte) (gateStatus, error) {
		return gateStatus{}, errors.New("gate down")
	})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"domains":{"old.example.com":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := buildGateConfig([]cachedDomain{{Domain: "open.example.com", ServiceID: "s", Port: 3000}})
	// Gate being down must not fail an op that gates nothing.
	if err := applyGateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if *started != 0 {
		t.Fatal("gate should not be required when nothing is gated")
	}
	data, _ := os.ReadFile(path)
	var got gateConfig
	if err := json.Unmarshal(data, &got); err != nil || len(got.Domains) != 0 {
		t.Fatalf("config not cleared: %s", data)
	}
}

func TestWriteFileAtomicReplacesAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := writeFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "two" {
		t.Fatalf("content %q", data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func TestProxyComposeRunsGateIsolated(t *testing.T) {
	c := proxyCompose()
	for _, want := range []string{
		"  stacked-gate:\n",
		"container_name: stacked-gate",
		`entrypoint: ["/stacked-agent", "gate"]`,
		agentBinaryPath + ":/stacked-agent:ro",
		gateDir + ":/opt/stacked/gate",
		"name: " + gateNetworkName,
		"internal: true",
		"read_only: true",
		"com.stacked.agent-version:",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("compose missing %q:\n%s", want, c)
		}
	}
	if strings.Contains(c, "\n  gate:\n    image") {
		t.Error("legacy `gate` service still present")
	}
	// The gate must not be on the shared stacked network.
	gateSvc := c[strings.Index(c, "  stacked-gate:\n"):strings.Index(c, "\nvolumes:")]
	if strings.Contains(gateSvc, "- stacked\n") {
		t.Errorf("gate service joined the stacked network:\n%s", gateSvc)
	}
}
