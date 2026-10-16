package executor

import (
	"strings"
	"testing"
)

func TestDatabasePortSpecs(t *testing.T) {
	mustSpecs := func(mode, host string) []string {
		t.Helper()
		got, err := databasePortSpecs(mode, host, 15432, 5432)
		if err != nil {
			t.Fatalf("databasePortSpecs(%q, %q): %v", mode, host, err)
		}
		return got
	}
	// internal → no host binding at all.
	if got := mustSpecs("internal", ""); len(got) != 0 {
		t.Errorf("internal must publish no port, got %q", got)
	}
	// unknown mode → fail closed (no publish).
	if got := mustSpecs("nonsense", ""); len(got) != 0 {
		t.Errorf("unknown mode must fail closed, got %q", got)
	}
	// public → bind 0.0.0.0 (no host IP prefix).
	if got := mustSpecs("public", ""); len(got) != 1 || got[0] != "15432:5432" {
		t.Errorf("public must bind host:native without IP prefix, got %q", got)
	}
	// tailnet → bind the tailscale IP.
	if got := mustSpecs("tailnet", "100.64.0.5"); len(got) != 1 || got[0] != "100.64.0.5:15432:5432" {
		t.Errorf("tailnet must bind the tailscale IP, got %q", got)
	}
	// IPv6 tailscale address → bracketed.
	if got := mustSpecs("tailnet", "fd7a:115c:a1e0::1"); len(got) != 1 || got[0] != "[fd7a:115c:a1e0::1]:15432:5432" {
		t.Errorf("tailnet IPv6 must be bracketed, got %q", got)
	}
	// tailnet without a tailscale IP → fail closed, publish nothing.
	if got := mustSpecs("tailnet", ""); len(got) != 0 {
		t.Errorf("tailnet without IP must fail closed, got %q", got)
	}
	// Anything that isn't an IP is rejected rather than spliced in.
	for _, bad := range []string{"0.0.0.0:1:2\n  evil: x", "localhost", "100.64.0.5 ", "fe80::1%eth0", "$HOST"} {
		if _, err := databasePortSpecs("tailnet", bad, 15432, 5432); err == nil {
			t.Errorf("tailnet bindHost %q must be rejected", bad)
		}
	}
}

func TestGenerateDatabaseComposeAccessModes(t *testing.T) {
	creds := map[string]string{
		"user":     "stk_user",
		"password": "secretpw",
		"dbName":   "stk_db",
	}

	// internal → compose carries no `ports:` block.
	internal, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "internal", "")
	if err != nil {
		t.Fatalf("internal compose: %v", err)
	}
	if strings.Contains(internal, "ports:") {
		t.Errorf("internal database must not publish ports:\n%s", internal)
	}
	// Still on the stacked network so links + docker exec keep working.
	if !strings.Contains(internal, `- "stacked"`) {
		t.Errorf("expected stacked network membership:\n%s", internal)
	}

	// public → publishes on 0.0.0.0.
	public, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "public", "")
	if err != nil {
		t.Fatalf("public compose: %v", err)
	}
	if !strings.Contains(public, `- "15432:5432"`) {
		t.Errorf("public database must publish 15432:5432:\n%s", public)
	}

	// tailnet → bound to the tailscale IP.
	tailnet, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "tailnet", "100.64.0.5")
	if err != nil {
		t.Fatalf("tailnet compose: %v", err)
	}
	if !strings.Contains(tailnet, `- "100.64.0.5:15432:5432"`) {
		t.Errorf("tailnet database must bind tailscale IP:\n%s", tailnet)
	}
}
