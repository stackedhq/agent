package executor

import (
	"strings"
	"testing"
)

func TestRenderDatabasePorts(t *testing.T) {
	// internal → no host binding at all.
	if got := renderDatabasePorts("internal", "", 15432, 5432); got != "" {
		t.Errorf("internal must publish no port, got %q", got)
	}
	// unknown mode → fail closed (no publish).
	if got := renderDatabasePorts("nonsense", "", 15432, 5432); got != "" {
		t.Errorf("unknown mode must fail closed, got %q", got)
	}
	// public → bind 0.0.0.0 (no host IP prefix).
	pub := renderDatabasePorts("public", "", 15432, 5432)
	if !strings.Contains(pub, `- "15432:5432"`) {
		t.Errorf("public must bind host:native without IP prefix, got %q", pub)
	}
	// tailnet → bind the tailscale IP.
	tn := renderDatabasePorts("tailnet", "100.64.0.5", 15432, 5432)
	if !strings.Contains(tn, `- "100.64.0.5:15432:5432"`) {
		t.Errorf("tailnet must bind the tailscale IP, got %q", tn)
	}
	// tailnet without a tailscale IP → fail closed, publish nothing.
	if got := renderDatabasePorts("tailnet", "", 15432, 5432); got != "" {
		t.Errorf("tailnet without IP must fail closed, got %q", got)
	}
}

func TestResolveAccessMode(t *testing.T) {
	if got := resolveAccessMode("public"); got != "public" {
		t.Errorf("public must stay public, got %q", got)
	}
	if got := resolveAccessMode("tailnet"); got != "tailnet" {
		t.Errorf("tailnet must stay tailnet, got %q", got)
	}
	if got := resolveAccessMode("internal"); got != "internal" {
		t.Errorf("internal must stay internal, got %q", got)
	}
	for _, mode := range []string{"", "Public", "PUBLIC", "nonsense", "legacy"} {
		if got := resolveAccessMode(mode); got != "internal" {
			t.Errorf("resolveAccessMode(%q) = %q, want internal", mode, got)
		}
	}
}

func TestValidateDatabasePort(t *testing.T) {
	for _, port := range []int{1, 80, 5432, 65535} {
		if err := validateDatabasePort(port); err != nil {
			t.Errorf("port %d should be valid: %v", port, err)
		}
	}
	for _, port := range []int{0, -1, 65536, 70000} {
		if err := validateDatabasePort(port); err == nil {
			t.Errorf("port %d should be rejected", port)
		}
	}
}

func TestValidateBindHost(t *testing.T) {
	if err := validateBindHost(""); err != nil {
		t.Errorf("empty bind host is allowed (fail closed later): %v", err)
	}
	for _, ip := range []string{"100.64.0.5", "127.0.0.1", "2001:db8::1"} {
		if err := validateBindHost(ip); err != nil {
			t.Errorf("valid IP %q rejected: %v", ip, err)
		}
	}
	for _, bad := range []string{"not-an-ip", "100.64.0", "localhost", "0.0.0.0/0"} {
		if err := validateBindHost(bad); err == nil {
			t.Errorf("invalid bind host %q accepted", bad)
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
	internal, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "internal", "", "db-1")
	if err != nil {
		t.Fatalf("internal compose: %v", err)
	}
	if strings.Contains(internal, "ports:") {
		t.Errorf("internal database must not publish ports:\n%s", internal)
	}
	// Shared `stacked` stays attached so isolationRelaxed services and
	// docker exec keep working; isolated apps reach DBs via stacked-data.
	if !strings.Contains(internal, "stacked:") && !strings.Contains(internal, "- stacked") {
		t.Errorf("expected stacked network membership:\n%s", internal)
	}
	if !strings.Contains(internal, "stacked-data") {
		t.Errorf("expected stacked-data membership:\n%s", internal)
	}
	if !strings.Contains(internal, "stacked-db-db-1") {
		t.Errorf("expected per-database network:\n%s", internal)
	}

	// public → publishes on 0.0.0.0.
	public, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "public", "", "db-1")
	if err != nil {
		t.Fatalf("public compose: %v", err)
	}
	if !strings.Contains(public, `- "15432:5432"`) {
		t.Errorf("public database must publish 15432:5432:\n%s", public)
	}

	// tailnet → bound to the tailscale IP.
	tailnet, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "tailnet", "100.64.0.5", "db-1")
	if err != nil {
		t.Fatalf("tailnet compose: %v", err)
	}
	if !strings.Contains(tailnet, `- "100.64.0.5:15432:5432"`) {
		t.Errorf("tailnet database must bind tailscale IP:\n%s", tailnet)
	}
}

func TestGenerateDatabaseComposeMissingOrUnknownMode(t *testing.T) {
	creds := map[string]string{
		"user":     "stk_user",
		"password": "secretpw",
		"dbName":   "stk_db",
	}

	// Legacy/malformed payloads must not grow a host port mapping.
	for _, mode := range []string{"", "nonsense", "PUBLIC"} {
		got, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, mode, "", "db-1")
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if strings.Contains(got, "ports:") || strings.Contains(got, "15432:5432") {
			t.Errorf("mode %q must publish no host port:\n%s", mode, got)
		}
	}
}

func TestGenerateDatabaseComposeRejectsBadPublishConfig(t *testing.T) {
	creds := map[string]string{
		"user":     "stk_user",
		"password": "secretpw",
		"dbName":   "stk_db",
	}

	if _, err := generateDatabaseCompose("postgres", 0, "postgres-x", "postgres:16", creds, "public", "", "db-1"); err == nil {
		t.Fatal("public with port 0 must be rejected")
	}
	if _, err := generateDatabaseCompose("postgres", 70000, "postgres-x", "postgres:16", creds, "public", "", "db-1"); err == nil {
		t.Fatal("public with port 70000 must be rejected")
	}
	if _, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "tailnet", "not-an-ip", "db-1"); err == nil {
		t.Fatal("tailnet with invalid bind IP must be rejected")
	}

	// tailnet without an IP still fails closed (no publish), no error.
	got, err := generateDatabaseCompose("postgres", 15432, "postgres-x", "postgres:16", creds, "tailnet", "", "db-1")
	if err != nil {
		t.Fatalf("tailnet without IP: %v", err)
	}
	if strings.Contains(got, "ports:") {
		t.Errorf("tailnet without IP must publish no host port:\n%s", got)
	}
}
