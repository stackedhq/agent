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
	if !strings.Contains(internal, "- stacked") {
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
