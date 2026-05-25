package heartbeat

import "testing"

func TestParseTailscaleStatus_Running(t *testing.T) {
	raw := []byte(`{
		"BackendState": "Running",
		"TailscaleIPs": ["100.64.0.5", "fd7a:115c:a1e0::5"],
		"CurrentTailnet": {"Name": "alice@example.com"},
		"Self": {
			"ID": "nID_abc123",
			"DNSName": "my-vps-ab12cd.taildead.ts.net.",
			"TailscaleIPs": ["100.64.0.5", "fd7a:115c:a1e0::5"]
		},
		"User": {"123": {"LoginName": "alice@example.com"}}
	}`)
	got := parseTailscaleStatus(raw)
	if got == nil {
		t.Fatal("expected non-nil status")
	}
	if got.Status != "connected" {
		t.Errorf("Status = %q, want connected", got.Status)
	}
	if got.IPv4 != "100.64.0.5" {
		t.Errorf("IPv4 = %q", got.IPv4)
	}
	if got.IPv6 != "fd7a:115c:a1e0::5" {
		t.Errorf("IPv6 = %q", got.IPv6)
	}
	if got.MagicDNSName != "my-vps-ab12cd.taildead.ts.net" {
		t.Errorf("MagicDNSName = %q (should have trailing dot stripped)", got.MagicDNSName)
	}
	if got.NodeID != "nID_abc123" {
		t.Errorf("NodeID = %q", got.NodeID)
	}
	if got.LoginName != "alice@example.com" {
		t.Errorf("LoginName = %q", got.LoginName)
	}
	if got.TailnetName != "alice@example.com" {
		t.Errorf("TailnetName = %q", got.TailnetName)
	}
}

func TestParseTailscaleStatus_NeedsLoginIsExpired(t *testing.T) {
	// Tailnet keys expire by default; the CLI reports BackendState=NeedsLogin
	// once that happens. The dashboard renders this as "Key expired".
	raw := []byte(`{"BackendState": "NeedsLogin"}`)
	got := parseTailscaleStatus(raw)
	if got == nil || got.Status != "needs_login" {
		t.Fatalf("got %+v, want status=needs_login", got)
	}
}

func TestParseTailscaleStatus_NeedsMachineAuthIsDistinct(t *testing.T) {
	// Tailnets with device-approval require an admin to approve new
	// devices in the Tailscale console. This is NOT recoverable by
	// the end user clicking Re-authorize in Stacked, so we surface it
	// as its own status.
	raw := []byte(`{"BackendState": "NeedsMachineAuth"}`)
	got := parseTailscaleStatus(raw)
	if got == nil || got.Status != "needs_admin_approval" {
		t.Fatalf("got %+v, want status=needs_admin_approval", got)
	}
}

func TestParseTailscaleStatus_RunningWithoutIPsIsStarting(t *testing.T) {
	// Fleeting startup state — Running with no tailnet IPs yet. Should
	// map to "starting" so the server doesn't flap a device into
	// "connected" and back.
	raw := []byte(`{"BackendState": "Running"}`)
	got := parseTailscaleStatus(raw)
	if got == nil || got.Status != "starting" {
		t.Fatalf("got %+v, want status=starting", got)
	}
}

func TestParseTailscaleStatus_UnknownStateReturnsNil(t *testing.T) {
	raw := []byte(`{"BackendState": "FutureStateThatDoesntExist"}`)
	got := parseTailscaleStatus(raw)
	if got != nil {
		t.Errorf("expected nil for unknown BackendState, got %+v", got)
	}
}

func TestParseTailscaleStatus_GarbageReturnsNil(t *testing.T) {
	if parseTailscaleStatus([]byte("not json")) != nil {
		t.Error("expected nil for non-JSON input")
	}
}
