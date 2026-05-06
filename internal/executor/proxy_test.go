package executor

import (
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/slots"
)

func TestGenerateCaddyfileNoSlotState(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{})
	if !strings.Contains(out, "reverse_proxy svc-1:3000") {
		t.Fatalf("expected legacy upstream svc-1:3000, got:\n%s", out)
	}
	if strings.Contains(out, "svc-1-blue") || strings.Contains(out, "svc-1-green") {
		t.Fatalf("did not expect slot-suffixed upstream, got:\n%s", out)
	}
}

func TestGenerateCaddyfileBlueActive(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Blue})
	if !strings.Contains(out, "reverse_proxy svc-1-blue:3000") {
		t.Fatalf("expected upstream svc-1-blue:3000, got:\n%s", out)
	}
}

func TestGenerateCaddyfileLegacyKeepsBareName(t *testing.T) {
	// During the first rolling deploy of a service migrating off
	// recreate, state momentarily reads `legacy` — the upstream must
	// still resolve to the bare serviceID until the flip writes a
	// real slot.
	parsed := []cachedDomain{
		{Domain: "app.example.com", ServiceID: "svc-1", Port: 3000},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-1": slots.Legacy})
	if !strings.Contains(out, "reverse_proxy svc-1:3000") {
		t.Fatalf("expected legacy upstream svc-1:3000, got:\n%s", out)
	}
}

func TestGenerateCaddyfileMixedRecreateAndRolling(t *testing.T) {
	parsed := []cachedDomain{
		{Domain: "a.example.com", ServiceID: "svc-rec", Port: 3000},
		{Domain: "b.example.com", ServiceID: "svc-roll", Port: 8080},
	}
	out := generateCaddyfile(parsed, map[string]slots.Slot{"svc-roll": slots.Green})
	if !strings.Contains(out, "reverse_proxy svc-rec:3000") {
		t.Fatalf("recreate service should keep bare upstream, got:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy svc-roll-green:8080") {
		t.Fatalf("rolling service should use slot upstream, got:\n%s", out)
	}
}

func TestGetIntPayloadOrFallback(t *testing.T) {
	cases := []struct {
		name     string
		payload  map[string]interface{}
		key      string
		fallback int
		want     int
	}{
		{"missing key", map[string]interface{}{}, "k", 60, 60},
		{"nil value", map[string]interface{}{"k": nil}, "k", 60, 60},
		{"zero float (treated as unset)", map[string]interface{}{"k": float64(0)}, "k", 60, 60},
		{"positive float", map[string]interface{}{"k": float64(42)}, "k", 60, 42},
		{"int", map[string]interface{}{"k": 7}, "k", 60, 7},
		{"wrong type", map[string]interface{}{"k": "thirty"}, "k", 60, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := getIntPayloadOr(c.payload, c.key, c.fallback); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}
