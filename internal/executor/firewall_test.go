package executor

import (
	"strings"
	"testing"
)

func joined(args []string) string { return strings.Join(args, " ") }

func TestFirewallRulesMatchOriginalDestPort(t *testing.T) {
	tag := firewallTag("postgres-abc")

	allow := joined(allowRuleArgs(15432, "203.0.113.0/24", tag))
	// Must match the ORIGINAL (pre-DNAT) destination port via conntrack —
	// matching --dport would never fire in DOCKER-USER (post-DNAT).
	if !strings.Contains(allow, "--ctorigdstport 15432") {
		t.Errorf("allow rule must match ctorigdstport, got: %s", allow)
	}
	if strings.Contains(allow, "--dport") {
		t.Errorf("allow rule must NOT use --dport (post-DNAT mismatch): %s", allow)
	}
	if !strings.Contains(allow, "-s 203.0.113.0/24") {
		t.Errorf("allow rule must scope to the source CIDR: %s", allow)
	}
	if !strings.Contains(allow, "-j RETURN") {
		t.Errorf("allow rule must RETURN (accept), got: %s", allow)
	}
	if !strings.Contains(allow, "--comment "+tag) {
		t.Errorf("allow rule must carry the reconcile tag: %s", allow)
	}

	drop := joined(dropRuleArgs(15432, tag))
	if !strings.Contains(drop, "--ctorigdstport 15432") {
		t.Errorf("drop rule must match ctorigdstport, got: %s", drop)
	}
	// Only NEW connections are dropped so established/return traffic survives.
	if !strings.Contains(drop, "--ctstate NEW") {
		t.Errorf("drop rule must only drop NEW connections, got: %s", drop)
	}
	if !strings.Contains(drop, "-j DROP") {
		t.Errorf("drop rule must DROP, got: %s", drop)
	}
}

func TestFirewallTagIsPerContainer(t *testing.T) {
	if firewallTag("a") == firewallTag("b") {
		t.Fatal("firewall tag must be unique per container")
	}
	if !strings.HasPrefix(firewallTag("postgres-x"), "stacked-db:") {
		t.Fatal("firewall tag must be namespaced")
	}
}
