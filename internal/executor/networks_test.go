package executor

import (
	"strings"
	"testing"
)

func TestNetworkPlanDefaultIsolation(t *testing.T) {
	plan := networkPlanFromPayload("svc-1", nil, []string{"api"})
	if plan.Isolation || plan.Primary != stackedNetwork {
		t.Fatalf("legacy payload must stay on shared stacked, got %+v", plan)
	}
	if len(plan.Attach) != 0 {
		t.Fatalf("shared plan attach = %v", plan.Attach)
	}
	if len(plan.Aliases) != 1 || plan.Aliases[0] != "api" {
		t.Fatalf("aliases = %v", plan.Aliases)
	}
}

func TestNetworkPlanOptInIsolation(t *testing.T) {
	plan := networkPlanFromPayload("svc-1", map[string]interface{}{"networkIsolation": true}, []string{"api"})
	if !plan.Isolation || plan.Primary != "stacked-svc-svc-1" {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.Attach) != 1 || plan.Attach[0] != stackedDataNetwork {
		t.Fatalf("compat data attach = %v", plan.Attach)
	}
}

func TestNetworkPlanSharedEscapeHatch(t *testing.T) {
	for _, payload := range []map[string]interface{}{
		{"networkIsolation": false},
		{"isolationRelaxed": true},
	} {
		plan := networkPlanFromPayload("svc-1", payload, nil)
		if plan.Isolation || plan.Primary != stackedNetwork || len(plan.Attach) != 0 {
			t.Fatalf("payload %+v => %+v", payload, plan)
		}
	}
}

func TestNetworkPlanExplicitLinks(t *testing.T) {
	plan := networkPlanFromPayload("svc-1", map[string]interface{}{
		"linkedServiceIds":  []interface{}{"svc-2", "svc-1"},
		"linkedDatabaseIds": []interface{}{"db-9"},
	}, nil)
	if plan.Primary != "stacked-svc-svc-1" {
		t.Fatalf("primary = %s", plan.Primary)
	}
	joined := strings.Join(plan.Attach, ",")
	if !strings.Contains(joined, "stacked-svc-svc-2") || !strings.Contains(joined, "stacked-db-db-9") {
		t.Fatalf("links = %v", plan.Attach)
	}
	if strings.Contains(joined, stackedDataNetwork) {
		t.Fatalf("explicit DB links must skip the shared data plane: %v", plan.Attach)
	}
	if strings.Contains(joined, "stacked-svc-svc-1") {
		t.Fatalf("must not self-link: %v", plan.Attach)
	}
}

func TestNetworkPlanEmptyExplicitDBLinks(t *testing.T) {
	plan := networkPlanFromPayload("svc-1", map[string]interface{}{
		"linkedDatabaseIds": []interface{}{},
	}, nil)
	for _, n := range plan.Attach {
		if n == stackedDataNetwork {
			t.Fatalf("empty linkedDatabaseIds must not join stacked-data: %+v", plan)
		}
	}
}

func TestRenderComposeSharedVsIsolated(t *testing.T) {
	shared := renderComposeServiceNetworks(sharedNetworkPlan(nil))
	if shared != "    networks:\n      - stacked\n" {
		t.Fatalf("shared list form = %q", shared)
	}

	isolated := networkPlanFromPayload("svc-1", map[string]interface{}{
		"linkedDatabaseIds": []interface{}{"db-1"},
	}, []string{"api"})
	out := renderComposeServiceNetworks(isolated)
	if !strings.Contains(out, "stacked-svc-svc-1:") || !strings.Contains(out, "aliases:") || !strings.Contains(out, "- api") {
		t.Fatalf("isolated aliases:\n%s", out)
	}
	if !strings.Contains(out, "stacked-db-db-1: {}") {
		t.Fatalf("linked db net:\n%s", out)
	}
}

func TestRollingAndComposeNetworkEquivalent(t *testing.T) {
	payload := map[string]interface{}{
		"linkedServiceIds":  []interface{}{"other"},
		"linkedDatabaseIds": []interface{}{"db-1"},
		"capAdd":            []interface{}{"NET_BIND_SERVICE"},
	}
	iso := isolationFromPayload(payload)
	nets := networkPlanFromPayload("svc-1", payload, []string{"api"})

	compose := generateCompose("svc-1", "img", nil, resourceLimits{restartPolicy: "unless-stopped"}, iso, nets, "")
	args := rollingContainerArgs("svc-1-blue", "svc-1", "blue", "img", "/env", resourceLimits{restartPolicy: "unless-stopped"}, iso, nets, "")

	if !strings.Contains(compose, "stacked-svc-svc-1") || !containsFlag(args, "--network=stacked-svc-svc-1") {
		t.Fatalf("primary network mismatch\ncompose:\n%s\nargs: %v", compose, args)
	}
	if !strings.Contains(compose, "- api") && !strings.Contains(compose, `- "api"`) {
		t.Fatalf("alias missing in compose:\n%s", compose)
	}
	if !containsFlag(args, "--network-alias=api") {
		t.Fatalf("alias mismatch\ncompose:\n%s\nargs: %v", compose, args)
	}
	if !strings.Contains(compose, "no-new-privileges:true") || !containsFlag(args, "--security-opt=no-new-privileges:true") {
		t.Fatalf("nnp mismatch")
	}
	if !strings.Contains(compose, `- "NET_BIND_SERVICE"`) || !containsFlag(args, "--cap-add=NET_BIND_SERVICE") {
		t.Fatalf("capAdd mismatch\ncompose:\n%s\nargs: %v", compose, args)
	}
	if !strings.Contains(compose, "stacked-svc-other") || !strings.Contains(compose, "stacked-db-db-1") {
		t.Fatalf("compose missing links:\n%s", compose)
	}
	// Rolling attaches extra nets after `docker run`; they live on the plan.
	joined := strings.Join(nets.Attach, ",")
	if !strings.Contains(joined, "stacked-svc-other") || !strings.Contains(joined, "stacked-db-db-1") {
		t.Fatalf("rolling attach plan = %v", nets.Attach)
	}
}
