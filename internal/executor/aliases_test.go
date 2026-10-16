package executor

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidNetworkAliasRejectsReserved(t *testing.T) {
	for _, a := range []string{
		"gate", "stacked-gate", "caddy", "proxy", "stacked", "localhost", "host", "docker",
		"host-docker-internal", "stk-db-abc", "stk-x", "stacked-anything",
		"3f2a1b4c-1d2e-4f5a-8b9c-0d1e2f3a4b5c",
	} {
		if validNetworkAlias(a) {
			t.Errorf("validNetworkAlias(%q) = true, want false", a)
		}
	}
	for _, a := range []string{"api", "web", "my-app", "gateway", "caddy2", "stk", "a"} {
		if !validNetworkAlias(a) {
			t.Errorf("validNetworkAlias(%q) = false, want true", a)
		}
	}
}

func withContainerNames(t *testing.T, fn func() (map[string]bool, error)) {
	t.Helper()
	orig := containerNamesFn
	t.Cleanup(func() { containerNamesFn = orig })
	containerNamesFn = fn
}

func TestResolveNetworkAliasesDropsExistingContainerNames(t *testing.T) {
	calls := 0
	withContainerNames(t, func() (map[string]bool, error) {
		calls++
		return map[string]bool{"postgres": true, "other-app-db-1": true}, nil
	})
	got, err := resolveNetworkAliases([]string{"api", "postgres", "gate", "other-app-db-1", "web", "Bad_Alias"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"api", "web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if calls != 1 {
		t.Fatalf("docker queried %d times, want 1", calls)
	}
}

func TestResolveNetworkAliasesSkipsDockerWhenEmpty(t *testing.T) {
	withContainerNames(t, func() (map[string]bool, error) {
		t.Fatal("docker should not be queried without aliases")
		return nil, nil
	})
	if got, err := resolveNetworkAliases(nil); err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestResolveNetworkAliasesFailsClosedOnDockerError(t *testing.T) {
	withContainerNames(t, func() (map[string]bool, error) { return nil, errors.New("daemon down") })
	if _, err := resolveNetworkAliases([]string{"api"}); err == nil || !strings.Contains(err.Error(), "daemon down") {
		t.Fatalf("expected docker error, got %v", err)
	}
}

func TestRenderersSkipReservedAliases(t *testing.T) {
	nets := renderYAML(yMap{{Key: "networks", Value: serviceNetworks([]string{"api", "stacked-gate", "caddy"})}})
	if strings.Contains(nets, "stacked-gate") || strings.Contains(nets, "caddy") || !strings.Contains(nets, `- "api"`) {
		t.Fatalf("compose networks:\n%s", nets)
	}
	args := rollingContainerArgs("svc-blue", "svc", "blue", "img", []string{"--env-file", "/env"}, resourceLimits{restartPolicy: "unless-stopped"}, []string{"api", "gate"}, "")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--network-alias=gate") || !strings.Contains(joined, "--network-alias=api") {
		t.Fatalf("docker run args: %s", joined)
	}
}
