package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeCaddyDocker struct {
	anyID     string
	runningID string
	networks  map[string][]string // container -> networks
	connected []string
	failNet   string
}

func withCaddyNetworkFakes(t *testing.T) *fakeCaddyDocker {
	t.Helper()
	f := &fakeCaddyDocker{networks: map[string][]string{}}
	origPath := caddyNetworksPath
	origAny, origRun, origInspect, origConnect := caddyContainerAnyFn, caddyRunningIDFn, inspectNetworksFn, connectCaddyNetworkFn
	t.Cleanup(func() {
		caddyNetworksPath = origPath
		caddyContainerAnyFn, caddyRunningIDFn, inspectNetworksFn, connectCaddyNetworkFn = origAny, origRun, origInspect, origConnect
	})
	caddyNetworksPath = filepath.Join(t.TempDir(), "proxy", "caddy-networks.json")
	caddyContainerAnyFn = func() (string, error) { return f.anyID, nil }
	caddyRunningIDFn = func() (string, error) {
		if f.runningID == "" {
			return "", fmt.Errorf("not running")
		}
		return f.runningID, nil
	}
	inspectNetworksFn = func(id string) ([]string, error) { return f.networks[id], nil }
	connectCaddyNetworkFn = func(network, container string) error {
		if network == f.failNet {
			return fmt.Errorf("network %s not found", network)
		}
		f.connected = append(f.connected, network+"@"+container)
		return nil
	}
	return f
}

func TestCaddyNetworksRememberForget(t *testing.T) {
	withCaddyNetworkFakes(t)
	for _, n := range []string{"dokploy-network", "dokploy-network", "other_net", "stacked", gateNetworkName, "bad name"} {
		if err := rememberCaddyNetwork(n); err != nil {
			t.Fatal(err)
		}
	}
	got, err := loadCaddyNetworks()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dokploy-network", "other_net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("networks = %v, want %v", got, want)
	}
	info, err := os.Stat(caddyNetworksPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode: %v %v", info, err)
	}
	if err := forgetCaddyNetwork("dokploy-network"); err != nil {
		t.Fatal(err)
	}
	if err := forgetCaddyNetwork("never-attached"); err != nil {
		t.Fatal(err)
	}
	got, _ = loadCaddyNetworks()
	if want := []string{"other_net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after forget = %v, want %v", got, want)
	}
}

// Machines that attached a network before the state file existed: the
// pre-`compose up` inspect records it, and the post-up reconnect
// re-attaches it to the recreated container.
func TestCaddyNetworksMigrateAndReconnectAcrossRecreate(t *testing.T) {
	f := withCaddyNetworkFakes(t)
	f.anyID = "old-caddy"
	f.networks["old-caddy"] = []string{"stacked", gateNetworkName, "proxy_default", "dokploy-network"}

	if err := recordCaddyRuntimeNetworks(); err != nil {
		t.Fatal(err)
	}
	got, _ := loadCaddyNetworks()
	if want := []string{"dokploy-network"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recorded %v, want %v", got, want)
	}

	// compose up recreated Caddy with only its compose networks.
	f.runningID = "new-caddy"
	if err := reconnectCaddyNetworks(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"dokploy-network@new-caddy"}; !reflect.DeepEqual(f.connected, want) {
		t.Fatalf("connected %v, want %v", f.connected, want)
	}
}

func TestCaddyNetworksNoContainerOrStateIsNoop(t *testing.T) {
	f := withCaddyNetworkFakes(t)
	if err := recordCaddyRuntimeNetworks(); err != nil {
		t.Fatal(err)
	}
	if err := reconnectCaddyNetworks(); err != nil {
		t.Fatal(err)
	}
	if len(f.connected) != 0 {
		t.Fatalf("unexpected connects: %v", f.connected)
	}
	if _, err := os.Stat(caddyNetworksPath); !os.IsNotExist(err) {
		t.Fatalf("state file must not be created without runtime networks: %v", err)
	}
}

func TestCaddyNetworksReconnectReportsMissingNetworkAndKeepsIt(t *testing.T) {
	f := withCaddyNetworkFakes(t)
	_ = rememberCaddyNetwork("gone-net")
	_ = rememberCaddyNetwork("live-net")
	f.runningID = "caddy"
	f.failNet = "gone-net"
	err := reconnectCaddyNetworks()
	if err == nil || !strings.Contains(err.Error(), "gone-net") {
		t.Fatalf("expected error naming gone-net, got %v", err)
	}
	if want := []string{"live-net@caddy"}; !reflect.DeepEqual(f.connected, want) {
		t.Fatalf("connected %v, want %v", f.connected, want)
	}
	got, _ := loadCaddyNetworks()
	if len(got) != 2 {
		t.Fatalf("missing network must stay recorded: %v", got)
	}
}

// TestDockerCaddyNetworkHelpers exercises the real inspect/connect
// helpers against a throwaway container and network.
func TestDockerCaddyNetworkHelpers(t *testing.T) {
	requireDocker(t)
	sfx := randSuffix(t)
	netName := "stk-test-net-" + sfx
	ctr := "stk-test-caddy-" + sfx
	dockerOut(t, "", nil, "network", "create", netName)
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", netName).Run() })
	dockerOut(t, "", nil, "run", "-d", "--name", ctr, CaddyImage, "sleep", "300")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", ctr).Run() })

	if err := connectNetwork(netName, ctr); err != nil {
		t.Fatal(err)
	}
	if err := connectNetwork(netName, ctr); err != nil {
		t.Fatalf("second connect must be idempotent: %v", err)
	}
	nets, err := inspectContainerNetworks(ctr)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range nets {
		if n == netName {
			found = true
		}
	}
	if !found {
		t.Fatalf("networks %v missing %s", nets, netName)
	}
}
