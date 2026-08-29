package executor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

func inspectLine(status string, running, restarting bool, networksJSON string) string {
	return fmt.Sprintf("%s\t%t\t%t\t%s", status, running, restarting, networksJSON)
}

func stackedNetworks(ip, ipv6 string) string {
	return fmt.Sprintf(`{"stacked":{"IPAddress":%q,"GlobalIPv6Address":%q}}`, ip, ipv6)
}

func TestParseInspectNetworkIPv4(t *testing.T) {
	info, err := parseInspectNetwork(inspectLine("running", true, false, stackedNetworks("172.18.0.9", "")), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if !info.OnNetwork || info.IP != "172.18.0.9" || !info.Running {
		t.Fatalf("got %+v", info)
	}
}

func TestParseInspectNetworkIPv6Fallback(t *testing.T) {
	info, err := parseInspectNetwork(inspectLine("running", true, false, stackedNetworks("", "fd00:dead::5")), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if !info.OnNetwork {
		t.Fatal("expected on stacked")
	}
	if info.IP != "fd00:dead::5" {
		t.Fatalf("got IP %q", info.IP)
	}
}

func TestParseInspectNetworkMissing(t *testing.T) {
	info, err := parseInspectNetwork(inspectLine("running", true, false, `{}`), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if info.OnNetwork || info.IP != "" {
		t.Fatalf("expected detached, got %+v", info)
	}
}

func TestParseInspectNetworkEmptyIP(t *testing.T) {
	info, err := parseInspectNetwork(inspectLine("running", true, false, stackedNetworks("", "")), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if !info.OnNetwork {
		t.Fatal("endpoint exists even without an address")
	}
	if info.IP != "" {
		t.Fatalf("expected empty IP, got %q", info.IP)
	}
}

func TestParseInspectNetworkPrefersIPv4(t *testing.T) {
	info, err := parseInspectNetwork(inspectLine("running", true, false, stackedNetworks("172.18.0.4", "fd00::4")), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "172.18.0.4" {
		t.Fatalf("got %q", info.IP)
	}
}

func TestParseInspectNetworkPicksStackedAmongMany(t *testing.T) {
	raw := `{"bridge":{"IPAddress":"172.17.0.2","GlobalIPv6Address":""},"stacked":{"IPAddress":"172.18.0.9","GlobalIPv6Address":""}}`
	info, err := parseInspectNetwork(inspectLine("running", true, false, raw), "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "172.18.0.9" {
		t.Fatalf("got %q", info.IP)
	}
}

func TestWaitForContainerIPRetriesUntilAssigned(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}

	n := 0
	dockerInspect = func(args ...string) (string, error) {
		n++
		if n < 3 {
			return inspectLine("running", true, false, stackedNetworks("", "")), nil
		}
		return inspectLine("running", true, false, stackedNetworks("172.18.0.12", "")), nil
	}

	ip, err := waitForContainerIP("svc-1", "stacked", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "172.18.0.12" {
		t.Fatalf("got %q", ip)
	}
	if n < 3 {
		t.Fatalf("expected retries, inspect called %d times", n)
	}
}

func TestWaitForContainerIPReconnectsWhenDetached(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}

	connects := 0
	dockerNetworkConnect = func(network, container string) error {
		if network != "stacked" || container != "svc-1" {
			t.Fatalf("connect %s %s", network, container)
		}
		connects++
		return nil
	}
	dockerInspect = func(args ...string) (string, error) {
		if connects == 0 {
			return inspectLine("running", true, false, `{}`), nil
		}
		return inspectLine("running", true, false, stackedNetworks("172.18.0.21", "")), nil
	}

	ip, err := waitForContainerIP("svc-1", "stacked", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "172.18.0.21" {
		t.Fatalf("got %q", ip)
	}
	if connects != 1 {
		t.Fatalf("expected one reconnect, got %d", connects)
	}
}

func TestIsTerminalIPError(t *testing.T) {
	if !isTerminalIPError(fmt.Errorf(`no IP on network "stacked" (status=exited)`)) {
		t.Fatal("exited should be terminal")
	}
	if isTerminalIPError(fmt.Errorf(`no IP on network "stacked" (status=restarting)`)) {
		t.Fatal("restarting should keep waiting")
	}
}

func TestWaitForContainerIPFailsFastWhenExited(t *testing.T) {
	restoreProbeHooks(t)
	slept := false
	sleep = func(time.Duration) { slept = true }
	dockerInspect = func(args ...string) (string, error) {
		return inspectLine("exited", false, false, `{}`), nil
	}

	_, err := waitForContainerIP("svc-1", "stacked", time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `no IP on network "stacked"`) || !strings.Contains(msg, "status=exited") {
		t.Fatalf("got %q", msg)
	}
	if slept {
		t.Fatal("exited containers should not consume the wait budget")
	}
}

func TestWaitForContainerIPTimesOutWhileRestarting(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}
	dockerInspect = func(args ...string) (string, error) {
		return inspectLine("restarting", false, true, `{}`), nil
	}

	_, err := waitForContainerIP("svc-1", "stacked", 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if !strings.Contains(err.Error(), "status=restarting") {
		t.Fatalf("got %q", err)
	}
}

func TestDockerNetworkConnectArgsAliasesRollingSlots(t *testing.T) {
	got := dockerNetworkConnectArgs("stacked", "svc-1-blue")
	want := []string{
		"network", "connect",
		"--alias", "svc-1-blue",
		"--alias", "svc-1",
		"stacked", "svc-1-blue",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v, want %v", got, want)
	}

	got = dockerNetworkConnectArgs("stacked", "abc-uuid")
	want = []string{"network", "connect", "--alias", "abc-uuid", "stacked", "abc-uuid"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("recreate args got %v, want %v", got, want)
	}
}

func TestWaitForContainerIPDoesNotReconnectWhenAlreadyAttached(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}

	dockerNetworkConnect = func(network, container string) error {
		t.Fatal("reconnect must not run when the endpoint already exists")
		return nil
	}
	n := 0
	dockerInspect = func(args ...string) (string, error) {
		n++
		if n == 1 {
			return inspectLine("running", true, false, stackedNetworks("", "")), nil
		}
		return inspectLine("running", true, false, stackedNetworks("172.18.0.30", "")), nil
	}

	ip, err := waitForContainerIP("svc-1", "stacked", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "172.18.0.30" {
		t.Fatalf("got %q", ip)
	}
}

func TestHealthGatePassesAfterIPAppears(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}

	n := 0
	dockerInspect = func(args ...string) (string, error) {
		n++
		if n < 2 {
			return inspectLine("running", true, false, stackedNetworks("", "")), nil
		}
		return inspectLine("running", true, false, stackedNetworks("172.18.0.9", "")), nil
	}
	origDial := dialTCP
	t.Cleanup(func() { dialTCP = origDial })
	dialTCP = func(addr string) error {
		if !strings.Contains(addr, "172.18.0.9") {
			return fmt.Errorf("wrong addr %s", addr)
		}
		return nil
	}

	if err := HealthGate(testStreamer(t), "svc-1", "stacked", 3000, "", time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestHealthGateFailsFastWhenExited(t *testing.T) {
	restoreProbeHooks(t)
	slept := 0
	sleep = func(time.Duration) { slept++ }
	dockerInspect = func(args ...string) (string, error) {
		return inspectLine("exited", false, false, `{}`), nil
	}

	err := HealthGate(testStreamer(t), "svc-1", "stacked", 3000, "", time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "status=exited") {
		t.Fatalf("got %q", err)
	}
	if slept != 0 {
		t.Fatalf("exited gate should return before probeRetryDelay, slept %d", slept)
	}
}

func TestWaitForContainerIPIgnoresAlreadyConnected(t *testing.T) {
	restoreProbeHooks(t)
	sleep = func(time.Duration) {}

	n := 0
	dockerNetworkConnect = func(network, container string) error {
		return fmt.Errorf("Error response from daemon: endpoint with name svc-1 already exists in network stacked")
	}
	dockerInspect = func(args ...string) (string, error) {
		n++
		if n == 1 {
			return inspectLine("running", true, false, `{}`), nil
		}
		return inspectLine("running", true, false, stackedNetworks("10.0.0.8", "")), nil
	}

	ip, err := waitForContainerIP("svc-1", "stacked", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "10.0.0.8" {
		t.Fatalf("got %q", ip)
	}
}

func restoreProbeHooks(t *testing.T) {
	t.Helper()
	origInspect := dockerInspect
	origSleep := sleep
	origConnect := dockerNetworkConnect
	origDelay := ipPollInterval
	origDial := dialTCP
	t.Cleanup(func() {
		dockerInspect = origInspect
		sleep = origSleep
		dockerNetworkConnect = origConnect
		ipPollInterval = origDelay
		dialTCP = origDial
	})
	ipPollInterval = time.Millisecond
}

func testStreamer(t *testing.T) *logs.Streamer {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return logs.NewStreamer(client.New(srv.URL, "test-token"), "op-1")
}
