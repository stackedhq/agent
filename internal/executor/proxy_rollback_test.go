package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// proxyRollbackFixture fakes the gate (via withGateFakes: the fake gate
// "loads" whatever is in the config file unless refuse says otherwise)
// and Caddy (caddyErr), and redirects domains.json to a temp dir.
type proxyRollbackFixture struct {
	cfgPath     string
	domainsPath string
	signaled    *int
	// refuse makes the fake gate never report a load of configs that
	// mention this domain ("" = load everything).
	refuse string
	// caddyErr is returned by the fake Caddy step; caddyCalls counts it.
	caddyErr   error
	caddyCalls int
	// onCaddy runs inside the fake Caddy step (before it returns).
	onCaddy func()
}

func newProxyRollbackFixture(t *testing.T) *proxyRollbackFixture {
	t.Helper()
	f := &proxyRollbackFixture{}
	f.cfgPath, _, f.signaled = withGateFakes(t, func(written []byte) (gateStatus, error) {
		if f.refuse != "" && strings.Contains(string(written), f.refuse) {
			return gateStatus{Loaded: true, ConfigHash: "stale"}, nil
		}
		return gateStatus{Loaded: true, ConfigHash: hashOf(written)}, nil
	})
	f.domainsPath = filepath.Join(t.TempDir(), "domains.json")
	origEnsure, origCaddy, origDomains := ensureProxyFn, caddyApplyFn, domainsCachePath
	t.Cleanup(func() {
		ensureProxyFn, caddyApplyFn, domainsCachePath = origEnsure, origCaddy, origDomains
	})
	domainsCachePath = f.domainsPath
	ensureProxyFn = func() error { return nil }
	caddyApplyFn = func([]cachedDomain) error {
		f.caddyCalls++
		if f.onCaddy != nil {
			f.onCaddy()
		}
		return f.caddyErr
	}
	return f
}

func gatedPayload(domains ...string) client.Operation {
	rows := make([]interface{}, 0, len(domains))
	for _, d := range domains {
		rows = append(rows, map[string]interface{}{
			"domain": d, "serviceId": "svc", "port": float64(3000),
			"authGateMode": "password", "authGateUsername": "admin",
			"authGatePasswordHash": "$2a$10$" + strings.Repeat("a", 53),
		})
	}
	return client.Operation{ID: "op", Type: "proxy_config", Payload: map[string]interface{}{"domains": rows}}
}

// seedGate writes the "previous" gate config and returns its bytes.
func (f *proxyRollbackFixture) seedGate(t *testing.T, domains ...string) []byte {
	t.Helper()
	if err := applyGateConfig(buildGateConfig(parseDomains(gatedPayload(domains...).Payload["domains"].([]interface{})))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *proxyRollbackFixture) gateBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(f.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Caddy reload fails after the gate loaded the new config: the gate is
// put back to the old config (and seen to load it), Caddy keeps its old
// config, and domains.json isn't updated, so both end in the old state.
// The restore works even when the op deadline is what failed Caddy.
func TestProxyConfigRestoresGateWhenCaddyReloadFails(t *testing.T) {
	f := newProxyRollbackFixture(t)
	prev := f.seedGate(t, "old.example.com")
	*f.signaled = 0

	opCtx, cancel := context.WithCancel(context.Background())
	restore := setOpContext(opCtx)
	defer restore()
	f.caddyErr = errors.New("caddy reload: exit status 1")
	f.onCaddy = func() {
		if !strings.Contains(string(f.gateBytes(t)), "new.example.com") {
			t.Errorf("gate must know the new domains before Caddy reloads")
		}
		cancel() // the op deadline expires during the Caddy step
	}
	var restoreCtxErr error
	gateSignalFn = func() error {
		*f.signaled++
		restoreCtxErr = currentOpContext().Err()
		return nil
	}

	err := (&Executor{}).ProxyConfig(gatedPayload("new.example.com"))
	if err == nil || !strings.Contains(err.Error(), "caddy reload") {
		t.Fatalf("expected the caddy error, got %v", err)
	}
	if got := f.gateBytes(t); string(got) != string(prev) {
		t.Fatalf("gate config not restored:\n%s\nwant:\n%s", got, prev)
	}
	if *f.signaled != 2 {
		t.Fatalf("gate signaled %d times, want 2 (apply + restore)", *f.signaled)
	}
	if restoreCtxErr != nil {
		t.Fatalf("restore ran under the expired op context: %v", restoreCtxErr)
	}
	if _, err := os.Stat(f.domainsPath); !os.IsNotExist(err) {
		t.Fatalf("domains.json written for a config Caddy never ran: %v", err)
	}
}

// Caddy validate rejection takes the same path.
func TestProxyConfigRestoresGateWhenCaddyValidateFails(t *testing.T) {
	f := newProxyRollbackFixture(t)
	prev := f.seedGate(t, "old.example.com", "kept.example.com")
	f.caddyErr = errors.New("caddy validate rejected new config: exit status 1")
	if err := (&Executor{}).ProxyConfig(gatedPayload("kept.example.com", "new.example.com")); err == nil {
		t.Fatal("expected error")
	}
	if got := f.gateBytes(t); string(got) != string(prev) {
		t.Fatalf("gate config not restored:\n%s", got)
	}
}

// The gate write succeeded but the gate never loaded it: Caddy isn't
// touched and the old gate config is put back.
func TestProxyConfigRestoresGateWhenGateDoesNotLoad(t *testing.T) {
	f := newProxyRollbackFixture(t)
	prev := f.seedGate(t, "old.example.com")
	f.refuse = "new.example.com"
	err := (&Executor{}).ProxyConfig(gatedPayload("new.example.com"))
	if err == nil || !strings.Contains(err.Error(), "auth gate") {
		t.Fatalf("expected auth gate error, got %v", err)
	}
	if f.caddyCalls != 0 {
		t.Fatal("Caddy must not be reloaded when the gate didn't load")
	}
	if got := f.gateBytes(t); string(got) != string(prev) {
		t.Fatalf("gate config not restored:\n%s", got)
	}
}

// No gate config before the op: a failed op removes the new one again.
func TestProxyConfigRestoresMissingGateConfig(t *testing.T) {
	f := newProxyRollbackFixture(t)
	f.caddyErr = errors.New("caddy reload: boom")
	if err := (&Executor{}).ProxyConfig(gatedPayload("new.example.com")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(f.cfgPath); !os.IsNotExist(err) {
		t.Fatalf("gate config should be gone again: %v", err)
	}
}

// If the old config can't be put back, the error says so.
func TestProxyConfigReportsFailedGateRestore(t *testing.T) {
	f := newProxyRollbackFixture(t)
	f.seedGate(t, "old.example.com")
	f.refuse = "old.example.com"
	f.caddyErr = errors.New("caddy reload: boom")
	err := (&Executor{}).ProxyConfig(gatedPayload("new.example.com"))
	if err == nil || !strings.Contains(err.Error(), "caddy reload: boom") || !strings.Contains(err.Error(), "restoring the previous auth gate config also failed") {
		t.Fatalf("unexpected error %v", err)
	}
}

// Success keeps the new gate config and caches the domains.
func TestProxyConfigSuccessKeepsNewState(t *testing.T) {
	f := newProxyRollbackFixture(t)
	f.seedGate(t, "old.example.com")
	if err := (&Executor{}).ProxyConfig(gatedPayload("new.example.com")); err != nil {
		t.Fatal(err)
	}
	if got := string(f.gateBytes(t)); !strings.Contains(got, "new.example.com") || strings.Contains(got, "old.example.com") {
		t.Fatalf("gate config = %s", got)
	}
	cached, err := loadDomains()
	if err != nil || len(cached) != 1 || cached[0].Domain != "new.example.com" {
		t.Fatalf("domains cache = %+v, %v", cached, err)
	}
}
