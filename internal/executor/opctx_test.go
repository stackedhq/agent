package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

type statusRecorder struct {
	mu       sync.Mutex
	statuses []client.StatusUpdate
}

func (r *statusRecorder) all() []client.StatusUpdate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]client.StatusUpdate(nil), r.statuses...)
}

// fakeServer records status updates and serves a cron HTTP target that
// hangs until the request is cancelled.
func fakeServer(t *testing.T) (*httptest.Server, *statusRecorder, chan struct{}) {
	t.Helper()
	rec := &statusRecorder{}
	hangReturned := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/status"):
			var u client.StatusUpdate
			_ = json.NewDecoder(r.Body).Decode(&u)
			rec.mu.Lock()
			rec.statuses = append(rec.statuses, u)
			rec.mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/hang":
			select {
			case <-r.Context().Done():
			case <-time.After(30 * time.Second):
			}
			hangReturned <- struct{}{}
		case r.URL.Path == "/ok":
			_, _ = w.Write([]byte("fine"))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec, hangReturned
}

func TestExecuteWithTimeoutReportsFailureAndUnwinds(t *testing.T) {
	srv, rec, hangReturned := fakeServer(t)
	e := New(client.New(srv.URL, "tok"))
	op := client.Operation{ID: "op-1", Type: "cron_run", Payload: map[string]interface{}{
		"mode": "http", "httpUrl": srv.URL + "/hang",
	}}

	start := time.Now()
	e.ExecuteWithTimeout(op, 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("ExecuteWithTimeout took %s", elapsed)
	}
	select {
	case <-hangReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("handler's request was not cancelled by the op deadline")
	}

	statuses := rec.all()
	if len(statuses) != 2 {
		t.Fatalf("expected running + one terminal update, got %+v", statuses)
	}
	if statuses[0].Status != "running" || statuses[1].Status != "failed" {
		t.Fatalf("unexpected statuses %+v", statuses)
	}
	if statuses[1].Result["code"] != "OP_TIMEOUT" || !strings.Contains(statuses[1].Result["error"].(string), "timed out") {
		t.Fatalf("unexpected timeout result %+v", statuses[1].Result)
	}
	if currentOpContext().Err() != nil {
		t.Fatalf("op context not restored after the op")
	}
}

func TestExecuteWithTimeoutSuccessPath(t *testing.T) {
	srv, rec, _ := fakeServer(t)
	e := New(client.New(srv.URL, "tok"))
	op := client.Operation{ID: "op-2", Type: "cron_run", Payload: map[string]interface{}{
		"mode": "http", "httpUrl": srv.URL + "/ok",
	}}
	e.ExecuteWithTimeout(op, time.Minute)
	statuses := rec.all()
	if len(statuses) != 2 || statuses[1].Status != "success" {
		t.Fatalf("unexpected statuses %+v", statuses)
	}
}

func TestOpCommandKilledWhenContextExpires(t *testing.T) {
	ctxDone := make(chan struct{})
	go func() {
		defer close(ctxDone)
		// `sh` spawns a grandchild that holds stdout; the group kill must
		// take it down too or the reader would block.
		start := time.Now()
		restore := setOpContext(contextWithTimeout(t, 300*time.Millisecond))
		defer restore()
		_, _ = runCommandSilent("", "sh", "-c", "sleep 30 & sleep 30")
		if time.Since(start) > 10*time.Second {
			t.Errorf("command outlived the op deadline: %s", time.Since(start))
		}
	}()
	select {
	case <-ctxDone:
	case <-time.After(20 * time.Second):
		t.Fatal("runCommandSilent did not return after the deadline")
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// Cleanup must still run after the op deadline expired, and is bounded by
// its own timeout.
func TestCleanupCommandIgnoresExpiredOpContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restore := setOpContext(ctx)
	defer restore()

	if _, err := runCommandSilent("", "sh", "-c", "true"); err == nil {
		t.Fatal("op-bound command should fail under a cancelled op context")
	}
	out, err := cleanupCommand(cleanupTimeout, "sh", "-c", "echo cleaned")
	if err != nil || strings.TrimSpace(out) != "cleaned" {
		t.Fatalf("cleanupCommand = %q, %v", out, err)
	}

	start := time.Now()
	if _, err := cleanupCommand(200*time.Millisecond, "sleep", "10"); err == nil {
		t.Fatal("cleanupCommand should be killed at its own deadline")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cleanupCommand took %s past its deadline", elapsed)
	}
}

func TestStopCleanupTimeoutCoversGrace(t *testing.T) {
	if got := stopCleanupTimeout(10); got != 10*time.Second+cleanupTimeout {
		t.Fatalf("stopCleanupTimeout(10) = %s", got)
	}
	if got := stopCleanupTimeout(-5); got != cleanupTimeout {
		t.Fatalf("stopCleanupTimeout(-5) = %s", got)
	}
}

// A handler that never returns after its timeout makes the agent exit so
// systemd restarts it.
func TestWaitForHandlerWatchdogExits(t *testing.T) {
	prevLimit, prevExit := handlerStuckLimit, exitProcess
	t.Cleanup(func() { handlerStuckLimit, exitProcess = prevLimit, prevExit })
	handlerStuckLimit = 50 * time.Millisecond
	codes := make(chan int, 1)
	exitProcess = func(code int) { codes <- code }

	done := make(chan opOutcome) // never fires
	returned := make(chan struct{})
	go func() {
		waitForHandler(client.Operation{ID: "op-stuck", Type: "deploy"}, done)
		close(returned)
	}()
	select {
	case code := <-codes:
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not fire")
	}
	<-returned
}

func TestWaitForHandlerReturnsWhenHandlerFinishes(t *testing.T) {
	prevExit := exitProcess
	t.Cleanup(func() { exitProcess = prevExit })
	exitProcess = func(code int) { t.Errorf("unexpected exit(%d)", code) }

	done := make(chan opOutcome, 1)
	done <- opOutcome{}
	waitForHandler(client.Operation{ID: "op-ok", Type: "deploy"}, done)
}

// The startup reconcile runs under its own deadline and restores the
// previous op context afterwards.
func TestReconcileProxyWithTimeoutRestoresOpContext(t *testing.T) {
	before := currentOpContext()
	_ = ReconcileProxyWithTimeout(time.Minute)
	if currentOpContext() != before {
		t.Fatal("op context not restored")
	}
}
