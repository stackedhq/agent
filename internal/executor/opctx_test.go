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
