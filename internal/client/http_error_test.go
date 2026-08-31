package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendBackoffHonoursRetryAfter(t *testing.T) {
	err := &HTTPError{StatusCode: http.StatusTooManyRequests, RetryAfter: 12 * time.Second}
	if got := SendBackoff(err); got != 12*time.Second {
		t.Fatalf("SendBackoff = %s, want 12s", got)
	}
}

func TestSendBackoffCapsAndDefaults(t *testing.T) {
	if got := SendBackoff(&HTTPError{StatusCode: 429}); got != 5*time.Second {
		t.Fatalf("default 429 backoff = %s, want 5s", got)
	}
	if got := SendBackoff(&HTTPError{StatusCode: 429, RetryAfter: time.Minute}); got != 30*time.Second {
		t.Fatalf("capped backoff = %s, want 30s", got)
	}
	if got := SendBackoff(&HTTPError{StatusCode: 500}); got != 0 {
		t.Fatalf("non-429 should not back off, got %s", got)
	}
	if got := SendBackoff(fmt.Errorf("network down")); got != 0 {
		t.Fatalf("plain error should not back off, got %s", got)
	}
}

func TestDoJSONDoesNotRetry429(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Retry-After", "5")
		http.Error(w, `{"code":"RATE_LIMITED"}`, http.StatusTooManyRequests)
	}))
	defer server.Close()

	err := New(server.URL, "stk_test").Heartbeat(&HeartbeatRequest{AgentVersion: "test"})
	if err == nil {
		t.Fatal("expected 429 error")
	}
	if hits != 1 {
		t.Fatalf("429 was retried %d times, want 1 request", hits)
	}
}

func TestDoRequestSurfaces429RetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "8")
		http.Error(w, `{"code":"RATE_LIMITED"}`, http.StatusTooManyRequests)
	}))
	defer server.Close()

	err := New(server.URL, "stk_test").SendServiceLogs("svc", []string{"line"})
	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("err type %T (%v), want *HTTPError", err, err)
	}
	if httpErr.StatusCode != 429 {
		t.Fatalf("status = %d", httpErr.StatusCode)
	}
	if httpErr.RetryAfter != 8*time.Second {
		t.Fatalf("RetryAfter = %s, want 8s", httpErr.RetryAfter)
	}
}
