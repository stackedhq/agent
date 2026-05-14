package client

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// doJSON must NOT retry on 4xx responses — retrying 429s in particular
// pours more entries into the server's sliding-window rate limit and
// turns a transient burst into a self-sustaining lockout.
func TestDoJSON_DoesNotRetryOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "stk_test")
	_, err := c.doJSON("GET", "/api/agent/operations", nil)
	if err == nil {
		t.Fatal("expected error on 429, got nil")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 request (no retry on 4xx), got %d", got)
	}

	var httpErr *HTTPError
	if !asHTTPError(err, &httpErr) {
		t.Fatalf("expected *HTTPError, got %T: %v", err, err)
	}
	if httpErr.Status != http.StatusTooManyRequests {
		t.Fatalf("expected status 429, got %d", httpErr.Status)
	}
	if httpErr.RetryAfter != 7*time.Second {
		t.Fatalf("expected RetryAfter=7s, got %v", httpErr.RetryAfter)
	}
}

// 5xx still retries up to 3 times (existing behaviour preserved).
func TestDoJSON_RetriesOn5xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New(srv.URL, "stk_test")
	// Reduce default attempt backoff impact by using a short overall test
	// guard — doJSON sleeps attempt*1s, so 3 attempts ≈ 3s. Fine.
	_, _ = c.doJSON("GET", "/api/agent/heartbeat", nil)
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 attempts on 5xx, got %d", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"  ", 0},
		{"0", 0},
		{"5", 5 * time.Second},
		{"  12 ", 12 * time.Second},
		{"-3", 0},
		{"not-a-number", 0},
		// HTTP-date form intentionally unsupported.
		{"Wed, 21 Oct 2015 07:28:00 GMT", 0},
	}
	for _, tc := range cases {
		got := parseRetryAfter(tc.in)
		if got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Small helper kept local to the test so we don't import errors twice
// across test/prod files just for this single assertion.
func asHTTPError(err error, target **HTTPError) bool {
	for err != nil {
		if e, ok := err.(*HTTPError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
