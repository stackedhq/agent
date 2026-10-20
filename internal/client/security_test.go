package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidateServerURL(t *testing.T) {
	ok := []string{
		"https://stacked.rest",
		"https://stacked.rest/",
		"https://example.com:8443/prefix",
		"http://localhost:3000",
		"http://LOCALHOST:3000",
		"http://127.0.0.1:3000",
		"http://[::1]:3000",
	}
	for _, u := range ok {
		if err := ValidateServerURL(u); err != nil {
			t.Errorf("ValidateServerURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{
		"http://stacked.rest",
		"http://10.0.0.5:3000",
		"http://127.0.0.2:3000",
		"http://localhost.evil.com",
		"ftp://stacked.rest",
		"stacked.rest",
		"https://",
		"https://user:pass@stacked.rest",
		"https://stacked.rest?x=1",
		"",
	}
	for _, u := range bad {
		if err := ValidateServerURL(u); err == nil {
			t.Errorf("ValidateServerURL(%q) = nil, want error", u)
		}
	}
}

func TestClientRefusesInsecureServer(t *testing.T) {
	_, err := New("http://stacked.example", "stk_x").doRequest("POST", "/api/agent/heartbeat", nil)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("err = %v, want https requirement", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, err := New(server.URL, "stk_x").doRequest("GET", "/api/agent/operations", nil)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want redirect error", err)
	}
	if leaked {
		t.Fatal("client followed the redirect")
	}
}

// newTLSClient returns a client for srv that trusts its test certificate.
func newTLSClient(srv *httptest.Server, server string) *Client {
	c := New(server, "stk_x")
	c.httpClient.Transport = srv.Client().Transport
	return c
}

func TestClientFollowsSameOriginHTTPSRedirects(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/operations":
			http.Redirect(w, r, "/v2/api/agent/operations", http.StatusPermanentRedirect)
		case "/v2/api/agent/operations":
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	body, err := newTLSClient(srv, srv.URL).doRequest("GET", "/api/agent/operations", nil)
	if err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if string(body) != "[]" || gotAuth != "Bearer stk_x" {
		t.Fatalf("body %q auth %q", body, gotAuth)
	}
}

func TestClientStopsAfterThreeRedirects(t *testing.T) {
	hops := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, fmt.Sprintf("/hop%d", hops), http.StatusFound)
	}))
	defer srv.Close()
	_, err := newTLSClient(srv, srv.URL).doRequest("GET", "/api/agent/operations", nil)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want redirect error", err)
	}
	if hops != 4 {
		t.Fatalf("server saw %d requests, want 4 (original + 3 followed redirects)", hops)
	}
}

func TestClientRefusesCrossOriginOrHTTPRedirects(t *testing.T) {
	var leaked bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer other.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer plain.Close()

	var target string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	for _, tc := range []struct{ name, target string }{
		{"other port", other.URL + "/x"},
		{"other host name", "https://localhost:" + u.Port() + "/x"},
		{"downgrade to http", "http://" + u.Host + "/x"},
		{"plain http server", plain.URL + "/x"},
	} {
		target = tc.target
		_, err := newTLSClient(srv, srv.URL).doRequest("GET", "/api/agent/operations", nil)
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("%s: err = %v, want redirect error", tc.name, err)
		}
	}
	if leaked {
		t.Fatal("client followed a cross-origin or http redirect")
	}
}

func TestClientCapsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxDefaultResponseBytes+1)))
	}))
	defer server.Close()

	c := New(server.URL, "stk_x")
	if _, err := c.doRequest("POST", "/api/agent/heartbeat", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want size cap error", err)
	}
	// The ops poll has a larger budget, so the same body is accepted there.
	if _, err := c.doRequest("GET", "/api/agent/operations", nil); err != nil {
		t.Fatalf("ops poll: %v", err)
	}
}

func TestResponseLimit(t *testing.T) {
	cases := map[string]int64{
		"/api/agent/operations":                  maxOpsResponseBytes,
		"/api/agent/operations/op-1/file-mounts": maxSecretsResponseBytes,
		"/api/agent/credentials/svc":             maxSecretsResponseBytes,
		"/api/agent/operations/op-1/status":      maxDefaultResponseBytes,
		"/api/agent/heartbeat":                   maxDefaultResponseBytes,
	}
	for path, want := range cases {
		if got := responseLimit(path); got != want {
			t.Errorf("responseLimit(%q) = %d, want %d", path, got, want)
		}
	}
}
