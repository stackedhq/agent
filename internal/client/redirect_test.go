package client

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRestrictRedirectsSameOriginAllowed(t *testing.T) {
	from, _ := url.Parse("https://stacked.rest/api/agent/operations")
	to, _ := url.Parse("https://stacked.rest/api/agent/operations/v2")
	req := &http.Request{URL: to}
	via := []*http.Request{{URL: from}}
	if err := restrictRedirects(req, via); err != nil {
		t.Fatalf("same-origin redirect rejected: %v", err)
	}
}

func TestRestrictRedirectsRejectsCrossOrigin(t *testing.T) {
	from, _ := url.Parse("https://stacked.rest/api/agent/operations")
	cases := []string{
		"https://evil.example/api/agent/operations",
		"https://stacked.rest.evil.example/api/agent/operations",
		"https://api.stacked.rest/api/agent/operations",
		"https://stacked.rest:8443/api/agent/operations",
		"http://stacked.rest/api/agent/operations",
	}
	for _, raw := range cases {
		to, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		err = restrictRedirects(&http.Request{URL: to}, []*http.Request{{URL: from}})
		if err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

func TestRestrictRedirectsRejectsTLSDowngrade(t *testing.T) {
	from, _ := url.Parse("https://127.0.0.1:8443/api/agent/heartbeat")
	to, _ := url.Parse("http://127.0.0.1:8443/api/agent/heartbeat")
	err := restrictRedirects(&http.Request{URL: to}, []*http.Request{{URL: from}})
	if err == nil || !strings.Contains(err.Error(), "TLS downgrade") {
		t.Fatalf("got %v", err)
	}
}

func TestClientRefusesCrossOriginRedirect(t *testing.T) {
	var leakedAuth bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leakedAuth = true
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer evil.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/api/agent/heartbeat", http.StatusFound)
	}))
	defer origin.Close()

	err := New(origin.URL, "stk_secret").SendServiceLogs("svc", []string{"line"})
	if err == nil {
		t.Fatal("expected cross-origin redirect to fail")
	}
	if !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("error = %v", err)
	}
	if leakedAuth {
		t.Fatal("Authorization leaked to the redirect target")
	}
}

func TestClientFollowsSameOriginRedirect(t *testing.T) {
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/logs/svc" {
			http.Redirect(w, r, "/api/agent/logs/svc-ok", http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("Authorization") == "Bearer stk_secret" {
			sawAuth = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := New(server.URL, "stk_secret").SendServiceLogs("svc", []string{"line"}); err != nil {
		t.Fatal(err)
	}
	if !sawAuth {
		t.Fatal("same-origin follow dropped Authorization")
	}
}

func TestClientRefusesHTTPSToHTTPRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("downgrade target should not be reached")
	}))
	defer plain.Close()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/api/agent/logs/svc", http.StatusFound)
	}))
	defer tlsServer.Close()

	c := New(tlsServer.URL, "stk_secret")
	c.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err := c.SendServiceLogs("svc", []string{"line"})
	if err == nil {
		t.Fatal("expected TLS downgrade to fail")
	}
	if !strings.Contains(err.Error(), "TLS downgrade") && !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("error = %v", err)
	}
}
