package executor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func TestValidateHTTPJobURLScheme(t *testing.T) {
	policy := httpJobPolicy{AllowPrivate: true}
	cases := []struct {
		raw  string
		want string
	}{
		{"ftp://example.com/", "scheme"},
		{"file:///etc/passwd", "scheme"},
		{"gopher://example.com/", "scheme"},
		{"javascript:alert(1)", "scheme"},
		{"http://", "missing host"},
		{"https://example.com/ok", ""},
		{"http://example.com/ok", ""},
	}
	for _, c := range cases {
		err := validateHTTPJobURL(c.raw, policy)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected %v", c.raw, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want substring %q", c.raw, err, c.want)
		}
	}
}

func TestClassifyAndValidateLiteralBypasses(t *testing.T) {
	denyAll := httpJobPolicy{}
	allowPriv := httpJobPolicy{AllowPrivate: true}
	allowLB := httpJobPolicy{AllowLoopback: true}

	blocked := []string{
		"http://169.254.169.254/",
		"http://169.254.169.254./",
		"http://[::ffff:169.254.169.254]/",
		"http://[::ffff:a9fe:a9fe]/",
		"http://[fd00:ec2::254]/",
		"http://100.100.100.200/",
		"http://metadata.google.internal/",
		"http://METADATA.google.internal./",
		"http://metadata/",
		"http://0.0.0.0/",
		"http://[::]/",
		"http://224.0.0.1/",
		"http://[ff02::1]/",
		"http://255.255.255.255/",
		"http://240.0.0.1/",
		"http://0xA9.0xFE.0xA9.0xFE/",
		"http://0251.0376.0251.0376/",
		"http://2852039166/",
		"http://[2002:a9fe:a9fe::1]/",
		"http://[64:ff9b::169.254.169.254]/",
		"http://[fe80::1]/",
	}
	for _, raw := range blocked {
		if err := validateHTTPJobURL(raw, httpJobPolicy{AllowPrivate: true, AllowLoopback: true}); err == nil {
			t.Errorf("expected block for %s", raw)
		}
	}

	loopback := []string{
		"http://127.0.0.1/",
		"http://127.1/",
		"http://2130706433/",
		"http://0x7f000001/",
		"http://[::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://localhost/",
	}
	for _, raw := range loopback {
		if raw == "http://localhost/" {
			// hostname is not a literal; validate only catches metadata names
			if err := validateHTTPJobURL(raw, denyAll); err != nil {
				t.Errorf("localhost hostname should pass pre-resolve check: %v", err)
			}
			continue
		}
		if err := validateHTTPJobURL(raw, denyAll); err == nil {
			t.Errorf("loopback should be denied by default: %s", raw)
		}
		if err := validateHTTPJobURL(raw, allowLB); err != nil {
			t.Errorf("loopback should be allowed with flag: %s: %v", raw, err)
		}
	}

	private := []string{
		"http://10.0.0.4/api",
		"http://192.168.1.9/",
		"http://172.18.0.5/",
		"http://100.64.1.2/", // Tailscale
		"http://[fd00:dead::5]/",
	}
	for _, raw := range private {
		if err := validateHTTPJobURL(raw, denyAll); err == nil {
			t.Errorf("private should require flag: %s", raw)
		}
		if err := validateHTTPJobURL(raw, allowPriv); err != nil {
			t.Errorf("private should be allowed with flag: %s: %v", raw, err)
		}
	}

	if err := validateHTTPJobURL("http://8.8.8.8/", denyAll); err != nil {
		t.Fatalf("public literal: %v", err)
	}
}

func TestHTTPJobPolicyFromPayload(t *testing.T) {
	p := httpJobPolicyFromPayload(nil)
	if !p.AllowPrivate || p.AllowLoopback {
		t.Fatalf("defaults: %+v", p)
	}
	p = httpJobPolicyFromPayload(map[string]interface{}{
		"httpAllowPrivate":  false,
		"httpAllowLoopback": true,
	})
	if p.AllowPrivate || !p.AllowLoopback {
		t.Fatalf("bool payload: %+v", p)
	}
	p = httpJobPolicyFromPayload(map[string]interface{}{
		"httpAllowPrivate":  "false",
		"httpAllowLoopback": "yes",
	})
	if p.AllowPrivate || !p.AllowLoopback {
		t.Fatalf("string payload: %+v", p)
	}
}

type mapResolver map[string][]net.IP

func (m mapResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := m[strings.ToLower(host)]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

func TestDialResolvesAndPins(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer okSrv.Close()
	okURL, _ := url.Parse(okSrv.URL)

	res := mapResolver{
		"good.example": {net.ParseIP("127.0.0.1")},
		"meta.example": {net.ParseIP("169.254.169.254")},
		"mixed.example": {
			net.ParseIP("169.254.169.254"),
			net.ParseIP("127.0.0.1"),
		},
		"v6meta.example": {net.ParseIP("::ffff:169.254.169.254")},
	}
	client := newHTTPJobClientWithResolver(httpJobPolicy{AllowLoopback: true}, res)

	req, err := http.NewRequest(http.MethodGet, "http://good.example:"+okURL.Port()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("good.example: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, "http://meta.example/", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected metadata DNS name to be blocked")
	}

	req, _ = http.NewRequest(http.MethodGet, "http://v6meta.example/", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected IPv6-mapped metadata to be blocked")
	}

	deny := newHTTPJobClientWithResolver(httpJobPolicy{}, res)
	req, _ = http.NewRequest(http.MethodGet, "http://good.example:"+okURL.Port()+"/", nil)
	if _, err := deny.Do(req); err == nil {
		t.Fatal("DNS name resolving to loopback must be blocked without httpAllowLoopback")
	}

	// Mixed records: skip blocked, pin the allowed loopback IP.
	req, _ = http.NewRequest(http.MethodGet, "http://mixed.example:"+okURL.Port()+"/", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("mixed.example should dial the allowed A record: %v", err)
	}
	resp.Body.Close()
}

func TestRedirectRevalidated(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer final.Close()

	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-meta":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
		case "/to-private":
			http.Redirect(w, r, "http://10.0.0.1/", http.StatusFound)
		case "/to-encoded":
			http.Redirect(w, r, "http://0xA9.0xFE.0xA9.0xFE/", http.StatusFound)
		case "/ok":
			http.Redirect(w, r, final.URL, http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer hop.Close()

	allowLB := newHTTPJobClient(httpJobPolicy{AllowLoopback: true, AllowPrivate: true})
	denyPriv := newHTTPJobClient(httpJobPolicy{AllowLoopback: true, AllowPrivate: false})

	resp, err := allowLB.Get(hop.URL + "/ok")
	if err != nil {
		t.Fatalf("allowed redirect: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}

	if _, err := allowLB.Get(hop.URL + "/to-meta"); err == nil {
		t.Fatal("redirect to metadata must fail")
	}
	if _, err := allowLB.Get(hop.URL + "/to-encoded"); err == nil {
		t.Fatal("encoded metadata redirect must fail")
	}
	if _, err := denyPriv.Get(hop.URL + "/to-private"); err == nil {
		t.Fatal("redirect to RFC1918 must fail without httpAllowPrivate")
	}
}

func TestRedirectCap(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/?n="+r.URL.Query().Get("n")+"x", http.StatusFound)
	}))
	defer srv.Close()

	client := newHTTPJobClient(httpJobPolicy{AllowLoopback: true})
	_, err := client.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("want redirect cap, got %v", err)
	}
}

func TestHTTPJobTimeoutAndCaps(t *testing.T) {
	if httpJobTimeout != 60*time.Second {
		t.Fatalf("timeout cap %s", httpJobTimeout)
	}
	if httpJobMaxRedirects != 5 {
		t.Fatalf("redirect cap %d", httpJobMaxRedirects)
	}
	if httpJobMaxResponseBytes != 4096 {
		t.Fatalf("response cap %d", httpJobMaxResponseBytes)
	}
}

func TestRunHTTPJobUsesPolicy(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(200)
		io.WriteString(w, "pong")
	}))
	defer srv.Close()

	logSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer logSrv.Close()

	e := &Executor{Client: newTestAPIClient(logSrv.URL)}
	result, err := e.RunJob(clientOp("http", map[string]interface{}{
		"httpUrl":           srv.URL + "/cron",
		"httpMethod":        "POST",
		"httpAllowLoopback": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result["exitCode"] != 0 {
		t.Fatalf("result %+v", result)
	}
	if gotPath != "/cron" {
		t.Fatalf("path %q", gotPath)
	}

	_, err = e.RunJob(clientOp("http", map[string]interface{}{
		"httpUrl": "http://169.254.169.254/latest/meta-data",
	}))
	if err == nil {
		t.Fatal("metadata job must fail")
	}
}

func clientOp(mode string, extra map[string]interface{}) client.Operation {
	p := map[string]interface{}{"mode": mode}
	for k, v := range extra {
		p[k] = v
	}
	return client.Operation{ID: "op-test", Type: "cron_run", Payload: p}
}

func newTestAPIClient(server string) *client.Client {
	return client.New(server, "tok")
}
