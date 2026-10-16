package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const testDomain = "app.example.com"

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func writeConfig(t *testing.T, path string, domains map[string]DomainGate) {
	t.Helper()
	data, err := json.Marshal(GateConfig{Domains: domains})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	srv  *Server
	h    http.Handler
	path string
	gate DomainGate
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	g := DomainGate{Mode: "password", Username: "admin", PasswordHash: mustHash(t, "hunter22"), ServiceName: "acme-api"}
	writeConfig(t, path, map[string]DomainGate{testDomain: g})
	s := NewServer(path, []byte("0123456789abcdef0123456789abcdef"))
	s.Reload()
	return &fixture{srv: s, h: s.Handler(), path: path, gate: g}
}

func (f *fixture) do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func checkReq(host, domainHeader string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Host = host
	if domainHeader != "" {
		req.Header.Set(DomainHeader, domainHeader)
	}
	req.Header.Set("X-Original-URI", "/dashboard?tab=1")
	return req
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"APP.Example.COM":       "app.example.com",
		"app.example.com.":      "app.example.com",
		"App.Example.com.:443":  "app.example.com",
		"app.example.com:8080":  "app.example.com",
		"[2001:DB8::1]:443":     "2001:db8::1",
		"[::1]":                 "::1",
		"  app.example.com  ":   "app.example.com",
		"[broken":               "",
		"app.example.com:":      "app.example.com",
		"192.168.1.1:80":        "192.168.1.1",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckHostVariantsGetLoginRedirect(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{"app.example.com", "APP.EXAMPLE.COM", "app.example.com.", "App.Example.Com.:443"} {
		rec := f.do(t, checkReq(host, ""))
		if rec.Code != http.StatusFound {
			t.Fatalf("host %q: status %d, want 302", host, rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/__stacked/login?rd=") {
			t.Fatalf("host %q: Location %q", host, loc)
		}
		u, _ := url.Parse(loc)
		if rd := u.Query().Get("rd"); rd != "/dashboard?tab=1" {
			t.Fatalf("rd = %q (Location %q): X-Original-URI must be URL-encoded", rd, loc)
		}
	}
}

func TestCheckDomainHeaderWinsOverHost(t *testing.T) {
	f := newFixture(t)
	// Header names a gated domain; Host is something else entirely.
	rec := f.do(t, checkReq("other.example.com", testDomain))
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", rec.Code)
	}
	// Header names an unknown domain; Host would have matched. Deny.
	rec = f.do(t, checkReq(testDomain, "unknown.example.com"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestCheckUnknownDomainDenied(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, checkReq("unknown.example.com", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	rec = f.do(t, checkReq("", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty host: status %d, want 403", rec.Code)
	}
}

func TestCheckDeniesWhenConfigMissingOrInvalid(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(t, checkReq(testDomain, testDomain)); rec.Code != http.StatusFound {
		t.Fatalf("precondition: status %d", rec.Code)
	}

	// Corrupt config: deny all (previously loaded config must not linger).
	if err := os.WriteFile(f.path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.srv.Reload()
	if rec := f.do(t, checkReq(testDomain, testDomain)); rec.Code != http.StatusForbidden {
		t.Fatalf("invalid config: status %d, want 403", rec.Code)
	}

	// Missing config: deny all.
	_ = os.Remove(f.path)
	f.srv.Reload()
	if rec := f.do(t, checkReq(testDomain, testDomain)); rec.Code != http.StatusForbidden {
		t.Fatalf("missing config: status %d, want 403", rec.Code)
	}

	// Valid config again: back to normal.
	writeConfig(t, f.path, map[string]DomainGate{testDomain: f.gate})
	f.srv.Reload()
	if rec := f.do(t, checkReq(testDomain, testDomain)); rec.Code != http.StatusFound {
		t.Fatalf("restored config: status %d, want 302", rec.Code)
	}
}

func TestServerStartsDenyAll(t *testing.T) {
	s := NewServer(filepath.Join(t.TempDir(), "absent.json"), []byte("k"))
	s.Reload()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, checkReq(testDomain, testDomain))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestInvalidEntriesAreDenied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, map[string]DomainGate{
		"nomode.example.com":  {Mode: "", Username: "a", PasswordHash: mustHash(t, "x")},
		"badhash.example.com": {Mode: "password", Username: "a", PasswordHash: "plaintext"},
		"nouser.example.com":  {Mode: "password", Username: "", PasswordHash: mustHash(t, "x")},
	})
	s := NewServer(path, []byte("k"))
	s.Reload()
	for _, d := range []string{"nomode.example.com", "badhash.example.com", "nouser.example.com"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, checkReq(d, d))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", d, rec.Code)
		}
	}
}

func loginPost(domain, user, pass, rd, ip string) *http.Request {
	form := url.Values{"username": {user}, "password": {pass}, "rd": {rd}}
	req := httptest.NewRequest(http.MethodPost, "/__stacked/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(DomainHeader, domain)
	req.Header.Set("X-Forwarded-For", ip)
	req.Host = domain
	return req
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie set (status %d)", rec.Code)
	return nil
}

func TestLoginFlowAndCookie(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, loginPost(testDomain, "admin", "hunter22", "/after", "203.0.113.5"))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/after" {
		t.Fatalf("login: status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookie(t, rec)

	req := checkReq(testDomain, testDomain)
	req.AddCookie(c)
	if rec := f.do(t, req); rec.Code != http.StatusOK {
		t.Fatalf("check with cookie: %d, want 200", rec.Code)
	}

	// Cookie is bound to its domain.
	other := DomainGate{Mode: "password", Username: "admin", PasswordHash: f.gate.PasswordHash}
	writeConfig(t, f.path, map[string]DomainGate{testDomain: f.gate, "other.example.com": other})
	f.srv.Reload()
	req = checkReq("other.example.com", "other.example.com")
	req.AddCookie(c)
	if rec := f.do(t, req); rec.Code != http.StatusFound {
		t.Fatalf("cookie replayed on other domain: %d, want 302", rec.Code)
	}
}

func TestCredentialChangeRevokesCookie(t *testing.T) {
	f := newFixture(t)
	c := sessionCookie(t, f.do(t, loginPost(testDomain, "admin", "hunter22", "/", "203.0.113.5")))

	changed := f.gate
	changed.PasswordHash = mustHash(t, "new-password")
	writeConfig(t, f.path, map[string]DomainGate{testDomain: changed})
	f.srv.Reload()

	req := checkReq(testDomain, testDomain)
	req.AddCookie(c)
	if rec := f.do(t, req); rec.Code != http.StatusFound {
		t.Fatalf("old cookie after password change: %d, want 302", rec.Code)
	}

	renamed := f.gate
	renamed.Username = "root"
	writeConfig(t, f.path, map[string]DomainGate{testDomain: renamed})
	f.srv.Reload()
	req = checkReq(testDomain, testDomain)
	req.AddCookie(c)
	if rec := f.do(t, req); rec.Code != http.StatusFound {
		t.Fatalf("old cookie after username change: %d, want 302", rec.Code)
	}
}

func TestCookieExpiryAndTampering(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.srv.now = func() time.Time { return now }

	fresh := f.srv.signCookie(testDomain, now.Add(-23*time.Hour), f.gate)
	if !f.srv.validateCookie(fresh, testDomain, f.gate) {
		t.Fatal("23h-old cookie should be valid")
	}
	old := f.srv.signCookie(testDomain, now.Add(-25*time.Hour), f.gate)
	if f.srv.validateCookie(old, testDomain, f.gate) {
		t.Fatal("25h-old cookie should be expired")
	}
	future := f.srv.signCookie(testDomain, now.Add(time.Hour), f.gate)
	if f.srv.validateCookie(future, testDomain, f.gate) {
		t.Fatal("future-dated cookie should be rejected")
	}
	if f.srv.validateCookie("garbage", testDomain, f.gate) {
		t.Fatal("garbage cookie accepted")
	}
	// Re-signed with a different key.
	other := NewServer(f.path, []byte("another-key-another-key-another!"))
	forged := other.signCookie(testDomain, now, f.gate)
	if f.srv.validateCookie(forged, testDomain, f.gate) {
		t.Fatal("cookie signed with a different key accepted")
	}
}

func TestLoginWrongCredentials(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct{ user, pass string }{
		{"admin", "wrong"},
		{"Admin", "hunter22"},
		{"nobody", "hunter22"},
		{"", ""},
	} {
		rec := f.do(t, loginPost(testDomain, tc.user, tc.pass, "/", "203.0.113.9"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%q/%q: status %d, want 401", tc.user, tc.pass, rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				t.Fatalf("%q/%q: cookie set on failed login", tc.user, tc.pass)
			}
		}
	}
}

func TestLoginUnknownDomainDenied(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, loginPost("unknown.example.com", "admin", "hunter22", "/", "203.0.113.5"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/__stacked/login", nil)
	req.Host = "unknown.example.com"
	if rec := f.do(t, req); rec.Code != http.StatusForbidden {
		t.Fatalf("GET status %d, want 403", rec.Code)
	}
}

func TestLoginPageForHostVariants(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{"APP.EXAMPLE.COM", "app.example.com."} {
		req := httptest.NewRequest(http.MethodGet, "/__stacked/login?rd=%2Fx", nil)
		req.Host = host
		rec := f.do(t, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Sign in to continue") {
			t.Fatalf("host %q: status %d", host, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `name="rd" value="/x"`) {
			t.Fatalf("host %q: rd not rendered", host)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.srv.now = func() time.Time { return now }

	for i := 0; i < loginBurst; i++ {
		rec := f.do(t, loginPost(testDomain, "admin", "wrong", "/", "198.51.100.7"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, rec.Code)
		}
	}
	// Even the correct password is refused once limited.
	rec := f.do(t, loginPost(testDomain, "admin", "hunter22", "/", "198.51.100.7"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: status %d, want 429", rec.Code)
	}
	// Other IPs are unaffected; XFF first value is the identity.
	rec = f.do(t, loginPost(testDomain, "admin", "hunter22", "/", "198.51.100.8, 198.51.100.7"))
	if rec.Code != http.StatusFound {
		t.Fatalf("other IP: status %d, want 302", rec.Code)
	}
	// Refill after the window.
	now = now.Add(loginWindow / loginBurst * 2)
	rec = f.do(t, loginPost(testDomain, "admin", "hunter22", "/", "198.51.100.7"))
	if rec.Code != http.StatusFound {
		t.Fatalf("after refill: status %d, want 302", rec.Code)
	}
}

func TestRateLimiterCleanupAndCap(t *testing.T) {
	now := time.Now()
	l := newRateLimiter(2, time.Minute, 2, func() time.Time { return now })
	if !l.allow("a") || !l.allow("b") {
		t.Fatal("initial allow failed")
	}
	// Table full and nothing refilled yet: fail closed for new keys.
	if l.allow("c") {
		t.Fatal("new key allowed while table full")
	}
	now = now.Add(2 * time.Minute)
	l.cleanup()
	if len(l.buckets) != 0 {
		t.Fatalf("cleanup left %d buckets", len(l.buckets))
	}
	if !l.allow("c") {
		t.Fatal("new key refused after cleanup")
	}
}

func TestIPv6ClientsKeyedBy64(t *testing.T) {
	a := httptest.NewRequest(http.MethodPost, "/", nil)
	a.Header.Set("X-Forwarded-For", "2001:db8:1:2::1")
	b := httptest.NewRequest(http.MethodPost, "/", nil)
	b.Header.Set("X-Forwarded-For", "2001:db8:1:2:ffff::9")
	if clientIP(a) != clientIP(b) {
		t.Fatalf("%s != %s", clientIP(a), clientIP(b))
	}
	c := httptest.NewRequest(http.MethodPost, "/", nil)
	c.RemoteAddr = "192.0.2.1:5555"
	if got := clientIP(c); got != "192.0.2.1" {
		t.Fatalf("RemoteAddr fallback: %q", got)
	}
}

func TestSafeRedirect(t *testing.T) {
	cases := map[string]string{
		"":                                     "/",
		"/":                                    "/",
		"/app?x=1#frag":                        "/app?x=1#frag",
		"//evil.com":                           "/",
		"/\\evil.com":                          "/",
		"https://evil.com":                     "/",
		"evil.com":                             "/",
		"/\t/evil.com":                         "/",
		"/\n/evil.com":                         "/",
		"/a/b//c":                              "/a/b//c",
		"/" + strings.Repeat("a", maxRedirect): "/",
	}
	for in, want := range cases {
		if got := SafeRedirect(in); got != want {
			t.Errorf("SafeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginRejectsOpenRedirect(t *testing.T) {
	f := newFixture(t)
	for _, rd := range []string{"//evil.com", "/\\evil.com", "https://evil.com"} {
		rec := f.do(t, loginPost(testDomain, "admin", "hunter22", rd, "203.0.113.5"))
		if rec.Code != http.StatusFound {
			t.Fatalf("rd %q: status %d", rd, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Fatalf("rd %q: Location %q, want /", rd, loc)
		}
	}
	// /check with a hostile X-Original-URI still redirects to a safe rd.
	req := checkReq(testDomain, testDomain)
	req.Header.Set("X-Original-URI", "//evil.com/x")
	rec := f.do(t, req)
	u, _ := url.Parse(rec.Header().Get("Location"))
	if u.Query().Get("rd") != "/" {
		t.Fatalf("Location %q", rec.Header().Get("Location"))
	}
}

func TestHealthReportsConfigHash(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body struct {
		Loaded     bool   `json:"loaded"`
		ConfigHash string `json:"configHash"`
		Domains    int    `json:"domains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Loaded || body.Domains != 1 || len(body.ConfigHash) != 64 {
		t.Fatalf("health = %+v", body)
	}
}

func TestLoadOrCreateSigningKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate", "signing.key")
	k1, err := loadOrCreateSigningKey(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("create: %v len=%d", err, len(k1))
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	k2, err := loadOrCreateSigningKey(path)
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key not persisted")
	}
}
