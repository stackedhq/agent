package gate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func withGate(t *testing.T, domains map[string]DomainGate) {
	t.Helper()
	signingKey = []byte("0123456789abcdef0123456789abcdef")
	configMu.Lock()
	gateConfig = GateConfig{Domains: canonicalizeDomainMap(domains)}
	configMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		gateConfig = GateConfig{}
		configMu.Unlock()
	})
}

func checkRequest(host string, cookie string) *http.Response {
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Original-URI", "/secret")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	handleCheck(rec, req)
	return rec.Result()
}

func TestHandleCheckFailsClosedForUnknownHost(t *testing.T) {
	withGate(t, map[string]DomainGate{
		"example.com": {Mode: "password", Username: "u", ServiceName: "app"},
	})

	res := checkRequest("unknown.example.com", "")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown host status = %d, want 403", res.StatusCode)
	}
}

func TestHandleCheckFailsClosedForEmptyHost(t *testing.T) {
	withGate(t, map[string]DomainGate{
		"example.com": {Mode: "password"},
	})

	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Host = ""
	rec := httptest.NewRecorder()
	handleCheck(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty host status = %d, want 403", rec.Code)
	}
}

func TestHandleCheckCanonicalizesMixedCaseTrailingDotAndPort(t *testing.T) {
	withGate(t, map[string]DomainGate{
		"example.com": {Mode: "password", Username: "u", ServiceName: "app"},
	})

	hosts := []string{
		"example.com",
		"ExAmPlE.com",
		"EXAMPLE.COM",
		"example.com.",
		"Example.COM.",
		"example.com:443",
		"ExAmPlE.com:8080",
		"Example.COM.:443",
	}
	for _, host := range hosts {
		res := checkRequest(host, "")
		if res.StatusCode != http.StatusFound {
			t.Errorf("host %q status = %d, want 302 (gated, no cookie)", host, res.StatusCode)
			continue
		}
		loc := res.Header.Get("Location")
		if !strings.Contains(loc, "/__stacked/login") {
			t.Errorf("host %q redirected to %q, want login", host, loc)
		}
	}
}

func TestHandleCheckValidCookiePassesForCanonicalVariants(t *testing.T) {
	withGate(t, map[string]DomainGate{
		"example.com": {Mode: "password", Username: "u", ServiceName: "app"},
	})

	cookie := signCookie("example.com", time.Now())
	hosts := []string{
		"example.com",
		"ExAmPlE.com",
		"example.com.",
		"example.com:443",
		"Example.COM.:443",
	}
	for _, host := range hosts {
		res := checkRequest(host, cookie)
		if res.StatusCode != http.StatusOK {
			t.Errorf("host %q with valid cookie status = %d, want 200", host, res.StatusCode)
		}
	}
}

func TestCookieSigningUsesCanonicalDomain(t *testing.T) {
	withGate(t, nil)

	now := time.Now()
	a := signCookie("ExAmPlE.com:443", now)
	b := signCookie("example.com", now)
	if a != b {
		t.Fatalf("mixed-case+port cookie %q != canonical cookie %q", a, b)
	}
	if !validateCookie(a, "EXAMPLE.COM.") {
		t.Fatal("cookie signed from mixed-case host should validate on trailing-dot host")
	}
	if !validateCookie(a, "example.com:8080") {
		t.Fatal("cookie should validate when request host includes a port")
	}
	if validateCookie(a, "other.example.com") {
		t.Fatal("cookie must not validate for a different domain")
	}
}

func TestCanonicalizeDomainMapLowercasesKeys(t *testing.T) {
	out := canonicalizeDomainMap(map[string]DomainGate{
		"ExAmPlE.com.":  {Mode: "password", Username: "alice"},
		"Other.COM:443": {Mode: "password", Username: "bob"},
	})
	if _, ok := out["example.com"]; !ok {
		t.Fatalf("missing example.com key, got %#v", out)
	}
	if _, ok := out["other.com"]; !ok {
		t.Fatalf("missing other.com key, got %#v", out)
	}
	if _, ok := out["ExAmPlE.com."]; ok {
		t.Fatal("mixed-case key should not survive canonicalization")
	}
}

func TestHandleLoginSetsCookieForCanonicalHost(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	withGate(t, map[string]DomainGate{
		"example.com": {
			Mode:         "password",
			Username:     "alice",
			PasswordHash: string(hash),
			ServiceName:  "app",
		},
	})

	form := url.Values{
		"username": {"alice"},
		"password": {"secret"},
		"rd":       {"/app"},
	}
	req := httptest.NewRequest(http.MethodPost, "/__stacked/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Host", "ExAmPlE.com:443")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("login status = %d, body %s", res.StatusCode, body)
	}

	var cookie string
	for _, c := range res.Cookies() {
		if c.Name == cookieName {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("login did not set session cookie")
	}
	if !validateCookie(cookie, "example.com") {
		t.Fatal("session cookie should validate against the canonical host")
	}
	if !validateCookie(cookie, "EXAMPLE.com.") {
		t.Fatal("session cookie should validate against mixed-case + trailing-dot host")
	}

	res = checkRequest("ExAmPlE.com", cookie)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("gated request with login cookie status = %d, want 200", res.StatusCode)
	}
}

func TestSafeLocalPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/dashboard", "/dashboard"},
		{"/ok/path?x=1", "/ok/path?x=1"},
		{"/app#frag", "/app"},
		{"//attacker.example", "/"},
		{"//attacker.example/phish", "/"},
		{"https://evil.example/x", "/"},
		{"http://evil.example", "/"},
		{"/%2F%2Fevil.example", "/"},
		{"/%2f%2fevil.example", "/"},
		{"/%5C%5Cevil.example", "/"},
		{"/\\evil.example", "/"},
		{"\\\\evil.example", "/"},
		{"://evil.example", "/"},
		{"javascript:alert(1)", "/"},
		{"/foo\r\nLocation: https://evil.example", "/"},
		{" /dashboard", "/"},
		{"dashboard", "/"},
	}
	for _, tt := range tests {
		if got := safeLocalPath(tt.in); got != tt.want {
			t.Errorf("safeLocalPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClientIPPrefersProxyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.9:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.2")
	req.Header.Set("X-Real-IP", "192.0.2.55")
	if got := clientIP(req); got != "192.0.2.55" {
		t.Fatalf("X-Real-IP: got %q", got)
	}

	req.Header.Del("X-Real-IP")
	if got := clientIP(req); got != "198.51.100.2" {
		t.Fatalf("X-Forwarded-For last hop: got %q", got)
	}

	req.Header.Del("X-Forwarded-For")
	if got := clientIP(req); got != "10.0.0.9" {
		t.Fatalf("RemoteAddr: got %q", got)
	}
}

func setupLoginTest(t *testing.T) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	signingKey = make([]byte, 32)
	configMu.Lock()
	gateConfig = GateConfig{Domains: canonicalizeDomainMap(map[string]DomainGate{
		"app.example": {Mode: "password", Username: "admin", PasswordHash: string(hash), ServiceName: "app"},
	})}
	configMu.Unlock()
	loginAttempts.reset()
	loginIPLimit = 3
	loginUserLimit = 3
	loginWindow = 15 * time.Minute
	nowFn = time.Now
	t.Cleanup(func() {
		loginIPLimit = 10
		loginUserLimit = 5
		loginWindow = 15 * time.Minute
		nowFn = time.Now
		loginAttempts.reset()
		configMu.Lock()
		gateConfig = GateConfig{}
		configMu.Unlock()
	})
}

func postLogin(t *testing.T, username, password, rd, ip string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"username": {username},
		"password": {password},
		"rd":       {rd},
	}
	req := httptest.NewRequest(http.MethodPost, "/__stacked/login", strings.NewReader(form.Encode()))
	req.Host = "app.example"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Host", "app.example")
	if ip != "" {
		req.Header.Set("X-Real-IP", ip)
	}
	req.RemoteAddr = "10.0.0.2:9"
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	return rec
}

func TestLoginRejectsOpenRedirects(t *testing.T) {
	setupLoginTest(t)
	cases := []struct {
		name, rd string
	}{
		{"protocol-relative", "//attacker.example"},
		{"absolute-https", "https://evil.example/phish"},
		{"absolute-http", "http://evil.example"},
		{"encoded-slashes", "/%2F%2Fevil.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postLogin(t, "admin", "s3cret", tc.rd, "203.0.113.10")
			if rec.Code != http.StatusFound {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.Bytes())
			}
			if loc := rec.Header().Get("Location"); loc != "/" {
				t.Fatalf("Location = %q, want /", loc)
			}
		})
	}
}

func TestLoginAllowsLocalRedirect(t *testing.T) {
	setupLoginTest(t)
	rec := postLogin(t, "admin", "s3cret", "/dashboard?tab=1", "203.0.113.10")
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard?tab=1" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestLoginEncodedOpenRedirectViaQuery(t *testing.T) {
	setupLoginTest(t)
	req := httptest.NewRequest(http.MethodGet, "/__stacked/login?rd="+url.QueryEscape("//attacker.example"), nil)
	req.Header.Set("X-Forwarded-Host", "app.example")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `value="//attacker.example"`) {
		t.Fatal("open redirect leaked into form")
	}
	if !strings.Contains(rec.Body.String(), `name="rd" value="/"`) {
		t.Fatalf("expected sanitized rd, body=%s", rec.Body.String())
	}
}

func TestLoginThrottlePerIP(t *testing.T) {
	setupLoginTest(t)
	for i := 0; i < loginIPLimit; i++ {
		rec := postLogin(t, "admin", "wrong", "/", "203.0.113.10")
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d", i+1, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Invalid username or password") {
			t.Fatalf("attempt %d: want uniform credential error", i+1)
		}
	}
	rec := postLogin(t, "admin", "wrong", "/", "203.0.113.10")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked status %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	rec = postLogin(t, "admin", "s3cret", "/dashboard", "203.0.113.10")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password under lock: %d", rec.Code)
	}
}

func TestLoginThrottlePerUsername(t *testing.T) {
	setupLoginTest(t)
	for i := 0; i < loginUserLimit; i++ {
		rec := postLogin(t, "admin", "wrong", "/", fmt.Sprintf("198.51.100.%d", i+1))
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d", i+1, rec.Code)
		}
	}
	rec := postLogin(t, "admin", "wrong", "/", "198.51.100.99")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("per-user lock status %d", rec.Code)
	}
}

func TestLoginCredentialErrorsAreUniform(t *testing.T) {
	setupLoginTest(t)
	badUser := postLogin(t, "nope", "s3cret", "/", "203.0.113.10")
	badPass := postLogin(t, "admin", "nope", "/", "203.0.113.11")
	if badUser.Code != http.StatusOK || badPass.Code != http.StatusOK {
		t.Fatalf("statuses %d %d", badUser.Code, badPass.Code)
	}
	if badUser.Body.String() != badPass.Body.String() {
		t.Fatal("username vs password failures diverged")
	}
	if !strings.Contains(badUser.Body.String(), "Invalid username or password") {
		t.Fatal("missing uniform error")
	}
}

func TestLoginRejectsWrongMethodAndContentType(t *testing.T) {
	setupLoginTest(t)
	req := httptest.NewRequest(http.MethodPut, "/__stacked/login", nil)
	req.Header.Set("X-Forwarded-Host", "app.example")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT status %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/__stacked/login", strings.NewReader(`{"username":"admin"}`))
	req.Header.Set("X-Forwarded-Host", "app.example")
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("json POST status %d", rec.Code)
	}
}

func TestLoginRejectsOversizedBody(t *testing.T) {
	setupLoginTest(t)
	body := "username=admin&password=s3cret&rd=/&pad=" + strings.Repeat("x", maxLoginBody)
	req := httptest.NewRequest(http.MethodPost, "/__stacked/login", strings.NewReader(body))
	req.Header.Set("X-Forwarded-Host", "app.example")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid form data") {
		t.Fatalf("body %s", rec.Body.Bytes())
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("oversized body must not set a session")
	}
}

func TestCheckSanitizesOriginalURI(t *testing.T) {
	setupLoginTest(t)
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("X-Forwarded-Host", "app.example")
	req.Header.Set("X-Original-URI", "//attacker.example")
	rec := httptest.NewRecorder()
	handleCheck(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("rd") != "/" {
		t.Fatalf("Location %q", loc)
	}
}

func TestSuccessfulLoginClearsThrottle(t *testing.T) {
	setupLoginTest(t)
	for i := 0; i < loginIPLimit-1; i++ {
		if rec := postLogin(t, "admin", "wrong", "/", "203.0.113.10"); rec.Code != http.StatusOK {
			t.Fatalf("fail %d: %d", i, rec.Code)
		}
	}
	if rec := postLogin(t, "admin", "s3cret", "/home", "203.0.113.10"); rec.Code != http.StatusFound {
		t.Fatalf("success status %d", rec.Code)
	}
	if rec := postLogin(t, "admin", "wrong", "/", "203.0.113.10"); rec.Code != http.StatusOK {
		t.Fatalf("after clear, fail should not lock immediately, got %d", rec.Code)
	}
}

func TestLimiterIsBounded(t *testing.T) {
	l := newAttemptLimiter()
	now := time.Now()
	for i := 0; i < maxLoginKeys+50; i++ {
		l.fail(fmt.Sprintf("k%d", i), now)
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > maxLoginKeys {
		t.Fatalf("limiter grew to %d", n)
	}
}
