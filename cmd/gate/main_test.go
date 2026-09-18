package gate

import (
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
