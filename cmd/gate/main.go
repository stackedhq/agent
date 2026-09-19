// Package main implements the Stacked auth gate sidecar.
//
// It runs as `stacked-agent gate` inside the proxy compose stack.
// Caddy's forward_auth sends a subrequest to /check; the gate
// validates a session cookie and returns 200 (pass) or 302 (login).
//
// Architecture is intentionally stateless: session cookies are
// HMAC-SHA256 signed with a per-machine key persisted to disk.
// The gate config (per-domain credentials) is written by the agent
// on every proxy_config op and read from /opt/stacked/gate/config.json.
package gate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stackedapp/stacked/agent/internal/gatehost"

	"golang.org/x/crypto/bcrypt"
)

const (
	gateDir        = "/opt/stacked/gate"
	configPath     = "/opt/stacked/gate/config.json"
	signingKeyPath = "/opt/stacked/gate/signing.key"
	listenAddr     = ":9876"
	cookieName     = "__stacked_gate"
	sessionTTL     = 24 * time.Hour
	maxLoginBody   = 8 << 10
	maxLoginKeys   = 4096
)

// GateConfig is the top-level config file written by the agent.
type GateConfig struct {
	Domains map[string]DomainGate `json:"domains"`
}

// DomainGate holds auth config for one domain.
type DomainGate struct {
	Mode         string `json:"mode"` // "password" | future: "stacked"
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"` // bcrypt
	ServiceName  string `json:"serviceName"`
}

var (
	configMu   sync.RWMutex
	gateConfig GateConfig
	signingKey []byte

	nowFn          = time.Now
	loginIPLimit   = 10
	loginUserLimit = 5
	loginWindow    = 15 * time.Minute
	loginAttempts  = newAttemptLimiter()
)

func Run() {
	ensureSigningKey()
	loadConfig()

	// Periodic config reload — picks up agent writes without restart.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for range ticker.C {
			reloadConfig()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/__stacked/login", handleLogin)
	mux.HandleFunc("/__stacked/logout", handleLogout)

	log.Printf("gate: listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("gate: %v", err)
	}
}

// ensureSigningKey loads or generates the HMAC signing key.
func ensureSigningKey() {
	_ = os.MkdirAll(gateDir, 0700)
	data, err := os.ReadFile(signingKeyPath)
	if err == nil && len(data) >= 32 {
		signingKey = data
		return
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("gate: generate signing key: %v", err)
	}
	if err := os.WriteFile(signingKeyPath, key, 0600); err != nil {
		log.Fatalf("gate: write signing key: %v", err)
	}
	signingKey = key
	log.Println("gate: generated new signing key")
}

func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("gate: no config yet (%v), starting empty", err)
		return
	}
	var cfg GateConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("gate: bad config: %v", err)
		return
	}
	cfg.Domains = canonicalizeDomainMap(cfg.Domains)
	configMu.Lock()
	gateConfig = cfg
	configMu.Unlock()
	log.Printf("gate: loaded config with %d domain(s)", len(cfg.Domains))
}

// reloadConfig is called periodically or on SIGHUP to pick up agent writes.
func reloadConfig() {
	loadConfig()
}

func canonicalizeDomainMap(in map[string]DomainGate) map[string]DomainGate {
	out := make(map[string]DomainGate, len(in))
	for host, d := range in {
		key := gatehost.CanonicalHost(host)
		if key == "" {
			continue
		}
		out[key] = d
	}
	return out
}

func getDomainGate(host string) (DomainGate, bool) {
	host = gatehost.CanonicalHost(host)
	if host == "" {
		return DomainGate{}, false
	}
	configMu.RLock()
	defer configMu.RUnlock()
	d, ok := gateConfig.Domains[host]
	return d, ok
}

// --- Cookie ---

func signCookie(domain string, issuedAt time.Time) string {
	domain = gatehost.CanonicalHost(domain)
	payload := fmt.Sprintf("%s|%d", domain, issuedAt.Unix())
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	raw := fmt.Sprintf("%s|%s", payload, sig)
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

func validateCookie(value, host string) bool {
	raw, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return false
	}
	domain, tsStr, sig := parts[0], parts[1], parts[2]

	host = gatehost.CanonicalHost(host)
	if host == "" || gatehost.CanonicalHost(domain) != host {
		return false
	}

	// Verify signature over the original payload bytes.
	payload := fmt.Sprintf("%s|%s", domain, tsStr)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Check expiry
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > sessionTTL {
		return false
	}
	return true
}

// --- Handlers ---

func requestHost(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return gatehost.CanonicalHost(host)
}

func handleCheck(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)

	gate, ok := getDomainGate(host)
	if !ok || gate.Mode == "" {
		// Fail closed: Caddy only invokes /check for hosts that should
		// be gated. An unknown host is a config mismatch, not a public
		// site — returning 200 here used to bypass the password gate.
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}

	cookie, err := r.Cookie(cookieName)
	if err == nil && validateCookie(cookie.Value, host) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Redirect to login. rd is query-escaped and already constrained
	// to a local path so the login 302 cannot become an open redirect.
	rd := safeLocalPath(r.Header.Get("X-Original-URI"))
	loginURL := "/__stacked/login?rd=" + url.QueryEscape(rd)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)

	gate, ok := getDomainGate(host)
	if !ok {
		http.Error(w, "Not configured", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		renderLogin(w, gate.ServiceName, safeLocalPath(r.URL.Query().Get("rd")), "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		renderLogin(w, gate.ServiceName, "/", "Invalid form data")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	rd := safeLocalPath(r.FormValue("rd"))

	ip := clientIP(r)
	userKey := loginUserKey(host, username)
	now := nowFn()
	if retry, ok := loginAttempts.blocked(ip, loginIPLimit, now); !ok {
		renderRetry(w, gate.ServiceName, rd, retry)
		return
	}
	if retry, ok := loginAttempts.blocked(userKey, loginUserLimit, now); !ok {
		renderRetry(w, gate.ServiceName, rd, retry)
		return
	}

	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(gate.Username)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(gate.PasswordHash), []byte(password)) == nil
	if !userOK || !passOK {
		loginAttempts.fail(ip, now)
		loginAttempts.fail(userKey, now)
		renderLogin(w, gate.ServiceName, rd, "Invalid username or password")
		return
	}

	loginAttempts.clear(ip)
	loginAttempts.clear(userKey)

	value := signCookie(host, now)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, rd, http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/__stacked/login", http.StatusFound)
}

// --- Login hardening ---

// safeLocalPath accepts only same-origin relative paths: a single leading
// slash, no scheme, no host. Protocol-relative (//host), absolute URLs,
// backslashes, and encoded equivalents collapse to "/".
func safeLocalPath(rd string) string {
	if rd == "" {
		return "/"
	}
	if strings.IndexFunc(rd, func(r rune) bool {
		return r < 0x20 || r == '\\'
	}) >= 0 {
		return "/"
	}
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.IsAbs() || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return "/"
	}
	if u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	if strings.ContainsAny(u.Path, "\\") {
		return "/"
	}
	return u.RequestURI()
}

// clientIP prefers headers Caddy injects on the gate reverse_proxy hop.
// X-Real-IP is set from {remote_host}; X-Forwarded-For is the last hop
// Caddy appended. RemoteAddr is the fallback when the gate is hit directly.
func clientIP(r *http.Request) string {
	if ip := normalizeIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := normalizeIP(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func loginUserKey(host, username string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	return strings.ToLower(host) + "\x00" + strings.ToLower(username)
}

type attemptBucket struct {
	n    int
	from time.Time
}

type attemptLimiter struct {
	mu      sync.Mutex
	buckets map[string]*attemptBucket
}

func newAttemptLimiter() *attemptLimiter {
	return &attemptLimiter{buckets: make(map[string]*attemptBucket)}
}

func (l *attemptLimiter) blocked(key string, limit int, now time.Time) (time.Duration, bool) {
	if key == "" || limit <= 0 {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked(now)
	b := l.buckets[key]
	if b == nil || now.Sub(b.from) >= loginWindow {
		return 0, true
	}
	if b.n >= limit {
		left := loginWindow - now.Sub(b.from)
		if left < time.Second {
			left = time.Second
		}
		return left, false
	}
	return 0, true
}

func (l *attemptLimiter) fail(key string, now time.Time) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || now.Sub(b.from) >= loginWindow {
		l.buckets[key] = &attemptBucket{n: 1, from: now}
	} else {
		b.n++
	}
	l.enforceCapLocked(now)
}

func (l *attemptLimiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *attemptLimiter) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buckets = make(map[string]*attemptBucket)
}

func (l *attemptLimiter) gcLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.from) >= loginWindow {
			delete(l.buckets, k)
		}
	}
}

func (l *attemptLimiter) enforceCapLocked(now time.Time) {
	l.gcLocked(now)
	for len(l.buckets) > maxLoginKeys {
		var oldestKey string
		var oldest time.Time
		for k, b := range l.buckets {
			if oldestKey == "" || b.from.Before(oldest) {
				oldestKey = k
				oldest = b.from
			}
		}
		delete(l.buckets, oldestKey)
	}
}

// --- Login Page ---

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

type loginData struct {
	ServiceName string
	RedirectTo  string
	Error       string
}

func renderRetry(w http.ResponseWriter, serviceName, rd string, retry time.Duration) {
	secs := int(retry.Seconds() + 0.5)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	renderLoginStatus(w, http.StatusTooManyRequests, serviceName, rd, "Too many attempts. Try again later.")
}

func renderLogin(w http.ResponseWriter, serviceName, rd, errMsg string) {
	renderLoginStatus(w, http.StatusOK, serviceName, rd, errMsg)
}

func renderLoginStatus(w http.ResponseWriter, status int, serviceName, rd, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	loginTmpl.Execute(w, loginData{
		ServiceName: serviceName,
		RedirectTo:  rd,
		Error:       errMsg,
	})
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — {{.ServiceName}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#09090b;color:#fafafa;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{width:100%;max-width:380px;padding:40px 32px;background:#18181b;
  border:1px solid #27272a;border-radius:16px}
h1{font-size:18px;font-weight:600;margin-bottom:4px;text-align:center}
.sub{font-size:13px;color:#71717a;text-align:center;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:6px}
input{width:100%;padding:10px 12px;background:#09090b;border:1px solid #27272a;
  border-radius:8px;color:#fafafa;font-size:14px;outline:none;transition:border .15s}
input:focus{border-color:#3b82f6}
.field{margin-bottom:16px}
button{width:100%;padding:10px;background:#fafafa;color:#09090b;border:none;
  border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.9}
.error{background:#7f1d1d;color:#fca5a5;padding:10px 12px;border-radius:8px;
  font-size:13px;margin-bottom:16px;text-align:center}
.footer{margin-top:24px;text-align:center;font-size:11px;color:#3f3f46}
.footer a{color:#52525b;text-decoration:none}
</style>
</head>
<body>
<div class="card">
  <h1>Sign in to continue</h1>
  <p class="sub">{{.ServiceName}}</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST" action="/__stacked/login">
    <input type="hidden" name="rd" value="{{.RedirectTo}}">
    <div class="field">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="username" autofocus required>
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
    </div>
    <button type="submit">Sign in</button>
  </form>
  <div class="footer">Protected by <a href="https://stacked.rest" target="_blank">Stacked</a></div>
</div>
</body>
</html>`
