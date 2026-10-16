// Package gate implements the Stacked auth gate sidecar.
//
// It runs as `stacked-agent gate` inside the proxy compose stack, on a
// private (internal) docker network shared only with Caddy. Caddy's
// forward_auth sends a subrequest to /check; the gate validates a
// session cookie and returns 200 (pass), 302 (login) or 403 (deny).
//
// Fail-closed rules:
//
//   - The gate keys every decision on the domain Caddy passes in the
//     fixed per-site header X-Stacked-Gate-Domain (the configured domain
//     literal from the Caddyfile). Both Caddy blocks that reach the gate
//     always set it, so a request without it is denied (403); the Host
//     header is never consulted.
//   - A domain the gate has no valid entry for gets 403, never 200.
//   - While the config file is missing, unreadable or invalid, every
//     request gets 403 until a valid config loads.
//
// Session cookies are HMAC-SHA256 signed with a per-machine key
// persisted to disk. The MAC covers domain, issue time and a hash of
// that domain's current credentials, so changing the username or
// password revokes every outstanding session.
//
// The gate config (per-domain credentials) is written by the agent on
// every proxy_config op to /opt/stacked/gate/config.json and picked up
// on SIGHUP or by the 5s reload ticker.
package gate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	gateDir        = "/opt/stacked/gate"
	configPath     = "/opt/stacked/gate/config.json"
	signingKeyPath = "/opt/stacked/gate/signing.key"
	listenAddr     = ":9876"
	statusURL      = "http://127.0.0.1:9876/healthz"
	cookieName     = "__stacked_gate"
	sessionTTL     = 24 * time.Hour
	// maxClockSkew bounds how far in the future a cookie's issue time
	// may be before it's rejected.
	maxClockSkew = 5 * time.Minute

	// DomainHeader is the fixed per-site header Caddy sets (header_up)
	// to the configured domain literal. Caddy overwrites any value the
	// client sent, so it can't be spoofed from outside.
	DomainHeader = "X-Stacked-Gate-Domain"

	maxLoginBody = 16 << 10
	maxRedirect  = 4096

	// Login rate limit: loginBurst attempts per loginWindow per
	// client-IP+domain, refilled continuously (token bucket).
	loginBurst     = 10
	loginWindow    = 5 * time.Minute
	maxLimiterKeys = 100_000
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

// loadedConfig is a validated, normalized config snapshot.
type loadedConfig struct {
	domains map[string]DomainGate
	hash    string // sha256 hex of the raw file bytes
}

// Server is the gate HTTP server. A nil config means "deny everything".
type Server struct {
	configPath string
	signingKey []byte

	mu      sync.RWMutex
	cfg     *loadedConfig
	loadErr string

	limiter *rateLimiter
	now     func() time.Time

	dummyOnce sync.Once
	dummyHash []byte
}

// NewServer builds a gate server reading config from configPath. The
// server starts in deny-all state; call Reload to load the config.
func NewServer(configPath string, signingKey []byte) *Server {
	s := &Server{
		configPath: configPath,
		signingKey: signingKey,
		now:        time.Now,
		loadErr:    "config not loaded yet",
	}
	s.limiter = newRateLimiter(loginBurst, loginWindow, maxLimiterKeys, func() time.Time { return s.now() })
	return s
}

// Main is the `stacked-agent gate [status]` entry point.
func Main(args []string) {
	if len(args) > 0 && args[0] == "status" {
		os.Exit(printStatus())
	}
	Run()
}

// Run starts the gate server and blocks.
func Run() {
	key, err := loadOrCreateSigningKey(signingKeyPath)
	if err != nil {
		log.Fatalf("gate: signing key: %v", err)
	}
	s := NewServer(configPath, key)
	s.Reload()

	// Periodic reload plus SIGHUP (sent by the agent right after it
	// writes config.json) so new config is picked up immediately.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-hup:
			}
			s.Reload()
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.limiter.cleanup()
		}
	}()

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	log.Printf("gate: listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("gate: %v", err)
	}
}

// printStatus queries the running gate's /healthz from inside the
// container (used by the agent via `docker exec`) and prints the JSON.
func printStatus() int {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(statusURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate status: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	fmt.Println(strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// loadOrCreateSigningKey loads the HMAC key or generates a new one,
// writing it atomically with mode 0600.
func loadOrCreateSigningKey(path string) ([]byte, error) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("rename: %w", err)
	}
	log.Println("gate: generated new signing key")
	return key, nil
}

// --- Config ---

// Reload reads and validates the config file. Missing, unreadable or
// invalid config switches the server to deny-all until a valid config
// loads. Logs only on state changes so the 5s ticker doesn't spam.
func (s *Server) Reload() {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		s.setDenyAll(fmt.Sprintf("config unreadable: %v", err))
		return
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	s.mu.RLock()
	unchanged := s.cfg != nil && s.cfg.hash == hash
	s.mu.RUnlock()
	if unchanged {
		return
	}

	domains, skipped, err := parseConfig(data)
	if err != nil {
		s.setDenyAll(fmt.Sprintf("config invalid: %v", err))
		return
	}
	for _, msg := range skipped {
		log.Printf("gate: skipping config entry (domain will be denied): %s", msg)
	}
	s.mu.Lock()
	s.cfg = &loadedConfig{domains: domains, hash: hash}
	s.loadErr = ""
	s.mu.Unlock()
	log.Printf("gate: loaded config with %d domain(s)", len(domains))
}

func (s *Server) setDenyAll(reason string) {
	s.mu.Lock()
	changed := s.cfg != nil || s.loadErr != reason
	s.cfg = nil
	s.loadErr = reason
	s.mu.Unlock()
	if changed {
		log.Printf("gate: %s; denying all requests until a valid config loads", reason)
	}
}

// parseConfig decodes and validates the config. A malformed document is
// an error (deny all). Individual invalid entries are dropped (so that
// domain is denied) and reported in skipped.
func parseConfig(data []byte) (map[string]DomainGate, []string, error) {
	var cfg GateConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, err
	}
	out := make(map[string]DomainGate, len(cfg.Domains))
	var skipped []string
	for raw, d := range cfg.Domains {
		key := NormalizeHost(raw)
		switch {
		case !validDomainKey(key):
			skipped = append(skipped, fmt.Sprintf("%q: invalid domain", raw))
		case d.Mode != "password":
			skipped = append(skipped, fmt.Sprintf("%q: unsupported mode %q", raw, d.Mode))
		case d.Username == "":
			skipped = append(skipped, fmt.Sprintf("%q: empty username", raw))
		case !validBcrypt(d.PasswordHash):
			skipped = append(skipped, fmt.Sprintf("%q: invalid password hash", raw))
		default:
			if _, dup := out[key]; dup {
				// Two raw keys normalizing to one domain with possibly
				// different credentials: ambiguous, deny the domain.
				delete(out, key)
				skipped = append(skipped, fmt.Sprintf("%q: duplicate domain after normalization", raw))
				continue
			}
			out[key] = d
		}
	}
	return out, skipped, nil
}

var domainKeyRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validDomainKey(s string) bool {
	return s != "" && len(s) <= 253 && domainKeyRe.MatchString(s)
}

func validBcrypt(h string) bool {
	_, err := bcrypt.Cost([]byte(h))
	return err == nil
}

// NormalizeHost lowercases a host, strips any port (including IPv6
// brackets) and a single trailing dot.
func NormalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		if end < 0 {
			return ""
		}
		h = h[1:end]
	} else if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

// requestDomain returns the domain the gate should key on: Caddy's
// fixed per-site header. Empty (deny) when the header is missing; the
// Host header is deliberately ignored, since every Caddy block that
// reaches the gate sets the header.
func requestDomain(r *http.Request) string {
	return NormalizeHost(r.Header.Get(DomainHeader))
}

// lookup returns the gate for domain. ok=false means deny (no valid
// config loaded, or the domain isn't configured).
func (s *Server) lookup(domain string) (DomainGate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil || domain == "" {
		return DomainGate{}, false
	}
	d, ok := s.cfg.domains[domain]
	return d, ok
}

// --- Cookie ---

// credHash binds a session to the domain's current credentials. bcrypt
// hashes never contain '|', so the encoding is unambiguous.
func credHash(g DomainGate) []byte {
	sum := sha256.Sum256([]byte(g.Username + "|" + g.PasswordHash))
	return sum[:16]
}

func (s *Server) mac(domain string, ts int64, g DomainGate) string {
	m := hmac.New(sha256.New, s.signingKey)
	fmt.Fprintf(m, "%s|%d|%x", domain, ts, credHash(g))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) signCookie(domain string, issuedAt time.Time, g DomainGate) string {
	ts := issuedAt.Unix()
	raw := fmt.Sprintf("%s|%d|%s", domain, ts, s.mac(domain, ts, g))
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

func (s *Server) validateCookie(value, domain string, g DomainGate) bool {
	raw, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 {
		return false
	}
	cookieDomain, tsStr, sig := parts[0], parts[1], parts[2]
	if subtle.ConstantTimeCompare([]byte(cookieDomain), []byte(domain)) != 1 {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	expected := s.mac(domain, ts, g)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}
	issued := time.Unix(ts, 0)
	now := s.now()
	if now.Sub(issued) > sessionTTL || issued.Sub(now) > maxClockSkew {
		return false
	}
	return true
}

// --- Redirect target ---

// SafeRedirect returns rd if it's a same-origin absolute path (single
// leading '/', not '//' or '/\', no control characters), else "/".
func SafeRedirect(rd string) string {
	if rd == "" || len(rd) > maxRedirect || rd[0] != '/' {
		return "/"
	}
	if len(rd) > 1 && (rd[1] == '/' || rd[1] == '\\') {
		return "/"
	}
	for _, c := range rd {
		// Browsers strip tab/CR/LF from URLs, so "/\t/evil" would turn
		// into "//evil". Reject all control characters.
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	return rd
}

// --- Client IP / rate limit ---

// clientIP returns the rate-limit identity for the request. The gate is
// only reachable from Caddy (internal docker network), and Caddy's
// reverse_proxy/forward_auth replace any client-supplied
// X-Forwarded-For with the real peer address (no trusted_proxies are
// configured), so the first X-Forwarded-For value is trustworthy here.
// IPv6 clients are keyed by /64 so one host can't rotate addresses.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if addr, err := netip.ParseAddr(first); err == nil {
			return ipKey(addr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return ipKey(addr)
	}
	return host
}

func ipKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	perSec   float64
	maxKeys  int
	now      func() time.Time
}

func newRateLimiter(burst int, window time.Duration, maxKeys int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		buckets:  make(map[string]*bucket),
		capacity: float64(burst),
		perSec:   float64(burst) / window.Seconds(),
		maxKeys:  maxKeys,
		now:      now,
	}
}

func (l *rateLimiter) refill(b *bucket, now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * l.perSec
		if b.tokens > l.capacity {
			b.tokens = l.capacity
		}
	}
	b.last = now
}

// allow consumes one token for key. When the table is full even after
// cleanup it fails closed (memory stays bounded).
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.cleanupLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false
			}
		}
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(l.now())
}

// cleanupLocked drops buckets that have refilled completely: they carry
// no state a fresh bucket wouldn't.
func (l *rateLimiter) cleanupLocked(now time.Time) {
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.capacity {
			delete(l.buckets, k)
		}
	}
}

// --- Handlers ---

// Handler returns the gate's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("/__stacked/login", s.handleLogin)
	mux.HandleFunc("/__stacked/logout", s.handleLogout)
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	domain := requestDomain(r)
	gate, ok := s.lookup(domain)
	if !ok {
		deny(w)
		return
	}

	if c, err := r.Cookie(cookieName); err == nil && s.validateCookie(c.Value, domain, gate) {
		w.WriteHeader(http.StatusOK)
		return
	}

	rd := SafeRedirect(r.Header.Get("X-Original-URI"))
	http.Redirect(w, r, "/__stacked/login?rd="+url.QueryEscape(rd), http.StatusFound)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	domain := requestDomain(r)
	gate, ok := s.lookup(domain)
	if !ok {
		deny(w)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		renderLogin(w, http.StatusOK, gate.ServiceName, SafeRedirect(r.URL.Query().Get("rd")), "")
		return
	case http.MethodPost:
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.allow(clientIP(r) + "|" + domain) {
		w.Header().Set("Retry-After", strconv.Itoa(int((loginWindow / loginBurst).Seconds())))
		renderLogin(w, http.StatusTooManyRequests, gate.ServiceName, "/", "Too many sign-in attempts. Try again in a few minutes.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		renderLogin(w, http.StatusBadRequest, gate.ServiceName, "/", "Invalid form data")
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	rd := SafeRedirect(r.PostFormValue("rd"))

	if !s.checkCredentials(gate, username, password) {
		renderLogin(w, http.StatusUnauthorized, gate.ServiceName, rd, "Invalid username or password")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.signCookie(domain, s.now(), gate),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	http.Redirect(w, r, rd, http.StatusFound)
}

// checkCredentials compares the username in constant time and always
// runs bcrypt (against a dummy hash on username mismatch) so response
// time doesn't reveal whether the username was right.
func (s *Server) checkCredentials(g DomainGate, username, password string) bool {
	gotU := sha256.Sum256([]byte(username))
	wantU := sha256.Sum256([]byte(g.Username))
	userOK := subtle.ConstantTimeCompare(gotU[:], wantU[:]) == 1

	hash := []byte(g.PasswordHash)
	if !userOK {
		hash = s.dummy()
	}
	pwOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return userOK && pwOK
}

func (s *Server) dummy() []byte {
	s.dummyOnce.Do(func() {
		secret := make([]byte, 24)
		_, _ = rand.Read(secret)
		// Cost 10 matches the server's bcrypt.hash(password, 10).
		h, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(secret)), 10)
		if err != nil {
			h = []byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinva")
		}
		s.dummyHash = h
	})
	return s.dummyHash
}

// handleLogout clears the session cookie. POST only, so a cross-site
// <img src=".../__stacked/logout"> or link prefetch can't sign users out.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/__stacked/login", http.StatusSeeOther)
}

// handleHealth reports load state for the agent (via `gate status`
// inside the container). Not routed by Caddy: only /__stacked/* and the
// forward_auth /check subrequest reach the gate from outside.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	resp := struct {
		Loaded     bool   `json:"loaded"`
		ConfigHash string `json:"configHash,omitempty"`
		Domains    int    `json:"domains"`
		Error      string `json:"error,omitempty"`
	}{Error: s.loadErr}
	if s.cfg != nil {
		resp.Loaded = true
		resp.ConfigHash = s.cfg.hash
		resp.Domains = len(s.cfg.domains)
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// --- Login Page ---

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

type loginData struct {
	ServiceName string
	RedirectTo  string
	Error       string
}

func renderLogin(w http.ResponseWriter, status int, serviceName, rd, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, loginData{
		ServiceName: serviceName,
		RedirectTo:  rd,
		Error:       errMsg,
	}); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		log.Printf("gate: render login: %v", err)
	}
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in: {{.ServiceName}}</title>
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
  <div class="footer">Protected by <a href="https://stacked.rest" target="_blank" rel="noopener">Stacked</a></div>
</div>
</body>
</html>`
