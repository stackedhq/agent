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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	gateDir        = "/opt/stacked/gate"
	configPath     = "/opt/stacked/gate/config.json"
	signingKeyPath = "/opt/stacked/gate/signing.key"
	listenAddr     = ":9876"
	cookieName     = "__stacked_gate"
	sessionTTL     = 24 * time.Hour
)

// GateConfig is the top-level config file written by the agent.
type GateConfig struct {
	Domains map[string]DomainGate `json:"domains"`
}

// DomainGate holds auth config for one domain.
type DomainGate struct {
	Mode         string `json:"mode"`         // "password" | future: "stacked"
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"` // bcrypt
	ServiceName  string `json:"serviceName"`
}

var (
	configMu   sync.RWMutex
	gateConfig GateConfig
	signingKey []byte
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
	configMu.Lock()
	gateConfig = cfg
	configMu.Unlock()
	log.Printf("gate: loaded config with %d domain(s)", len(cfg.Domains))
}

// reloadConfig is called periodically or on SIGHUP to pick up agent writes.
func reloadConfig() {
	loadConfig()
}

func getDomainGate(host string) (DomainGate, bool) {
	// Strip port if present
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	configMu.RLock()
	defer configMu.RUnlock()
	d, ok := gateConfig.Domains[host]
	return d, ok
}

// --- Cookie ---

func signCookie(domain string, issuedAt time.Time) string {
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

	// Strip port from host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	if domain != host {
		return false
	}

	// Verify signature
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

func handleCheck(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	gate, ok := getDomainGate(host)
	if !ok || gate.Mode == "" {
		// No gate for this domain — pass through
		w.WriteHeader(http.StatusOK)
		return
	}

	cookie, err := r.Cookie(cookieName)
	if err == nil && validateCookie(cookie.Value, host) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Redirect to login
	originalURI := r.Header.Get("X-Original-URI")
	if originalURI == "" {
		originalURI = "/"
	}
	loginURL := fmt.Sprintf("/__stacked/login?rd=%s", originalURI)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	gate, ok := getDomainGate(host)
	if !ok {
		http.Error(w, "Not configured", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		rd := r.URL.Query().Get("rd")
		if rd == "" {
			rd = "/"
		}
		renderLogin(w, gate.ServiceName, rd, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// POST: validate credentials
	if err := r.ParseForm(); err != nil {
		renderLogin(w, gate.ServiceName, "/", "Invalid form data")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	rd := r.FormValue("rd")
	if rd == "" {
		rd = "/"
	}

	if username != gate.Username || bcrypt.CompareHashAndPassword([]byte(gate.PasswordHash), []byte(password)) != nil {
		renderLogin(w, gate.ServiceName, rd, "Invalid username or password")
		return
	}

	// Set session cookie
	value := signCookie(host, time.Now())
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

// --- Login Page ---

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

type loginData struct {
	ServiceName string
	RedirectTo  string
	Error       string
}

func renderLogin(w http.ResponseWriter, serviceName, rd, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
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
