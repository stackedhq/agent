package executor

import (
	"fmt"
	"log"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// SslCheck inspects Caddy's certificate data directory for each requested
// domain and reports whether a certificate has been issued.
//
// Caddy persists certs under issuer-specific directories, e.g.:
//
//	/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/<domain>/<domain>.crt
//	/data/caddy/certificates/acme.zerossl.com-v2-DV90/<domain>/<domain>.crt
//
// Caddy 2 defaults to a Let's Encrypt → ZeroSSL fallback chain, so we glob
// across any issuer directory instead of hardcoding LE.
//
// All domains are checked in a single `docker compose exec` to avoid the
// ~1–2s per-call overhead of compose. The container shell loops through
// the list and prints `<domain>=active|pending`. We parse stdout.
//
// Per-domain result values:
//
//	"active"  — certificate file exists somewhere under /data/caddy/certificates
//	"pending" — no cert yet (still issuing, or not attempted)
//
// Payload shape: { "domains": [{ "domain": "foo.com" }, ...] }
// Result shape:  { "<domain>": "active" | "pending", ... }
func (e *Executor) SslCheck(op client.Operation) (map[string]interface{}, error) {
	domainsRaw, ok := op.Payload["domains"]
	if !ok {
		return nil, fmt.Errorf("ssl_check requires domains in payload")
	}
	domainList, ok := domainsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("ssl_check domains must be an array")
	}

	// Filter and validate. Skip anything that fails the safety check —
	// this op runs inside `docker compose exec` so we want zero shell
	// injection surface even though payload comes from our own server.
	domains := make([]string, 0, len(domainList))
	for _, d := range domainList {
		dm, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		domain, _ := dm["domain"].(string)
		if domain == "" || !isSafeDomain(domain) {
			continue
		}
		domains = append(domains, domain)
	}

	result := make(map[string]interface{}, len(domains))
	if len(domains) == 0 {
		log.Printf("ssl_check: no domains to inspect")
		return result, nil
	}

	// Default everything to pending so a parsing miss doesn't leave a
	// domain absent from the response (server treats missing as pending
	// anyway, but explicit is clearer in logs).
	for _, d := range domains {
		result[d] = "pending"
	}

	// Build a portable shell loop. Quoting is safe because every domain
	// already passed isSafeDomain — only [a-zA-Z0-9.-_].
	var script strings.Builder
	script.WriteString("set -eu; ")
	for _, d := range domains {
		// `ls` on the glob; redirect stderr; success means at least one
		// matching cert file exists.
		fmt.Fprintf(&script,
			"if ls /data/caddy/certificates/*/%s/%s.crt >/dev/null 2>&1; then echo '%s=active'; else echo '%s=pending'; fi; ",
			d, d, d, d,
		)
	}

	out, err := runCommandSilent(proxyDir, "docker", "compose", "exec", "-T", "caddy", "sh", "-c", script.String())
	if err != nil {
		// If the exec itself fails (Caddy not running, compose missing,
		// etc.) we surface the error so the server can mark the op
		// failed. Server's cooldown logic prevents a tight loop.
		return nil, fmt.Errorf("caddy exec: %s: %w", strings.TrimSpace(out), err)
	}

	// Parse `<domain>=<state>` lines.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		d := line[:eq]
		state := line[eq+1:]
		if state == "active" || state == "pending" {
			result[d] = state
		}
	}

	log.Printf("ssl_check inspected %d domain(s)", len(result))
	return result, nil
}

// isSafeDomain restricts the domain charset so it can be safely interpolated
// into a shell command. Matches a permissive subset of valid hostnames.
func isSafeDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	return true
}
