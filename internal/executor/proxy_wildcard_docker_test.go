package executor

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDockerCaddyServesWildcardWithInternalTLS runs the pinned Caddy
// image on a rendered wildcard config and checks what Cloudflare would
// see as the origin: a certificate for *.example.com from Caddy's local
// CA, and the upstream receiving the original Host header. A concrete
// host under the wildcard keeps its own block and wins.
func TestDockerCaddyServesWildcardWithInternalTLS(t *testing.T) {
	requireDocker(t)
	withServerBaseURL(t, "https://stacked.rest")

	rows := sanitizeDomains([]cachedDomain{
		// Test-only upstreams: echo sites appended below, on loopback
		// inside the same container.
		{Domain: "*.example.com", ServiceID: "127.0.0.1", Port: 8081, TLSMode: tlsModeInternal},
		{Domain: "api.example.com", ServiceID: "127.0.0.1", Port: 8082, TLSMode: tlsModeInternal},
	})
	if len(rows) != 2 {
		t.Fatalf("sanitizeDomains dropped rows: %+v", rows)
	}
	content, err := generateCaddyfileChecked(rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	content += "http://:8081 {\n    respond \"wildcard host={host}\"\n}\n\nhttp://:8082 {\n    respond \"concrete host={host}\"\n}\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	name := "stacked-wildcard-test-" + randSuffix(t)
	out, err := exec.Command("docker", "run", "-d", "--name", name,
		"-p", "127.0.0.1::443",
		"-v", path+":/etc/caddy/Caddyfile:ro",
		CaddyImage, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	portOut, err := exec.Command("docker", "port", name, "443/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	addr := strings.TrimSpace(strings.SplitN(string(portOut), "\n", 2)[0])

	get := func(host string) (string, *tls.ConnectionState, error) {
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				// Cloudflare's "Full" mode doesn't verify the origin
				// certificate, so neither does this client.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec // see above
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			},
		}
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			return "", nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), resp.TLS, err
	}

	var body string
	var state *tls.ConnectionState
	deadline := time.Now().Add(30 * time.Second)
	for {
		body, state, err = get("preview-123.example.com")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("request to wildcard host: %v\n%s", err, logs)
	}
	if body != "wildcard host=preview-123.example.com" {
		t.Fatalf("upstream should see the original Host, got %q", body)
	}
	leaf := state.PeerCertificates[0]
	if !strings.Contains(strings.Join(leaf.DNSNames, ","), "*.example.com") {
		t.Fatalf("expected a *.example.com certificate, got SANs %v", leaf.DNSNames)
	}
	if !strings.Contains(leaf.Issuer.CommonName, "Caddy Local Authority") {
		t.Fatalf("expected Caddy's local CA as issuer, got %q", leaf.Issuer.CommonName)
	}

	body, _, err = get("api.example.com")
	if err != nil {
		t.Fatalf("request to concrete host: %v", err)
	}
	if body != "concrete host=api.example.com" {
		t.Fatalf("concrete host should win over the wildcard, got %q", body)
	}
}
