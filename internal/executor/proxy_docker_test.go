package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDockerCaddyValidatesQuotedPaths renders a Caddyfile with route
// paths outside the bare-token charset (quoted), a gated host, the
// docker host alias and a UUID upstream, then runs the pinned Caddy
// image's `caddy validate` and `caddy adapt` on it.
func TestDockerCaddyValidatesQuotedPaths(t *testing.T) {
	requireDocker(t)
	withServerBaseURL(t, "https://stacked.rest")
	withMachineID(t, "3f2a1b4c-1d2e-4f5a-8b9c-0d1e2f3a4b5c")

	rows := sanitizeDomains([]cachedDomain{
		{Domain: "app.example.com", ServiceID: "3f2a1b4c-1d2e-4f5a-8b9c-0d1e2f3a4b5c", Port: 3000, Path: "/api%20v1"},
		{Domain: "app.example.com", ServiceID: "svc-b", Port: 3000, Path: "/a'b(c)[d]<e>|f^g!$&+,;=:@", StripPrefix: boolPtr(false)},
		{Domain: "app.example.com", ServiceID: "svc-c", Port: 3000, Path: "/<<EOF"},
		{Domain: "app.example.com", ServiceID: "svc-d", Port: 3000, Path: "/plain-path_1.2~x"},
		{Domain: "app.example.com", ServiceID: "svc-root", Port: 3000},
		gatedRow("gated.example.com", "/", "admin", "$2a$10$aaaa"),
		{Domain: "hdi.example.com", Host: "host.docker.internal", Port: 8080, Scheme: "http", OnDemandTLS: true},
		{Domain: "uuid.example.com", Host: "3f2a1b4c-1d2e-4f5a-8b9c-0d1e2f3a4b5c", Port: 3000, Scheme: "http"},
	})
	if len(rows) != 8 {
		t.Fatalf("sanitizeDomains dropped rows: %+v", rows)
	}
	content, err := generateCaddyfileChecked(rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, `handle_path "/api%20v1*" {`) || !strings.Contains(content, `handle "/a'b(c)[d]<e>|f^g!$&+,;=:@*" {`) {
		t.Fatalf("quoted matchers missing:\n%s", content)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := exec.Command("docker", append([]string{"run", "--rm", "-v", path + ":/etc/caddy/Caddyfile:ro", CaddyImage}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("caddy %s: %v\n%s\n--- Caddyfile ---\n%s", strings.Join(args, " "), err, out, content)
		}
		return string(out)
	}
	run("caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
	adapted := run("caddy", "adapt", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
	// The quotes are Caddyfile syntax, not part of the matcher.
	for _, want := range []string{`"/api%20v1*"`, `"/a'b(c)[d]\u003ce\u003e|f^g!$\u0026+,;=:@*"`, `"/\u003c\u003cEOF*"`} {
		if !strings.Contains(adapted, want) {
			t.Errorf("adapted JSON missing path matcher %s:\n%s", want, adapted)
		}
	}
}
