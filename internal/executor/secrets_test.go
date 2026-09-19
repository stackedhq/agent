package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSecretFileModes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "svc")
	path := filepath.Join(dir, ".env")
	if err := writeSecretFile(path, "SECRET=s3cret\n"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("service dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
}

func TestWriteFilePublicModesLeaveSecretParent(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "svc")
	if err := writeSecretFile(filepath.Join(dir, ".env"), "A=1\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, "docker-compose.yml"), "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	compose, err := os.Stat(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if compose.Mode().Perm() != 0o644 {
		t.Fatalf("compose mode = %o, want 0644", compose.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("secret parent widened to %o", dirInfo.Mode().Perm())
	}
}

func TestWriteSecretFileTightensExistingWorldReadable(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "svc")
	path := filepath.Join(dir, ".env")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("OLD=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(path, "NEW=2\n"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode = %o after rewrite, want 0600", info.Mode().Perm())
	}
	dirInfo, _ := os.Stat(dir)
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o after rewrite, want 0700", dirInfo.Mode().Perm())
	}
}

func TestReconcileSecretPermissionsTightensExisting(t *testing.T) {
	root := t.TempDir()
	svcRoot := filepath.Join(root, "services")
	dbRoot := filepath.Join(root, "databases")
	gateDir := filepath.Join(root, "gate")

	svc := filepath.Join(svcRoot, "svc-1")
	if err := os.MkdirAll(svc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svc, ".env"), []byte("K=v\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dbRoot, "db-1")
	if err := os.MkdirAll(db, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "docker-compose.yml"), []byte("POSTGRES_PASSWORD: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(gateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gateDir, "config.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	tightenServiceSecrets(svcRoot)
	tightenDatabaseSecrets(dbRoot)
	tightenGateSecrets(gateDir)

	assertMode(t, svc, 0o700)
	assertMode(t, filepath.Join(svc, ".env"), 0o600)
	assertMode(t, db, 0o700)
	assertMode(t, filepath.Join(db, "docker-compose.yml"), 0o600)
	assertMode(t, gateDir, 0o700)
	assertMode(t, filepath.Join(gateDir, "config.json"), 0o600)
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
	}
}

func TestParseGitRemoteStripsUserinfo(t *testing.T) {
	got := parseGitRemote("https://x-access-token:ghs_supersecret@github.com/acme/app.git")
	if got.CleanURL != "https://github.com/acme/app.git" {
		t.Fatalf("clean URL = %q", got.CleanURL)
	}
	if got.Username != "x-access-token" || got.Password != "ghs_supersecret" {
		t.Fatalf("auth = %+v", got)
	}
	if gitRemoteContainsUserinfo(got.CleanURL) {
		t.Fatal("clean URL still has userinfo")
	}
}

func TestParseGitRemotePlainHTTPS(t *testing.T) {
	got := parseGitRemote("https://github.com/acme/app.git")
	if got.CleanURL != "https://github.com/acme/app.git" {
		t.Fatalf("clean URL = %q", got.CleanURL)
	}
	if got.Password != "" {
		t.Fatalf("unexpected password %q", got.Password)
	}
}

func TestStartGitAuthKeepsTokenOffEnvValues(t *testing.T) {
	remote := parseGitRemote("https://x-access-token:ghs_only_in_file@github.com/acme/app.git")
	session, err := startGitAuth(remote)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, kv := range session.env() {
		if strings.Contains(kv, "ghs_only_in_file") {
			t.Fatalf("token leaked into git env: %s", kv)
		}
	}
	body, err := os.ReadFile(filepath.Join(session.dir, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ghs_only_in_file") {
		t.Fatal("secret file missing token")
	}
	info, err := os.Stat(filepath.Join(session.dir, "secret"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode = %v", info.Mode())
	}
}

func TestSanitizeGitRemoteStripsCredentials(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	if out, err := runCommandSilent(dir, "git", "init"); err != nil {
		t.Fatalf("git init: %s: %v", out, err)
	}
	dirty := "https://x-access-token:ghs_should_not_persist@github.com/acme/app.git"
	if out, err := runCommandSilent(dir, "git", "remote", "add", "origin", dirty); err != nil {
		t.Fatalf("git remote add: %s: %v", out, err)
	}
	if err := sanitizeGitRemote(dir, "https://github.com/acme/app.git"); err != nil {
		t.Fatal(err)
	}
	out, err := runCommandSilent(dir, "git", "config", "--get", "remote.origin.url")
	if err != nil {
		t.Fatalf("git config: %s: %v", out, err)
	}
	url := strings.TrimSpace(out)
	if gitRemoteContainsUserinfo(url) || strings.Contains(url, "ghs_should_not_persist") || strings.Contains(url, "x-access-token") {
		t.Fatalf("remote still dirty: %q", url)
	}
	if url != "https://github.com/acme/app.git" {
		t.Fatalf("remote = %q", url)
	}
}

func TestNixpacksBuildArgsOmitSecretValues(t *testing.T) {
	args, extra := nixpacksBuildArgs("/repo", "stacked-svc", "bun run build", "", map[string]string{
		"DATABASE_URL": "postgres://u:supersecret@db/app",
		"HOST":         "0.0.0.0",
	})
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, "supersecret") || strings.Contains(joined, "postgres://") {
		t.Fatalf("secret leaked into argv: %v", args)
	}
	hasDB := false
	hasHost := false
	for i, a := range args {
		if a == "--env" && i+1 < len(args) {
			if args[i+1] == "DATABASE_URL" {
				hasDB = true
			}
			if args[i+1] == "HOST" {
				hasHost = true
			}
			if strings.Contains(args[i+1], "=") {
				t.Fatalf("--env value on argv: %q", args[i+1])
			}
		}
	}
	if !hasDB || !hasHost {
		t.Fatalf("missing --env keys: %v", args)
	}
	found := false
	for _, e := range extra {
		if e == "DATABASE_URL=postgres://u:supersecret@db/app" {
			found = true
		}
	}
	if !found {
		t.Fatalf("secret missing from process env overlay: %v", extra)
	}
}

func TestSystemdUnitSetsUmask(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "stacked-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "UMask=0077") {
		t.Fatal("packaging/stacked-agent.service missing UMask=0077")
	}
}
