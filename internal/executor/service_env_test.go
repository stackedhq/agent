package executor

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestServiceEnvInjectsHostAndDropsInvalid(t *testing.T) {
	env, warnings := serviceEnv(map[string]string{
		"OK":       "1",
		"BAD-KEY":  "x",
		"1BAD":     "x",
		"NUL":      "a\x00b",
		"MULTI":    "a\nb",
		"EMPTYVAL": "",
	})
	want := map[string]string{"OK": "1", "MULTI": "a\nb", "EMPTYVAL": "", "HOST": "0.0.0.0"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("serviceEnv = %v, want %v", env, want)
	}
	if len(warnings) != 3 {
		t.Fatalf("expected 3 warnings, got %v", warnings)
	}
	// An explicit HOST wins.
	env, _ = serviceEnv(map[string]string{"HOST": "127.0.0.1"})
	if env["HOST"] != "127.0.0.1" {
		t.Fatalf("explicit HOST overridden: %v", env)
	}
	// nil input still yields HOST.
	env, _ = serviceEnv(nil)
	if env["HOST"] != "0.0.0.0" {
		t.Fatalf("nil env: %v", env)
	}
}

func TestComposeEnvironmentIsSortedAndEscaped(t *testing.T) {
	out := renderYAML(yMap{{Key: "environment", Value: composeEnvironment(map[string]string{
		"B": "x$Y",
		"A": "line1\nline2",
	})}})
	want := "environment:\n  A: \"line1\\nline2\"\n  B: \"x$$Y\"\n"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestBuildEnvFileSkipsUnrepresentable(t *testing.T) {
	got := buildEnvFile(map[string]string{
		"A":     "1",
		"MULTI": "a\nb",
		"CR":    "a\r",
		"BAD-K": "x",
		"D":     "$X 'q' \"q\"",
	})
	want := "A=1\nD=$X 'q' \"q\"\n"
	if got != want {
		t.Fatalf("buildEnvFile = %q, want %q", got, want)
	}
}

func TestDockerRunEnvSplitsMultiline(t *testing.T) {
	d, err := dockerRunEnvFor(map[string]string{
		"A":   "1",
		"PEM": "-----BEGIN-----\nabc\n-----END-----",
		"CR":  "x\r\ny",
		"Z":   "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.FileContent != "A=1\nZ=\n" {
		t.Fatalf("file content = %q", d.FileContent)
	}
	if !reflect.DeepEqual(d.PassKeys, []string{"CR", "PEM"}) {
		t.Fatalf("pass keys = %v", d.PassKeys)
	}
	args := d.Args("/x/stacked.env")
	if !reflect.DeepEqual(args, []string{"--env-file=/x/stacked.env", "-e", "CR", "-e", "PEM"}) {
		t.Fatalf("args = %v", args)
	}
	for _, a := range args {
		if strings.Contains(a, "abc") {
			t.Fatalf("secret value in argv: %v", args)
		}
	}
	t.Setenv("PEM", "agent-value")
	cmdEnv := d.CommandEnv()
	var pem []string
	for _, kv := range cmdEnv {
		if strings.HasPrefix(kv, "PEM=") {
			pem = append(pem, kv)
		}
	}
	if len(pem) != 1 || pem[0] != "PEM=-----BEGIN-----\nabc\n-----END-----" {
		t.Fatalf("PEM in command env = %q", pem)
	}

	// Nothing multi-line: inherit the agent env untouched.
	d, _ = dockerRunEnvFor(map[string]string{"A": "1"})
	if d.CommandEnv() != nil {
		t.Fatal("expected nil command env without pass-through keys")
	}
}

func TestDockerRunEnvRejectsCLIOverridingMultiline(t *testing.T) {
	for _, k := range []string{"DOCKER_HOST", "docker_config", "PATH", "HOME", "LD_PRELOAD", "HTTPS_PROXY"} {
		if _, err := dockerRunEnvFor(map[string]string{k: "a\nb"}); err == nil {
			t.Errorf("multi-line %s accepted for the docker CLI env", k)
		}
		// Single-line values are fine: they go through the env file only.
		if _, err := dockerRunEnvFor(map[string]string{k: "ab"}); err != nil {
			t.Errorf("single-line %s rejected: %v", k, err)
		}
	}
}

func TestCleanupLegacyEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")

	// New-format compose: .env removed.
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(generateCompose(goldenServiceID, "img", nil, resourceLimits{restartPolicy: "no"}, nil, "", map[string]string{"A": "1"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupLegacyEnvFile(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf(".env should be removed, stat err = %v", err)
	}

	// Legacy compose still referencing it: kept, tightened to 0600.
	legacy, err := os.ReadFile(filepath.Join("testdata", "compose_legacy", "service-min.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("SECRET=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cleanupLegacyEnvFile(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf(".env must be kept for the legacy compose: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode = %o, want 0600", info.Mode().Perm())
	}

	// No .env: no-op.
	if err := os.Remove(envPath); err != nil {
		t.Fatal(err)
	}
	if err := cleanupLegacyEnvFile(dir); err != nil {
		t.Fatal(err)
	}
}

func TestComposeArgsPinProject(t *testing.T) {
	dir := "/opt/stacked/services/" + goldenServiceID
	got := composeArgs(dir, "up", "-d")
	want := []string{
		"compose", "-p", goldenServiceID,
		"-f", dir + "/docker-compose.yml",
		"--project-directory", dir,
		"--env-file", os.DevNull,
		"up", "-d",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composeArgs = %v\nwant %v", got, want)
	}
}

func TestEnsureDirAndWriteFilePrivateModes(t *testing.T) {
	base := t.TempDir()
	private := filepath.Join(base, "services")
	public := filepath.Join(base, "data")
	orig := privateDirRoots
	privateDirRoots = []string{private}
	t.Cleanup(func() { privateDirRoots = orig })

	// A pre-existing world-readable private root is tightened.
	if err := os.MkdirAll(private, 0o755); err != nil {
		t.Fatal(err)
	}
	svcDir := filepath.Join(private, "svc")
	if err := ensureDir(svcDir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{private, svcDir} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %o, want 0700", p, info.Mode().Perm())
		}
	}

	// Paths outside private roots keep 0755 (subject to umask).
	pubDir := filepath.Join(public, "x")
	if err := ensureDir(pubDir); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(pubDir); info.Mode().Perm()&0o700 != 0o700 || info.Mode().Perm() == 0o700 {
		t.Errorf("public dir mode = %o, want 0755-ish", info.Mode().Perm())
	}

	// writeFile: new files 0600, existing 0644 files tightened.
	f := filepath.Join(svcDir, "docker-compose.yml")
	if err := os.WriteFile(f, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(f, "new"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("existing file mode = %o, want 0600", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(f); string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
	g := filepath.Join(svcDir, "new.env")
	if err := writeFile(g, "x"); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(g); info.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %o, want 0600", info.Mode().Perm())
	}
}
