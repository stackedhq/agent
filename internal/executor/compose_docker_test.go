package executor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Docker-backed tests. They use the real Compose parser as the YAML parser
// and real containers to compare env across deploy paths. Opt in with
// STACKED_DOCKER_TESTS=1 (needs a local docker daemon + compose plugin);
// they create uniquely named containers/projects and remove them.

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("STACKED_DOCKER_TESTS") != "1" {
		t.Skip("set STACKED_DOCKER_TESTS=1 to run docker-backed tests")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func dockerOut(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// ensureStackedNetwork creates the external `stacked` network the compose
// files reference, removing it afterwards if this test created it.
func ensureStackedNetwork(t *testing.T) {
	t.Helper()
	if exec.Command("docker", "network", "inspect", "stacked").Run() == nil {
		return
	}
	if out, err := exec.Command("docker", "network", "create", "stacked").CombinedOutput(); err != nil {
		t.Fatalf("network create: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", "stacked").Run() })
}

// composeConfigJSON parses a project with `docker compose config` and
// returns the decoded document.
func composeConfigJSON(t *testing.T, dir string, args []string) map[string]interface{} {
	t.Helper()
	out := dockerOut(t, dir, nil, append(args, "config", "--format", "json")...)
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &doc); err != nil {
		t.Fatalf("decode config: %v\n%s", err, out)
	}
	delete(doc, "name")
	return doc
}

// TestDockerComposeGoldenMatchesLegacy proves the YAML emitter is
// semantically identical to the old hand-written templates for normal
// input: both are parsed by `docker compose config` (which also inlines the
// legacy `env_file: .env` into `environment`) and compared.
func TestDockerComposeGoldenMatchesLegacy(t *testing.T) {
	requireDocker(t)
	legacyEnv, err := os.ReadFile(filepath.Join("testdata", "compose_legacy", "service.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			project := "stk-golden-" + randSuffix(t)

			legacyDir := filepath.Join(t.TempDir(), project)
			if err := os.MkdirAll(legacyDir, 0o755); err != nil {
				t.Fatal(err)
			}
			legacy, err := os.ReadFile(filepath.Join("testdata", "compose_legacy", c.legacy))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(legacyDir, "docker-compose.yml"), legacy, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(legacyDir, ".env"), legacyEnv, 0o644); err != nil {
				t.Fatal(err)
			}

			newDir := filepath.Join(t.TempDir(), project)
			if err := os.MkdirAll(newDir, 0o755); err != nil {
				t.Fatal(err)
			}
			rendered, err := c.render()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(newDir, "docker-compose.yml"), []byte(rendered), 0o644); err != nil {
				t.Fatal(err)
			}

			// The legacy layout was invoked as plain `docker compose` in the
			// dir; the new one with composeArgs.
			got := composeConfigJSON(t, newDir, composeArgs(newDir))
			want := composeConfigJSON(t, legacyDir, []string{"compose", "-p", project, "-f", filepath.Join(legacyDir, "docker-compose.yml")})
			for _, doc := range []map[string]interface{}{got, want} {
				services, _ := doc["services"].(map[string]interface{})
				for _, svc := range services {
					m := svc.(map[string]interface{})
					for _, k := range c.ignore {
						delete(m, k)
					}
				}
			}
			if !reflect.DeepEqual(got, want) {
				g, _ := json.MarshalIndent(got, "", "  ")
				w, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("parsed compose differs from legacy template\n--- new\n%s\n--- legacy\n%s", g, w)
			}
		})
	}
}

// TestDockerProjectEnvFileIgnored is the Step 0 regression: a `.env` in the
// project dir must not be able to redirect compose (COMPOSE_FILE,
// COMPOSE_PROJECT_NAME) or feed interpolation.
func TestDockerProjectEnvFileIgnored(t *testing.T) {
	requireDocker(t)
	dir := filepath.Join(t.TempDir(), "stk-dotenv-"+randSuffix(t))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := generateCompose(goldenServiceID, "alpine:3", nil, resourceLimits{restartPolicy: "no"}, nil, "", map[string]string{"A": "${X:-unset}"})
	files := map[string]string{
		"docker-compose.yml": compose,
		"evil.yml":           "services:\n  evil:\n    image: busybox\n",
		".env":               "COMPOSE_FILE=evil.yml\nCOMPOSE_PROJECT_NAME=other\nX=fromdotenv\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := dockerOut(t, dir, append(os.Environ(), "X=fromagentenv"), append(composeArgs(dir), "config", "--format", "json")...)
	var doc struct {
		Name     string                     `json:"name"`
		Services map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if doc.Name != filepath.Base(dir) {
		t.Fatalf("project name = %q, want %q", doc.Name, filepath.Base(dir))
	}
	if _, ok := doc.Services["evil"]; ok || len(doc.Services) != 1 {
		t.Fatalf(".env COMPOSE_FILE was honoured: %s", out)
	}
	if !strings.Contains(out, `"A": "$${X:-unset}"`) && !strings.Contains(out, `"A": "${X:-unset}"`) {
		t.Fatalf("env value was interpolated: %s", out)
	}
}

var trickyEnv = map[string]string{
	"PLAIN":      "hello",
	"DOLLAR":     "a$X-b",
	"BRACE":      "${X}c",
	"DOUBLE":     "$$X",
	"SQUOTED":    "'single $X quoted'",
	"DQUOTED":    `"double $X quoted"`,
	"HASH":       "a #comment",
	"SPACES":     "  padded  ",
	"EMPTY":      "",
	"EQUALS":     "k=v=w",
	"UNICODE":    "zażółć ✓",
	"BACKSLASH":  `C:\path\n`,
	"MULTILINE":  "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n",
	"CRLF":       "line1\r\nline2",
	"YAMLISH":    "a: b\n- c\n{d: e}",
	"SMTP_FROM":  "Riffado <noreply@riffado.com>",
	"HOST":       "0.0.0.0",
	"LEADING_EQ": "=x",
}

func containerEnv(t *testing.T, name string) map[string]string {
	t.Helper()
	out := dockerOut(t, "", nil, "inspect", "--format", "{{json .Config.Env}}", name)
	var list []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &list); err != nil {
		t.Fatalf("decode env: %v %s", err, out)
	}
	env := map[string]string{}
	for _, kv := range list {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	return env
}

// TestDockerEnvParityComposeVsDockerRun deploys the same env through the
// compose (recreate / fast-restart) path and the `docker run` (blue/green,
// release) path and checks both containers see exactly the stored values.
func TestDockerEnvParityComposeVsDockerRun(t *testing.T) {
	requireDocker(t)
	ensureStackedNetwork(t)
	suffix := randSuffix(t)
	name := "stk-envtest-" + suffix
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	env, warnings := serviceEnv(trickyEnv)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// Compose path.
	compose := generateCompose(name, "alpine:3", nil, resourceLimits{restartPolicy: "no"}, nil, "sleep 300", env)
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", composeArgs(dir, "down", "-t", "0")...).Run()
	})
	dockerOut(t, dir, nil, composeArgs(dir, "up", "-d")...)

	// docker run path.
	runEnv, envPath, err := writeServiceEnvFileAt(dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(runEnv.PassKeys) != 3 { // MULTILINE, CRLF, YAMLISH
		t.Fatalf("expected 3 pass-through keys, got %v", runEnv.PassKeys)
	}
	runName := name + "-run"
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", runName).Run() })
	args := []string{"run", "-d", "--name", runName}
	args = append(args, runEnv.Args(envPath)...)
	args = append(args, "alpine:3", "sleep", "300")
	dockerOut(t, "", runEnv.CommandEnv(), args...)

	composeGot := containerEnv(t, name)
	runGot := containerEnv(t, runName)
	for k, want := range env {
		if composeGot[k] != want {
			t.Errorf("compose env %s = %q, want %q", k, composeGot[k], want)
		}
		if runGot[k] != want {
			t.Errorf("docker run env %s = %q, want %q", k, runGot[k], want)
		}
	}
}

// writeServiceEnvFileAt is writeServiceEnvFile without the private-root
// directory handling, for temp dirs.
func writeServiceEnvFileAt(dir string, env map[string]string) (dockerRunEnv, string, error) {
	d, err := dockerRunEnvFor(env)
	if err != nil {
		return d, "", err
	}
	path := filepath.Join(dir, serviceEnvFileName)
	return d, path, os.WriteFile(path, []byte(d.FileContent), 0o600)
}

// TestDockerRedisPasswordNotInArgv brings up the generated redis compose
// and checks auth works with an awkward password, the server runs as the
// image's redis user, and no process argv contains the password.
func TestDockerRedisPasswordNotInArgv(t *testing.T) {
	requireDocker(t)
	ensureStackedNetwork(t)
	suffix := randSuffix(t)
	dir := filepath.Join(t.TempDir(), "stk-redis-"+suffix)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	password := `p"a$X s\w'o#rd` + suffix
	container := "stk-redis-test-" + suffix
	compose, err := generateDatabaseCompose("redis", 0, container, "redis:7-alpine", map[string]string{"password": password}, "internal", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compose, "--requirepass") {
		t.Fatalf("compose still passes --requirepass:\n%s", compose)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", composeArgs(dir, "down", "-v", "-t", "0")...).Run()
	})
	dockerOut(t, dir, nil, composeArgs(dir, "up", "-d")...)

	var pong string
	for i := 0; i < 30; i++ {
		cmd := exec.Command("docker", "exec", "-e", "REDISCLI_AUTH="+password, container, "redis-cli", "ping")
		out, _ := cmd.CombinedOutput()
		pong = strings.TrimSpace(string(out))
		if pong == "PONG" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if pong != "PONG" {
		t.Fatalf("redis auth with the generated password failed: %q", pong)
	}
	noauth, _ := exec.Command("docker", "exec", container, "redis-cli", "ping").CombinedOutput()
	if !strings.Contains(string(noauth), "NOAUTH") {
		t.Fatalf("redis accepted an unauthenticated ping: %s", noauth)
	}
	top := dockerOut(t, "", nil, "top", container, "-o", "pid,user,args")
	if strings.Contains(top, suffix) {
		t.Fatalf("password visible in process list:\n%s", top)
	}
	inspect := dockerOut(t, "", nil, "inspect", "--format", "{{json .Config.Cmd}}", container)
	if strings.Contains(inspect, suffix) {
		t.Fatalf("password in container Cmd: %s", inspect)
	}
	lines := strings.Split(strings.TrimSpace(top), "\n")
	sort.Strings(lines)
	for _, l := range lines {
		fields := strings.Fields(l)
		if strings.Contains(l, "redis-server") && len(fields) > 1 && (fields[1] == "root" || fields[1] == "0") {
			t.Fatalf("redis-server runs as root:\n%s", top)
		}
	}
}

// TestDockerLegacyComposeSeesSyncedEnv: a service still on the old
// compose template (env_file: .env) that is deployed blue/green gets its
// `.env` rewritten, so the real Compose parser resolves the new values.
func TestDockerLegacyComposeSeesSyncedEnv(t *testing.T) {
	requireDocker(t)
	ensureStackedNetwork(t)
	dir := filepath.Join(t.TempDir(), "stk-legacyenv-"+randSuffix(t))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(filepath.Join("testdata", "compose_legacy", "service-min.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncLegacyEnvFile(dir, map[string]string{"API_KEY": "new", "HOST": "0.0.0.0"}); err != nil {
		t.Fatal(err)
	}
	doc := composeConfigJSON(t, dir, composeArgs(dir))
	svc := doc["services"].(map[string]interface{})[goldenServiceID].(map[string]interface{})
	env := svc["environment"].(map[string]interface{})
	if env["API_KEY"] != "new" || env["HOST"] != "0.0.0.0" {
		t.Fatalf("compose resolved env %v, want the synced values", env)
	}
}

// TestDockerBlueGreenRefreshedComposeEnv: after a recreate deploy wrote an
// `environment:` map, a blue/green deploy regenerates docker-compose.yml so
// the real Compose parser (what a Restart fallback uses) sees the new env.
func TestDockerBlueGreenRefreshedComposeEnv(t *testing.T) {
	requireDocker(t)
	ensureStackedNetwork(t)
	dir := filepath.Join(t.TempDir(), "stk-bgenv-"+randSuffix(t))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := generateCompose(goldenServiceID, "alpine:3", nil, resourceLimits{restartPolicy: "no"}, nil, "", map[string]string{"API_KEY": "old", "GONE": "1"})
	if err := writeFile(filepath.Join(dir, "docker-compose.yml"), old); err != nil {
		t.Fatal(err)
	}
	if err := refreshBlueGreenCompose(dir, goldenServiceID, "alpine:3", nil, nil, map[string]string{"API_KEY": "new", "HOST": "0.0.0.0"}); err != nil {
		t.Fatal(err)
	}
	doc := composeConfigJSON(t, dir, composeArgs(dir))
	svc := doc["services"].(map[string]interface{})[goldenServiceID].(map[string]interface{})
	env := svc["environment"].(map[string]interface{})
	if len(env) != 2 || env["API_KEY"] != "new" || env["HOST"] != "0.0.0.0" {
		t.Fatalf("compose resolved env %v, want the blue/green deploy's env", env)
	}
}
