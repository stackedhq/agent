package executor

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseGitSource(t *testing.T) {
	cases := []struct {
		in   string
		want gitSource
	}{
		{"https://github.com/acme/api.git", gitSource{URL: "https://github.com/acme/api.git"}},
		{"https://x-access-token:ghs_abc@github.com/acme/api.git", gitSource{URL: "https://github.com/acme/api.git", Username: "x-access-token", Password: "ghs_abc"}},
		{"https://oauth2:glpat-123@gitlab.com/acme/api.git", gitSource{URL: "https://gitlab.com/acme/api.git", Username: "oauth2", Password: "glpat-123"}},
		{"https://tok3n@git.example.com/a/b", gitSource{URL: "https://git.example.com/a/b", Username: "x-access-token", Password: "tok3n"}},
	}
	for _, c := range cases {
		got, err := parseGitSource(c.in)
		if err != nil {
			t.Errorf("parseGitSource(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseGitSource(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if strings.Contains(got.URL, "@") {
			t.Errorf("credentials left in URL: %q", got.URL)
		}
	}
	for _, bad := range []string{
		"", "git@github.com:acme/api.git", "ssh://git@github.com/acme/api.git", "http://github.com/a/b",
		"file:///etc", "/etc/passwd", "acme/api", "ext::sh -c id", "--upload-pack=id", "https:///nohost",
		"https://-oProxyCommand=x/a",
	} {
		if _, err := parseGitSource(bad); err == nil {
			t.Errorf("parseGitSource(%q) accepted", bad)
		}
	}
}

func TestGitArgvConstruction(t *testing.T) {
	if got, want := gitCloneArgs("main", "https://github.com/a/b.git", "repo"),
		[]string{"-c", "credential.helper=", "clone", "--branch", "main", "--single-branch", "--", "https://github.com/a/b.git", "repo"}; !reflect.DeepEqual(got, want) {
		t.Errorf("clone args = %v", got)
	}
	if got, want := gitFetchBranchArgs("feature/x"),
		[]string{"-c", "credential.helper=", "fetch", "--", "origin", "+refs/heads/feature/x:refs/remotes/origin/feature/x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("fetch args = %v", got)
	}
	if got, want := gitResetArgs("dev"), []string{"reset", "--hard", "refs/remotes/origin/dev", "--"}; !reflect.DeepEqual(got, want) {
		t.Errorf("reset args = %v", got)
	}
	if got, want := gitCheckoutArgs("abc1234", true), []string{"checkout", "--detach", "--end-of-options", "abc1234", "--"}; !reflect.DeepEqual(got, want) {
		t.Errorf("checkout args = %v", got)
	}
	if got, want := gitCheckoutArgs("abc1234", false), []string{"checkout", "--detach", "abc1234", "--"}; !reflect.DeepEqual(got, want) {
		t.Errorf("checkout args (old git) = %v", got)
	}
	if got := gitSetRemoteArgs("https://github.com/a/b.git"); strings.Contains(strings.Join(got, " "), "@") {
		t.Errorf("set-url carries credentials: %v", got)
	}
}

func TestGitVersionAtLeast(t *testing.T) {
	for out, want := range map[string]bool{
		"git version 2.24.0\n":               true,
		"git version 2.54.0 (Apple Git-157)": true,
		"git version 2.23.4":                 false,
		"git version 1.9.1":                  false,
		"git version 3.0.0":                  true,
		"garbage":                            false,
	} {
		if got := gitVersionAtLeast(out, 2, 24); got != want {
			t.Errorf("gitVersionAtLeast(%q) = %v, want %v", out, got, want)
		}
	}
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func withGitConfigCount(t *testing.T, supported bool) {
	t.Helper()
	orig := gitConfigCountSupported
	gitConfigCountSupported = func() bool { return supported }
	t.Cleanup(func() { gitConfigCountSupported = orig })
}

func TestGitSessionEnv(t *testing.T) {
	t.Setenv("GIT_ALLOW_PROTOCOL", "ext:file:https")
	withGitConfigCount(t, true)
	s, err := newGitSession(gitSource{URL: "https://github.com/a/b.git", Username: "x-access-token", Password: "ghs_secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v, _ := envValue(s.env, "GIT_ALLOW_PROTOCOL"); v != "https" {
		t.Fatalf("GIT_ALLOW_PROTOCOL = %q", v)
	}
	count := 0
	for _, kv := range s.env {
		if strings.HasPrefix(kv, "GIT_ALLOW_PROTOCOL=") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("GIT_ALLOW_PROTOCOL set %d times", count)
	}
	if v, _ := envValue(s.env, "GIT_TERMINAL_PROMPT"); v != "0" {
		t.Fatalf("GIT_TERMINAL_PROMPT = %q", v)
	}
	if _, ok := envValue(s.env, "GIT_ASKPASS"); ok {
		t.Fatal("GIT_ASKPASS must not be set: the askpass helper is gone")
	}
	want := map[string]string{
		"GIT_CONFIG_COUNT":   "1",
		"GIT_CONFIG_KEY_0":   "http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0": "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_secret")),
	}
	for k, v := range want {
		if got, _ := envValue(s.env, k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	if _, ok := envValue(s.env, "GIT_CONFIG_PARAMETERS"); ok {
		t.Fatal("GIT_CONFIG_PARAMETERS must not be set alongside GIT_CONFIG_COUNT")
	}

	// Old git (< 2.31): same header via GIT_CONFIG_PARAMETERS only.
	withGitConfigCount(t, false)
	old, err := newGitSession(gitSource{URL: "https://git.example.com:8443/a/b", Username: "oauth2", Password: "glpat-1"})
	if err != nil {
		t.Fatal(err)
	}
	wantParam := "'http.https://git.example.com:8443/.extraheader'='Authorization: Basic " +
		base64.StdEncoding.EncodeToString([]byte("oauth2:glpat-1")) + "'"
	if got, _ := envValue(old.env, "GIT_CONFIG_PARAMETERS"); got != wantParam {
		t.Fatalf("GIT_CONFIG_PARAMETERS = %q, want %q", got, wantParam)
	}
	if _, ok := envValue(old.env, "GIT_CONFIG_COUNT"); ok {
		t.Fatal("GIT_CONFIG_COUNT set on old git")
	}

	// Public repo: no credentials, still https-only.
	pub, err := newGitSession(gitSource{URL: "https://github.com/a/b.git"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_ASKPASS"} {
		if _, ok := envValue(pub.env, k); ok {
			t.Fatalf("%s set without credentials", k)
		}
	}
	if v, _ := envValue(pub.env, "GIT_ALLOW_PROTOCOL"); v != "https" {
		t.Fatalf("GIT_ALLOW_PROTOCOL = %q", v)
	}
}

// TestGitCloneSendsAuthHeaderFromEnv clones over (dumb) HTTPS from a
// test server that requires the Authorization header, in both the
// GIT_CONFIG_COUNT and GIT_CONFIG_PARAMETERS modes, and checks the token
// is neither in argv nor persisted in .git/config.
func TestGitCloneSendsAuthHeaderFromEnv(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	gitEnv := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t",
		"GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_NOSYSTEM=1", "HOME="+root)
	run := func(dir string, env []string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	work := filepath.Join(root, "work")
	_ = os.Mkdir(work, 0o755)
	run(work, gitEnv, "init", "-q", "-b", "main")
	run(work, gitEnv, "commit", "-q", "--allow-empty", "-m", "init")
	bare := filepath.Join(root, "bare.git")
	run(root, gitEnv, "clone", "-q", "--bare", work, bare)
	run(bare, gitEnv, "update-server-info")

	const token = "ghs_supersecret"
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	files := http.StripPrefix("/acme/app.git", http.FileServer(http.Dir(bare)))
	// Handlers run on server goroutines (and may still be finishing a
	// previous clone's request), so the counter must be atomic.
	var authed atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		files.ServeHTTP(w, r)
	}))
	defer srv.Close()

	for _, countMode := range []bool{true, false} {
		withGitConfigCount(t, countMode)
		src, err := parseGitSource("https://x-access-token:" + token + "@" + strings.TrimPrefix(srv.URL, "https://") + "/acme/app.git")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := newGitSession(src)
		if err != nil {
			t.Fatal(err)
		}
		env := append(mergeEnv(sess.env, []string{"GIT_CONFIG_NOSYSTEM=1", "HOME=" + root}), "GIT_SSL_NO_VERIFY=true")
		dest := fmt.Sprintf("clone-%v", countMode)
		args := gitCloneArgs("main", src.URL, dest)
		for _, a := range args {
			if strings.Contains(a, token) {
				t.Fatalf("token in argv: %v", args)
			}
		}
		authed.Store(0)
		run(root, env, args...)
		if authed.Load() == 0 {
			t.Fatalf("countMode=%v: server never saw the auth header", countMode)
		}
		cfg, err := os.ReadFile(filepath.Join(root, dest, ".git", "config"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(cfg), token) || strings.Contains(string(cfg), "extraheader") ||
			strings.Contains(string(cfg), strings.TrimPrefix(wantAuth, "Basic ")) {
			t.Fatalf("credentials persisted in .git/config:\n%s", cfg)
		}
	}

	// Without the session env the server refuses the clone.
	plain, _ := parseGitSource(srv.URL + "/acme/app.git")
	cmd := exec.Command("git", gitCloneArgs("main", plain.URL, "anon")...)
	cmd.Dir = root
	cmd.Env = append(mergeEnv(os.Environ(), []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "HOME=" + root}), "GIT_SSL_NO_VERIFY=true")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("anonymous clone succeeded: %s", out)
	}
}

// TestGitBranchSwitchOnSingleBranchClone reproduces the branch-change bug:
// a --single-branch clone only fetches its original branch, so the deploy
// must fetch the new branch with an explicit refspec before resetting.
// Uses a local repo (protocol restriction lifted for the test only).
func TestGitBranchSwitchOnSingleBranchClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_NOSYSTEM=1", "HOME="+root)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	run(src, "init", "-q", "-b", "main")
	run(src, "commit", "-q", "--allow-empty", "-m", "main")
	run(src, "checkout", "-q", "-b", "dev")
	run(src, "commit", "-q", "--allow-empty", "-m", "dev")
	devSha := run(src, "rev-parse", "HEAD")
	run(src, "checkout", "-q", "main")

	run(root, gitCloneArgs("main", src, "repo")...)
	repo := filepath.Join(root, "repo")
	run(repo, gitSetRemoteArgs(src)...)
	run(repo, gitFetchBranchArgs("dev")...)
	run(repo, gitResetArgs("dev")...)
	if got := run(repo, "rev-parse", "HEAD"); got != devSha {
		t.Fatalf("HEAD = %s, want dev tip %s", got, devSha)
	}
	run(repo, gitCheckoutArgs(devSha[:7], gitSupportsEndOfOptions())...)
	if got := run(repo, "rev-parse", "HEAD"); got != devSha {
		t.Fatalf("detached HEAD = %s, want %s", got, devSha)
	}
}

func TestNixpacksBuildArgsKeepSecretsOutOfArgv(t *testing.T) {
	args, env := nixpacksBuildArgs("/r", "stacked-x", "npm run build", "-rf start", map[string]string{
		"API_TOKEN":     "s3cret",
		"MULTI":         "a\nb",
		"NIXPACKS_NODE": "20",
		"PATH":          "/custom",
		"BAD-KEY":       "x",
	})
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, "s3cret") || strings.Contains(joined, "a\nb") {
		t.Fatalf("secret in argv: %q", args)
	}
	for _, want := range []string{"--env=API_TOKEN", "--env=MULTI", "--env=NIXPACKS_NODE=20", "--env=PATH=/custom", "--build-cmd=npm run build", "--start-cmd=-rf start"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, args)
		}
	}
	if strings.Contains(joined, "BAD-KEY") {
		t.Errorf("invalid key passed: %q", args)
	}
	if v, _ := envValue(env, "API_TOKEN"); v != "s3cret" {
		t.Fatalf("API_TOKEN not in process env")
	}
	if v, _ := envValue(env, "PATH"); v == "/custom" {
		t.Fatal("user PATH leaked into the nixpacks process env")
	}
	if _, env := nixpacksBuildArgs("/r", "x", "", "", map[string]string{"PATH": "/p"}); env != nil {
		t.Fatal("expected inherited env when nothing is passed via env")
	}
}
