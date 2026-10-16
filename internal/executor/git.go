package executor

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Git plumbing for source deploys.
//
//   - The clone URL is stored and passed tokenless. Credentials reach git
//     through a GIT_ASKPASS helper that reads them from git's env, so the
//     token is never in argv (visible to every local user via ps) and never
//     in .git/config.
//   - GIT_ALLOW_PROTOCOL=https on every git command: no ssh://, git://,
//     ext::, or local/file clones, including via redirects or submodules.
//   - `--` / `--end-of-options` before positional args; branch and commit
//     are validated before use.

// gitSource is a parsed clone URL with credentials split out.
type gitSource struct {
	URL      string // tokenless https URL
	Username string
	Password string
}

func (g gitSource) hasCredentials() bool {
	return g.Password != ""
}

// parseGitSource accepts only https URLs and strips any userinfo.
func parseGitSource(raw string) (gitSource, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return gitSource{}, fmt.Errorf("unsupported git URL: only https:// clone URLs are allowed")
	}
	if strings.HasPrefix(u.Host, "-") {
		return gitSource{}, fmt.Errorf("unsupported git URL host")
	}
	var src gitSource
	if u.User != nil {
		src.Username = u.User.Username()
		src.Password, _ = u.User.Password()
		if src.Password == "" && src.Username != "" {
			// `https://<token>@host/...` form: the token is the username.
			src.Password = src.Username
			src.Username = "x-access-token"
		}
		if src.Username == "" {
			src.Username = "x-access-token"
		}
		u.User = nil
	}
	src.URL = u.String()
	return src, nil
}

// gitAskpassScript answers git's username/password prompts from env vars
// set only on the git process. It contains no secret itself.
const gitAskpassScript = `#!/bin/sh
case "$1" in
  Username*|username*) printf '%s\n' "$STACKED_GIT_USERNAME" ;;
  *) printf '%s\n' "$STACKED_GIT_PASSWORD" ;;
esac
`

// gitSession holds the env (and askpass helper) for one deploy's git calls.
type gitSession struct {
	env     []string
	tempDir string
}

// newGitSession prepares the git env. Call Close to remove the helper.
func newGitSession(src gitSource) (*gitSession, error) {
	s := &gitSession{}
	extra := []string{
		"GIT_ALLOW_PROTOCOL=https",
		"GIT_TERMINAL_PROMPT=0",
	}
	if src.hasCredentials() {
		dir, err := os.MkdirTemp("", "stacked-git-")
		if err != nil {
			return nil, fmt.Errorf("create askpass dir: %w", err)
		}
		s.tempDir = dir
		script := filepath.Join(dir, "askpass.sh")
		if err := os.WriteFile(script, []byte(gitAskpassScript), 0o700); err != nil {
			s.Close()
			return nil, fmt.Errorf("write askpass helper: %w", err)
		}
		extra = append(extra,
			"GIT_ASKPASS="+script,
			"STACKED_GIT_USERNAME="+src.Username,
			"STACKED_GIT_PASSWORD="+src.Password,
		)
	}
	s.env = mergeEnv(os.Environ(), extra)
	return s, nil
}

func (s *gitSession) Close() {
	if s != nil && s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir)
	}
}

// mergeEnv returns base with every name in extra replaced by extra's value.
func mergeEnv(base, extra []string) []string {
	override := make(map[string]struct{}, len(extra))
	for _, kv := range extra {
		name, _, _ := strings.Cut(kv, "=")
		override[name] = struct{}{}
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := override[name]; ok {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

// gitNoCredentialHelper disables any configured credential helper for the
// call, so the askpass answer is never persisted (e.g. by `store`) and a
// stale stored token is never used instead of the fresh one.
var gitNoCredentialHelper = []string{"-c", "credential.helper="}

func gitCloneArgs(branch, url, dest string) []string {
	args := append([]string{}, gitNoCredentialHelper...)
	return append(args, "clone", "--branch", branch, "--single-branch", "--", url, dest)
}

func gitSetRemoteArgs(url string) []string {
	return []string{"remote", "set-url", "origin", url}
}

// gitFetchBranchArgs fetches exactly the deploy branch into its
// remote-tracking ref. An explicit refspec matters for clones made with
// --single-branch: their default refspec only covers the original branch,
// so after the service's branch changes a plain `git fetch origin` would
// never create refs/remotes/origin/<new>.
func gitFetchBranchArgs(branch string) []string {
	args := append([]string{}, gitNoCredentialHelper...)
	return append(args, "fetch", "--", "origin", gitBranchRefspec(branch))
}

func gitBranchRefspec(branch string) string {
	return "+refs/heads/" + branch + ":refs/remotes/origin/" + branch
}

func gitResetArgs(branch string) []string {
	return []string{"reset", "--hard", "refs/remotes/origin/" + branch, "--"}
}

// gitCheckoutArgs detaches at sha. The trailing `--` makes git treat sha as
// a revision even if a file has the same name; `--end-of-options` (git
// 2.24+) is belt and braces on top of the hex validation.
func gitCheckoutArgs(sha string, endOfOptions bool) []string {
	args := []string{"checkout", "--detach"}
	if endOfOptions {
		args = append(args, "--end-of-options")
	}
	return append(args, sha, "--")
}

var (
	gitVersionOnce    sync.Once
	gitHasEndOfOption bool
	gitVersionPattern = regexp.MustCompile(`git version (\d+)\.(\d+)`)
)

// gitSupportsEndOfOptions reports whether the host git understands
// `--end-of-options` (added in git 2.24).
func gitSupportsEndOfOptions() bool {
	gitVersionOnce.Do(func() {
		out, err := exec.Command("git", "version").Output()
		if err != nil {
			return
		}
		gitHasEndOfOption = gitVersionAtLeast(string(out), 2, 24)
	})
	return gitHasEndOfOption
}

func gitVersionAtLeast(versionOutput string, major, minor int) bool {
	m := gitVersionPattern.FindStringSubmatch(versionOutput)
	if m == nil {
		return false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj > major || (maj == major && min >= minor)
}
