package executor

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Git plumbing for source deploys.
//
//   - The clone URL is stored and passed tokenless. Credentials reach git
//     as an `http.<origin>/.extraheader` Authorization header set through
//     git's environment config (GIT_CONFIG_COUNT/KEY/VALUE), so the token
//     is never in argv (visible to every local user via ps), never in
//     .git/config, and no helper script has to be written or executed
//     (/tmp is noexec on some hosts). The header is scoped to the clone
//     origin, so a redirect to another host doesn't carry it.
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

// gitSession holds the env for one deploy's git calls.
type gitSession struct {
	env []string
}

// gitConfigCountSupported reports whether the host git reads config from
// GIT_CONFIG_COUNT/GIT_CONFIG_KEY_n/GIT_CONFIG_VALUE_n (git 2.31+). Older
// git gets the same setting through GIT_CONFIG_PARAMETERS, which git has
// read since 1.7 (it's what `git -c` uses to pass config to
// subprocesses). Never both: http.extraheader is multi-valued, so a git
// that read both would send the header twice. Package var for tests.
var gitConfigCountSupported = func() bool { return gitVersionAtLeastHost(2, 31) }

// newGitSession prepares the git env. Call Close when done.
func newGitSession(src gitSource) (*gitSession, error) {
	extra := []string{
		"GIT_ALLOW_PROTOCOL=https",
		"GIT_TERMINAL_PROMPT=0",
	}
	if src.hasCredentials() {
		key, value, err := gitAuthHeaderConfig(src)
		if err != nil {
			return nil, err
		}
		if gitConfigCountSupported() {
			extra = append(extra,
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0="+key,
				"GIT_CONFIG_VALUE_0="+value,
			)
		} else {
			extra = append(extra, "GIT_CONFIG_PARAMETERS="+gitConfigParam(key, value))
		}
	}
	return &gitSession{env: mergeEnv(os.Environ(), extra)}, nil
}

// gitAuthHeaderConfig returns the config key/value that makes git send
// `Authorization: Basic base64(user:password)` to the clone origin only.
func gitAuthHeaderConfig(src gitSource) (string, string, error) {
	u, err := url.Parse(src.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", fmt.Errorf("unsupported git URL")
	}
	if strings.ContainsAny(src.Username+src.Password, "\r\n\x00") {
		return "", "", fmt.Errorf("git credentials contain control characters")
	}
	key := "http.https://" + u.Host + "/.extraheader"
	auth := base64.StdEncoding.EncodeToString([]byte(src.Username + ":" + src.Password))
	return key, "Authorization: Basic " + auth, nil
}

// gitConfigParam encodes one entry in GIT_CONFIG_PARAMETERS format
// ('key'='value', single quotes escaped shell-style).
func gitConfigParam(key, value string) string {
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	return q(key) + "=" + q(value)
}

// Close is kept for call-site symmetry; the session owns no resources.
func (s *gitSession) Close() {}

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
// call, so a stale stored token is never used instead of the fresh one
// and nothing is ever persisted (e.g. by `store`).
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
		gitHasEndOfOption = gitVersionAtLeastHost(2, 24)
	})
	return gitHasEndOfOption
}

var (
	hostGitVersionOnce sync.Once
	hostGitVersion     string
)

// gitVersionAtLeastHost reports whether the host git is at least
// major.minor (false when git is missing or unparseable).
func gitVersionAtLeastHost(major, minor int) bool {
	hostGitVersionOnce.Do(func() {
		out, err := exec.Command("git", "version").Output()
		if err == nil {
			hostGitVersion = string(out)
		}
	})
	return gitVersionAtLeast(hostGitVersion, major, minor)
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
