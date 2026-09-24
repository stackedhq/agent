package executor

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// gitRemote is a clone URL with credentials stripped from the URL itself.
// Auth, when needed, is supplied via a short-lived GIT_ASKPASS helper so
// tokens never land in argv or in `.git/config`.
type gitRemote struct {
	CleanURL string
	Username string
	Password string
}

func parseGitRemote(raw string) gitRemote {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return gitRemote{CleanURL: raw}
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	u.User = nil
	if username == "" && password != "" {
		username = "x-access-token"
	}
	return gitRemote{
		CleanURL: u.String(),
		Username: username,
		Password: password,
	}
}

type gitAuthSession struct {
	dir      string
	extraEnv []string
}

func (s *gitAuthSession) env() []string {
	if s == nil {
		return nil
	}
	return s.extraEnv
}

func (s *gitAuthSession) Close() {
	if s == nil || s.dir == "" {
		return
	}
	_ = os.RemoveAll(s.dir)
}

// startGitAuth writes a 0700 askpass helper and a 0600 secret file.
// The git child sees only GIT_ASKPASS (and the secret path) in its
// environment — never the token in argv. Close() shreds the temp dir.
func startGitAuth(remote gitRemote) (*gitAuthSession, error) {
	if remote.Password == "" {
		return &gitAuthSession{}, nil
	}
	dir, err := os.MkdirTemp("", "stacked-git-")
	if err != nil {
		return nil, fmt.Errorf("git auth tempdir: %w", err)
	}
	if err := os.Chmod(dir, secretDirMode); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	secretPath := filepath.Join(dir, "secret")
	body := remote.Username + "\n" + remote.Password + "\n"
	if err := writeFileMode(secretPath, body, secretFileMode); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	askpass := filepath.Join(dir, "askpass")
	script := `#!/bin/sh
user=$(sed -n '1p' "$STACKED_GIT_SECRET")
pass=$(sed -n '2p' "$STACKED_GIT_SECRET")
case "$1" in
*[Uu]sername*) printf '%s\n' "$user" ;;
*)             printf '%s\n' "$pass" ;;
esac
`
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &gitAuthSession{
		dir: dir,
		extraEnv: []string{
			"GIT_ASKPASS=" + askpass,
			"SSH_ASKPASS=" + askpass,
			"GIT_TERMINAL_PROMPT=0",
			"STACKED_GIT_SECRET=" + secretPath,
		},
	}, nil
}

func sanitizeGitRemote(repoDir, cleanURL string) error {
	if cleanURL == "" {
		return nil
	}
	if _, err := runCommandSilent(repoDir, "git", "remote", "set-url", "origin", cleanURL); err != nil {
		return fmt.Errorf("sanitize git remote: %w", err)
	}
	return nil
}

func gitRemoteContainsUserinfo(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.Contains(raw, "@") && strings.Contains(raw, "://")
	}
	return u.User != nil
}
