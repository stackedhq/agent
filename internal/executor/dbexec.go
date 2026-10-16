package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Secrets for `docker exec` never go in argv.
//
// Process arguments are world-readable on the host (`ps`, /proc/<pid>/cmdline),
// including those of processes inside containers. So:
//
//   - env-capable tools (psql/pg_*: PGPASSWORD, mysql*: MYSQL_PWD, redis-cli:
//     REDISCLI_AUTH) get `docker exec -e NAME` in argv while the value sits in
//     the docker CLI's own environment, which the CLI forwards into the exec'd
//     process (/proc/<pid>/environ is readable only by the same user/root);
//   - mongo tools have no password env var, so the password goes in a 0600
//     `--config` YAML file written inside the container over stdin and
//     removed afterwards (see writeMongoToolConfig);
//   - new passwords in rotation SQL/commands go over stdin.

// dockerExec is a `docker exec` invocation plus the secrets its argv names.
type dockerExec struct {
	Args    []string
	Secrets map[string]string
}

// newDockerExec builds `docker exec [-i] -e NAME... <container> <command...>`.
func newDockerExec(interactive bool, container string, secrets map[string]string, command ...string) dockerExec {
	args := []string{"exec"}
	if interactive {
		args = append(args, "-i")
	}
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "-e", name)
	}
	args = append(args, container)
	args = append(args, command...)
	return dockerExec{Args: args, Secrets: secrets}
}

// Env is the docker CLI's process env: the agent's env plus the secrets.
// nil (inherit) when there are no secrets.
func (d dockerExec) Env() []string {
	if len(d.Secrets) == 0 {
		return nil
	}
	env := os.Environ()
	for name, value := range d.Secrets {
		env = append(env, name+"="+value)
	}
	return env
}

// Command returns the op-bound `docker` command with Env set.
func (d dockerExec) Command() *exec.Cmd {
	cmd := opCommand("docker", d.Args...)
	cmd.Env = d.Env()
	return cmd
}

// mongoConfigYAML renders a mongo-tools `--config` file. JSON strings are
// valid YAML double-quoted scalars, so any password round-trips.
func mongoConfigYAML(password string) string {
	b, _ := json.Marshal(password)
	return "password: " + string(b) + "\n"
}

const mongoConfigCleanupTimeout = 30 * time.Second

// writeMongoToolConfig writes a `--config` file holding password into the
// container (0600, via stdin, never argv) and returns its path and a cleanup
// func that removes it. The cleanup uses its own deadline so it still runs
// after an op timeout.
func writeMongoToolConfig(container, password string) (string, func(), error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", func() {}, err
	}
	path := "/tmp/stacked-mongo-" + hex.EncodeToString(nonce[:]) + ".yaml"
	cmd := opCommand("docker", "exec", "-i", container, "sh", "-c", `umask 077 && cat > "$1"`, "sh", path)
	cmd.Stdin = strings.NewReader(mongoConfigYAML(password))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", func() {}, fmt.Errorf("write mongo tool config in %s: %v: %s", container, err, strings.TrimSpace(string(out)))
	}
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), mongoConfigCleanupTimeout)
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "exec", container, "rm", "-f", path).Run()
	}
	return path, cleanup, nil
}
