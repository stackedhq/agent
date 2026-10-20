package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/logs"
)

// Service environment handling.
//
// History: env vars used to be written to `<serviceDir>/.env`, which was
// both the service's `env_file:` and, by accident, Compose's *project* env
// file. That let a value like `COMPOSE_FILE=evil.yml` reconfigure Compose
// itself, and Compose interpolated `$X` inside env_file values from the
// agent's own environment (and stripped surrounding quotes), so the recreate
// path and the `docker run --env-file` paths disagreed on the container env.
//
// Now:
//   - compose services get their env as an `environment:` map in
//     docker-compose.yml (JSON-quoted, `$` escaped), which is exact and
//     supports multi-line values;
//   - `docker run` paths (rolling blue/green, release) read single-line
//     values from `stacked.env` (0600) and multi-line values through the
//     docker CLI's process env with `-e KEY`;
//   - compose is always invoked with `--env-file /dev/null`, and the legacy
//     `.env` is removed once nothing references it.

const (
	serviceEnvFileName = "stacked.env"
	legacyEnvFileName  = ".env"
)

// serviceEnv returns the env the service container should see: the
// server-managed vars plus the HOST=0.0.0.0 default (apps must bind all
// interfaces to be reachable from Caddy over the docker network). Keys that
// aren't valid env names and values containing NUL (which no process env can
// hold) are dropped; the returned warnings name them so the deploy log shows
// why.
func serviceEnv(vars map[string]string) (map[string]string, []string) {
	out := make(map[string]string, len(vars)+1)
	var warnings []string
	for k, v := range vars {
		if !validEnvKey(k) {
			warnings = append(warnings, fmt.Sprintf("skipping env var with invalid name %q", truncateForError(k)))
			continue
		}
		if strings.ContainsRune(v, 0) {
			warnings = append(warnings, fmt.Sprintf("skipping env var %s: value contains a NUL byte", k))
			continue
		}
		out[k] = v
	}
	if _, ok := out["HOST"]; !ok {
		out["HOST"] = "0.0.0.0"
	}
	sort.Strings(warnings)
	return out, warnings
}

func addEnvWarnings(streamer *logs.Streamer, warnings []string) {
	for _, w := range warnings {
		streamer.AddLine("WARN: " + w)
	}
	if len(warnings) > 0 {
		streamer.Flush()
	}
}

// literalEnvWarning returns one deploy-log warning naming (never showing
// the values of) env vars whose value contains `$` or is wrapped in
// matching quotes. The old `.env` / env_file path let Compose expand
// `$VAR` and strip quotes in such values; they are now passed to the
// container exactly as stored, so an app relying on the old behaviour
// sees a different value. Empty when no key is affected.
func literalEnvWarning(env map[string]string) string {
	var keys []string
	for _, k := range sortedKeys(env) {
		v := env[k]
		if strings.Contains(v, "$") || isWrappedInMatchingQuotes(v) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	return fmt.Sprintf("env vars %s contain $ or surrounding quotes. Values are now passed to the container literally: "+
		"$VAR references are no longer expanded and quotes are no longer stripped. Update these values if your app relied on that.",
		strings.Join(keys, ", "))
}

func isWrappedInMatchingQuotes(v string) bool {
	if len(v) < 2 {
		return false
	}
	first, last := v[0], v[len(v)-1]
	return first == last && (first == '"' || first == '\'')
}

// addLiteralEnvWarning writes literalEnvWarning to the deploy log.
func addLiteralEnvWarning(streamer *logs.Streamer, env map[string]string) {
	if w := literalEnvWarning(env); w != "" {
		addEnvWarnings(streamer, []string{w})
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// composeEnvironment renders env as a compose `environment:` mapping.
// Values go through yStr, so they are JSON-quoted and `$`-escaped: the
// container sees exactly the stored value, including newlines.
func composeEnvironment(env map[string]string) yMap {
	m := make(yMap, 0, len(env))
	for _, k := range sortedKeys(env) {
		m = append(m, yKV{Key: k, Value: yStr(env[k])})
	}
	return m
}

// isEnvFileSafeValue reports whether `docker run --env-file` reproduces v
// exactly. The docker CLI splits the file on newlines (dropping a trailing
// `\r`) and otherwise keeps the value byte-for-byte: no quote stripping, no
// interpolation, no comment handling after the `=`.
func isEnvFileSafeValue(v string) bool {
	return !strings.ContainsAny(v, "\n\r\x00")
}

// buildEnvFile renders a `docker run --env-file` file. Values are written
// verbatim and must not be quoted: the docker CLI does not strip quotes.
// Keys that aren't valid env names and values that the format can't
// represent (multi-line, NUL) are omitted; callers that need multi-line
// values use dockerRunEnvFor, which passes them through the process env.
func buildEnvFile(vars map[string]string) string {
	var b strings.Builder
	for _, k := range sortedKeys(vars) {
		v := vars[k]
		if !validEnvKey(k) || !isEnvFileSafeValue(v) {
			continue
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

// dockerRunEnv is the env plumbing for a `docker run` invocation.
type dockerRunEnv struct {
	// FileContent is the stacked.env content (single-line values).
	FileContent string
	// PassKeys are passed as `-e KEY`; the docker CLI reads their values
	// from its own process env, which keeps them out of argv.
	PassKeys []string
	// ProcEnv holds the KEY=VALUE pairs to add to the docker CLI's env.
	ProcEnv []string
}

// dockerCLIEnvKey reports whether an env name changes how the docker CLI
// itself behaves. Such names can't be routed through the CLI's process env.
func dockerCLIEnvKey(k string) bool {
	u := strings.ToUpper(k)
	for _, p := range []string{"DOCKER_", "BUILDKIT_", "BUILDX_", "COMPOSE_", "XDG_", "LD_", "OTEL_", "NOTARY_"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	switch u {
	case "HOME", "PATH", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "GODEBUG", "GOTRACEBACK", "GOMAXPROCS", "GOGC", "GOMEMLIMIT":
		return true
	}
	return false
}

// dockerRunEnvFor splits env (already passed through serviceEnv) into the
// env-file part and the `-e KEY` part.
func dockerRunEnvFor(env map[string]string) (dockerRunEnv, error) {
	var out dockerRunEnv
	var file strings.Builder
	for _, k := range sortedKeys(env) {
		v := env[k]
		if isEnvFileSafeValue(v) {
			file.WriteString(k + "=" + v + "\n")
			continue
		}
		if dockerCLIEnvKey(k) {
			return dockerRunEnv{}, fmt.Errorf("env var %s has a multi-line value, which this deploy path can't pass to the container (the name collides with a docker CLI setting); use a single-line value", k)
		}
		out.PassKeys = append(out.PassKeys, k)
		out.ProcEnv = append(out.ProcEnv, k+"="+v)
	}
	out.FileContent = file.String()
	return out, nil
}

// Args returns the `docker run` flags for this env, given the path the
// FileContent was written to.
func (d dockerRunEnv) Args(envFilePath string) []string {
	args := []string{"--env-file=" + envFilePath}
	for _, k := range d.PassKeys {
		args = append(args, "-e", k)
	}
	return args
}

// CommandEnv returns the process env for the docker CLI: the agent's env
// with any same-named entries replaced by the pass-through values. Returns
// nil (inherit) when there is nothing to pass.
func (d dockerRunEnv) CommandEnv() []string {
	if len(d.ProcEnv) == 0 {
		return nil
	}
	pass := make(map[string]struct{}, len(d.PassKeys))
	for _, k := range d.PassKeys {
		pass[k] = struct{}{}
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+len(d.ProcEnv))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if _, clash := pass[name]; clash {
			continue
		}
		out = append(out, kv)
	}
	return append(out, d.ProcEnv...)
}

// writeServiceEnvFile writes <dir>/stacked.env (0600) for `docker run`
// paths and returns its plumbing.
func writeServiceEnvFile(dir string, env map[string]string) (dockerRunEnv, string, error) {
	d, err := dockerRunEnvFor(env)
	if err != nil {
		return dockerRunEnv{}, "", err
	}
	path := filepath.Join(dir, serviceEnvFileName)
	if err := writeFile(path, d.FileContent); err != nil {
		return dockerRunEnv{}, "", fmt.Errorf("write %s: %w", serviceEnvFileName, err)
	}
	return d, path, nil
}

// syncLegacyEnvFile is cleanupLegacyEnvFile for deploy paths that don't
// rewrite docker-compose.yml up front (blue/green rewrites it only after
// the traffic flip, see refreshBlueGreenCompose). While an older compose file
// still lists `.env` as `env_file:`, a later `compose restart`/`up -d`
// (restart op fallback) would start the container with whatever `.env`
// holds, so it's rewritten (0600) with the current values in the format
// the old agent used (verbatim KEY=VALUE, single-line values only).
// Otherwise the legacy file is removed.
func syncLegacyEnvFile(dir string, env map[string]string) error {
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err == nil && composeReferencesLegacyEnv(string(compose)) {
		envPath := filepath.Join(dir, legacyEnvFileName)
		if info, statErr := os.Lstat(envPath); statErr == nil && !info.Mode().IsRegular() {
			if rmErr := os.RemoveAll(envPath); rmErr != nil {
				return rmErr
			}
		}
		return writeFile(envPath, buildEnvFile(env))
	}
	return cleanupLegacyEnvFile(dir)
}

// cleanupLegacyEnvFile removes the pre-stacked.env `.env` from a service dir
// once the compose file no longer references it. If an older compose file
// still lists it as `env_file:` (e.g. a blue/green deploy that failed
// before rewriting the compose file; see syncLegacyEnvFile), the file is kept so
// `compose restart`/`up` keep working, but its mode is tightened to 0600.
func cleanupLegacyEnvFile(dir string) error {
	envPath := filepath.Join(dir, legacyEnvFileName)
	info, err := os.Lstat(envPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	compose, readErr := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if readErr == nil && composeReferencesLegacyEnv(string(compose)) && info.Mode().IsRegular() {
		return os.Chmod(envPath, 0o600)
	}
	return os.Remove(envPath)
}

// composeReferencesLegacyEnv detects the old template's `env_file: [.env]`.
func composeReferencesLegacyEnv(compose string) bool {
	for _, line := range strings.Split(compose, "\n") {
		t := strings.TrimSpace(line)
		if t == "- .env" || t == `- ".env"` || t == "env_file: .env" {
			return true
		}
	}
	return false
}
