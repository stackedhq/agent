package executor

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

const (
	stackedDir  = "/opt/stacked"
	servicesDir = "/opt/stacked/services"
	proxyDir    = "/opt/stacked/proxy"
)

// Executor handles running operations dispatched by the poller.
type Executor struct {
	Client *client.Client
}

func New(c *client.Client) *Executor {
	return &Executor{Client: c}
}

// Execute dispatches an operation to the correct handler based on type.
func (e *Executor) Execute(op client.Operation) {
	// Report running
	if err := e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "running"}); err != nil {
		log.Printf("Failed to report running status for %s: %v", op.ID, err)
	}

	var err error
	var result map[string]interface{}
	switch op.Type {
	case "deploy":
		result, err = e.Deploy(op)
	case "release_command":
		err = e.ReleaseCommand(op)
	case "cron_run":
		result, err = e.RunJob(op)
	case "stop":
		err = e.Stop(op)
	case "service_destroy":
		err = e.ServiceDestroy(op)
	case "restart":
		err = e.Restart(op)
	case "setup":
		err = e.Setup(op)
	case "proxy_config":
		err = e.ProxyConfig(op)
	case "ssl_check":
		result, err = e.SslCheck(op)
	case "self_update":
		err = e.SelfUpdate(op)
	case "db_provision":
		result, err = e.Provision(op)
	case "db_start":
		err = e.StartDB(op)
	case "db_stop":
		err = e.StopDB(op)
	case "db_destroy":
		err = e.DestroyDB(op)
	case "db_extension_enable":
		err = e.EnableExtension(op)
	case "db_extension_disable":
		err = e.DisableExtension(op)
	case "db_set_access":
		err = e.SetAccess(op)
	case "db_rotate_password":
		err = e.RotatePassword(op)
	case "db_migrate":
		err = e.DBMigrate(op)
	case "volume_migrate":
		err = e.VolumeMigrate(op)
	case "db_backup":
		err = e.Backup(op)
	case "db_restore":
		err = e.Restore(op)
	case "db_query":
		result, err = e.QueryDatabase(op)
	case "tailscale_setup":
		err = e.TailscaleSetup(op)
	case "tailscale_disable":
		err = e.TailscaleDisable(op)
	case "dokploy_takeover_probe":
		result, err = e.DokployTakeoverProbe(op)
	case "dokploy_traefik_stop":
		err = e.DokployTraefikStop(op)
	case "dokploy_traefik_start":
		err = e.DokployTraefikStart(op)
	case "dokploy_caddy_attach_network":
		err = e.DokployCaddyAttachNetwork(op)
	case "dokploy_caddy_detach_network":
		err = e.DokployCaddyDetachNetwork(op)
	default:
		err = fmt.Errorf("unknown operation type: %s", op.Type)
	}

	// Open-ended ops (today: tailscale_setup) take responsibility for
	// their own terminal status updates — the handler has already
	// reported `running` with an interim result, and the final
	// transition will come from a different path (heartbeat-driven in
	// the tailscale case). Return early so we don't clobber that state
	// with a synthetic `success`.
	if errors.Is(err, errOpenEnded) {
		return
	}

	if err != nil {
		log.Printf("Operation %s (%s) failed: %v", op.ID, op.Type, err)
		// If the handler returned a typed error carrying a
		// structured result (currently only ProxyConfigError), use
		// that instead of the bare {error: "..."} envelope so the
		// server can render an actionable banner. Falls back to the
		// historical shape for plain errors, preserving back-compat
		// with the existing server-side parser.
		failResult := map[string]interface{}{"error": err.Error()}
		var pe *ProxyConfigError
		if errors.As(err, &pe) {
			failResult = pe.Result()
		}
		_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{
			Status: "failed",
			Result: failResult,
		})
		return
	}

	_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{
		Status: "success",
		Result: result,
	})
}

// serviceDir returns the working directory for a service.
func serviceDir(serviceID string) string {
	return filepath.Join(servicesDir, serviceID)
}

// runCommand executes a command, streaming stdout/stderr to the Stacked API.
func (e *Executor) runCommand(operationID, dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	// Combine stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	streamer := logs.NewStreamer(e.Client, operationID)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	streamer.Stream(stdout)
	streamer.Flush()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s exited with error: %w", name, err)
	}
	return nil
}

// runCommandWithStreamer executes a command using an existing streamer,
// so all commands in a deploy share the same log stream and progress state.
func (e *Executor) runCommandWithStreamer(streamer *logs.Streamer, dir, name string, args ...string) error {
	return e.runCommandWithEnv(streamer, dir, nil, name, args...)
}

// runCommandWithEnv is runCommandWithStreamer plus extra environment
// entries. Use this when a secret must reach a child process without
// appearing in argv (visible in /proc/<pid>/cmdline).
func (e *Executor) runCommandWithEnv(streamer *logs.Streamer, dir string, extraEnv []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(extraEnv) > 0 {
		cmd.Env = mergeEnv(os.Environ(), extraEnv)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	streamer.Stream(stdout)
	streamer.Flush()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s exited with error: %w", name, err)
	}
	return nil
}

// mergeEnv overlays extra KEY=VALUE pairs onto base, last extra wins.
func mergeEnv(base, extra []string) []string {
	replace := make(map[string]string, len(extra))
	order := make([]string, 0, len(extra))
	for _, kv := range extra {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, seen := replace[k]; !seen {
			order = append(order, k)
		}
		replace[k] = v
	}
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, hit := replace[k]; hit {
				continue
			}
		}
		out = append(out, kv)
	}
	for _, k := range order {
		out = append(out, k+"="+replace[k])
	}
	return out
}

// runCommandSilent executes a command and returns its combined output.
func runCommandSilent(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const (
	publicDirMode  os.FileMode = 0o755
	publicFileMode os.FileMode = 0o644
	secretDirMode  os.FileMode = 0o700
	secretFileMode os.FileMode = 0o600
)

// ensureDir creates a public directory (0755). Existing dirs are left
// alone so a later public write cannot widen a secret-bearing parent.
func ensureDir(path string) error {
	return os.MkdirAll(path, publicDirMode)
}

// ensureSecretDir creates a directory that will hold credentials (0700)
// and tightens an existing world-readable one.
func ensureSecretDir(path string) error {
	if err := os.MkdirAll(path, secretDirMode); err != nil {
		return err
	}
	return os.Chmod(path, secretDirMode)
}

// writeFile writes public/config content as 0644. Parent dirs are created
// 0755 only when missing; an existing 0700 secret parent is preserved.
func writeFile(path, content string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeFileMode(path, content, publicFileMode)
}

// writeSecretFile writes credential-bearing content as 0600 under a 0700 parent.
func writeSecretFile(path, content string) error {
	if err := ensureSecretDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeFileMode(path, content, secretFileMode)
}

func writeFileMode(path, content string, mode os.FileMode) error {
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return err
	}
	// WriteFile honors umask on create and does not chmod an existing file.
	return os.Chmod(path, mode)
}

// ensureRegularFile guarantees `path` exists as a regular file. If it's
// missing, it's created with `fallbackContent`. If it exists but is not a
// regular file (most commonly: a directory auto-created by docker when a
// bind-mount source was missing at `compose up` time), it's removed and
// recreated. Idempotent.
//
// Without this, a single failed `docker compose up` can permanently poison
// a host path: docker auto-mkdirs the missing source, then every subsequent
// `compose up` fails with "not a directory" because the bind-mount
// destination is a file inside the image. Manual `rm -rf` was the only
// recovery before this helper.
func ensureRegularFile(path, fallbackContent string) error {
	info, err := os.Stat(path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return nil
	case err == nil:
		log.Printf("%s exists but is not a regular file (mode=%s); recreating", path, info.Mode())
		if rmErr := os.RemoveAll(path); rmErr != nil {
			return fmt.Errorf("remove non-regular %s: %w", path, rmErr)
		}
		return writeFile(path, fallbackContent)
	case errors.Is(err, os.ErrNotExist):
		return writeFile(path, fallbackContent)
	default:
		return err
	}
}

// getStringPayload extracts a string from the operation payload.
func getStringPayload(payload map[string]interface{}, key string) string {
	v, ok := payload[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// mergedReader returns an io.Reader that reads from both r1 and r2.
func mergedReader(r1, r2 io.Reader) io.Reader {
	return io.MultiReader(r1, r2)
}
