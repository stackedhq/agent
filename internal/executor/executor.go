package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

const (
	stackedDir  = "/opt/stacked"
	servicesDir = "/opt/stacked/services"
	proxyDir    = "/opt/stacked/proxy"

	// rejectedOpType is a dispatch marker for ops that failed payload
	// validation. It can't collide with a real op type.
	rejectedOpType = "\x00rejected"
)

// Executor handles running operations dispatched by the poller.
type Executor struct {
	Client *client.Client
}

func New(c *client.Client) *Executor {
	return &Executor{Client: c}
}

// Execute dispatches an operation with no deadline. The poller uses
// ExecuteWithTimeout; this stays for callers that don't need one.
func (e *Executor) Execute(op client.Operation) {
	e.ExecuteWithTimeout(op, 0)
}

// opUnwindLogInterval is how often a still-running handler is logged after
// its operation timed out.
const opUnwindLogInterval = 5 * time.Minute

type opOutcome struct {
	result map[string]interface{}
	err    error
}

// ExecuteWithTimeout dispatches an operation to the correct handler based
// on type. With timeout > 0 the op runs under a deadline: every command
// started through opCommand (runCommand*, runCommandSilent*, the backup /
// migrate / query / job helpers) is killed when it expires, and the op is
// reported failed at that moment. The call still waits for the handler to
// unwind before returning, so operations stay strictly sequential.
func (e *Executor) ExecuteWithTimeout(op client.Operation, timeout time.Duration) {
	NoteMachineID(op.MachineID)

	// Report running
	if err := e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "running"}); err != nil {
		log.Printf("Failed to report running status for %s: %v", op.ID, err)
	}

	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	restore := setOpContext(ctx)
	defer restore()

	done := make(chan opOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Operation %s (%s) panicked: %v", op.ID, op.Type, r)
				done <- opOutcome{err: fmt.Errorf("agent error while running %s: %v", op.Type, r)}
			}
		}()
		result, err := e.dispatch(op)
		done <- opOutcome{result: result, err: err}
	}()

	var out opOutcome
	select {
	case out = <-done:
	case <-ctx.Done():
		select {
		case out = <-done:
			// Finished right at the deadline: report the real outcome.
			e.reportOutcome(op, out.result, out.err)
			return
		default:
		}
		// Report the timeout now so the dashboard isn't left waiting on a
		// handler that is being killed. A late handler result is dropped
		// (the server ignores updates to terminal operations anyway).
		timeoutErr := fmt.Errorf("operation timed out after %s", timeout)
		log.Printf("Operation %s (%s) failed: %v", op.ID, op.Type, timeoutErr)
		_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{
			Status: "failed",
			Result: map[string]interface{}{"error": timeoutErr.Error(), "code": "OP_TIMEOUT"},
		})
		waitForHandler(op, done)
		return
	}
	e.reportOutcome(op, out.result, out.err)
}

// handlerStuckLimit is how long a handler may keep running after its op
// timed out before the agent gives up on it and exits, so systemd
// (Restart=always) brings back a clean agent instead of the poller staying
// blocked forever behind a call that ignores the op context.
var handlerStuckLimit = 15 * time.Minute

// exitProcess is os.Exit, swappable in tests.
var exitProcess = os.Exit

// waitForHandler blocks until a timed-out handler returns. Its commands
// were bound to the expired context, so this is normally immediate. If the
// handler is still running handlerStuckLimit later, the agent exits.
func waitForHandler(op client.Operation, done <-chan opOutcome) {
	ticker := time.NewTicker(opUnwindLogInterval)
	defer ticker.Stop()
	watchdog := time.NewTimer(handlerStuckLimit)
	defer watchdog.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			log.Printf("Operation %s (%s): handler still running after its timeout; waiting before the next operation", op.ID, op.Type)
		case <-watchdog.C:
			log.Printf("Operation %s (%s): handler still running %s after its timeout; exiting so systemd restarts a clean agent", op.ID, op.Type, handlerStuckLimit)
			exitProcess(1)
			return
		}
	}
}

func (e *Executor) dispatch(op client.Operation) (map[string]interface{}, error) {
	var err error
	var result map[string]interface{}
	// Reject path-bearing identifiers before any handler can join them
	// into a filesystem path or hand them to RemoveAll.
	dispatchType := op.Type
	if idErr := validateOpIdentifiers(op.Payload); idErr != nil {
		err = idErr
		dispatchType = rejectedOpType
	}
	switch dispatchType {
	case rejectedOpType:
		// Rejected above; err is already set.
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

	return result, err
}

func (e *Executor) reportOutcome(op client.Operation, result map[string]interface{}, err error) {
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
	streamer := logs.NewStreamer(e.Client, operationID)
	return e.runCommandWithStreamerEnv(streamer, dir, nil, name, args...)
}

// runCommandWithStreamer executes a command using an existing streamer,
// so all commands in a deploy share the same log stream and progress state.
func (e *Executor) runCommandWithStreamer(streamer *logs.Streamer, dir, name string, args ...string) error {
	return e.runCommandWithStreamerEnv(streamer, dir, nil, name, args...)
}

// runCommandWithStreamerEnv is runCommandWithStreamer with an explicit
// process env (nil inherits the agent's env). Used to hand secrets to child
// processes without putting them in argv.
func (e *Executor) runCommandWithStreamerEnv(streamer *logs.Streamer, dir string, env []string, name string, args ...string) error {
	cmd := opCommand(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	return runStreamedCmd(streamer, cmd, name)
}

// runStreamedCmd starts a prepared command with stdout+stderr merged into
// the streamer and waits for it.
func runStreamedCmd(streamer *logs.Streamer, cmd *exec.Cmd, name string) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

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

// runCommandSilent executes a command and returns its combined output.
func runCommandSilent(dir, name string, args ...string) (string, error) {
	return runCommandSilentEnv(dir, nil, name, args...)
}

func runCommandSilentEnv(dir string, env []string, name string, args ...string) (string, error) {
	cmd := opCommand(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// composeArgs returns the `docker` argv for a compose command against the
// project in dir (a service or database directory). Everything Compose would
// otherwise discover implicitly is pinned:
//
//   - `-p` is the directory basename, the project name Compose has always
//     derived for these dirs, so existing containers keep matching;
//   - `-f` / `--project-directory` stop COMPOSE_FILE-style overrides and
//     parent-directory lookups;
//   - `--env-file /dev/null` stops Compose from loading `<dir>/.env` as the
//     project env file. Verified on Compose v5: without it, COMPOSE_FILE and
//     COMPOSE_PROJECT_NAME in .env are honoured.
func composeArgs(dir string, args ...string) []string {
	base := []string{
		"compose",
		"-p", filepath.Base(dir),
		"-f", filepath.Join(dir, "docker-compose.yml"),
		"--project-directory", dir,
		"--env-file", os.DevNull,
	}
	return append(base, args...)
}

// privateDirRoots hold secrets (env, compose files with credentials, DB
// dumps, proxy/gate config). Directories at or under them are created 0700
// and pre-existing ones are tightened. Containers read the files they need
// through bind mounts resolved by the docker daemon, so host-side traversal
// by other users is never required.
var privateDirRoots = []string{
	servicesDir,
	databasesDir,
	proxyDir,
	"/opt/stacked/gate",
	stackedDir + "/backups-tmp",
}

func privateRootFor(path string) (string, bool) {
	for _, root := range privateDirRoots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return root, true
		}
	}
	return "", false
}

// ensureDir creates a directory if it doesn't exist. Paths under a private
// root are created 0700 and every directory from the root down to path is
// chmodded 0700 (best effort: a root-owned dir from an old install is left
// alone rather than failing the op). Other paths keep the historical 0755.
func ensureDir(path string) error {
	clean := filepath.Clean(path)
	root, private := privateRootFor(clean)
	if !private {
		return os.MkdirAll(path, 0o755)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return err
	}
	for p := clean; ; p = filepath.Dir(p) {
		if info, err := os.Lstat(p); err == nil && info.IsDir() && info.Mode().Perm() != 0o700 {
			if err := os.Chmod(p, 0o700); err != nil {
				log.Printf("ensureDir: could not tighten %s to 0700: %v", p, err)
			}
		}
		if p == root || p == "/" || p == "." {
			break
		}
	}
	return nil
}

// writeFile writes content to a file (mode 0600), creating parent dirs as
// needed. A pre-existing file is chmodded before it is rewritten so secrets
// never land in a file that is still world-readable from an older agent.
func writeFile(path, content string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
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
