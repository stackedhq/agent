package executor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// errOpenEnded signals to executor.Execute() that the handler has taken
// responsibility for the op's terminal status update and the executor
// must NOT auto-flip the op to "success" after the handler returns.
//
// Today this is used exclusively by TailscaleSetup, which forks
// `tailscale up` into a goroutine and returns immediately after the
// auth URL is reported. The final transition to "success" happens
// server-side in the heartbeat handler when the agent later reports
// `tailscale status --json` as Connected. The serial poller (see
// internal/poller/poller.go) would otherwise stall all other ops on
// this machine for as long as the user takes to click the URL.
var errOpenEnded = errors.New("operation left open-ended")

// Matches the URL the `tailscale` CLI prints on first run to prompt the
// user to authenticate. Kept tight (no host wildcard, hex/alnum-only
// token) so a hostile / corrupted stderr stream can't smuggle a phishing
// URL through to the dashboard.
var tailscaleAuthURLRe = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9]+`)

// TailscaleSetup brings the machine onto the user's tailnet via the
// interactive auth-URL flow:
//
//  1. Install `tailscale` if not present (idempotent apt install).
//  2. Start `tailscale up --hostname=... --accept-dns=true --ssh=false`
//     as a child of a detached goroutine.
//  3. Scan stderr for the auth URL within a short window. Report it via
//     UpdateStatus(running, {authUrl}) so the dashboard can render the
//     "Open Tailscale to authorize" panel.
//  4. Return errOpenEnded so the executor doesn't write a terminal
//     status. The final success transition is heartbeat-driven on the
//     server side.
//
// Failure modes that happen BEFORE the URL is seen (binary missing,
// install error, immediate exit) return a normal error and the
// executor reports `failed` as usual.
func (e *Executor) TailscaleSetup(op client.Operation) error {
	hostname := getStringPayload(op.Payload, "hostname")
	if hostname == "" {
		return fmt.Errorf("tailscale_setup requires hostname in payload")
	}

	// Idempotent install. On Debian/Ubuntu hosts (the only thing we
	// officially support today) the official upstream installer is the
	// simplest, most-reliable choice; it handles the apt key + repo
	// list and is itself idempotent. We never run it if the binary is
	// already present so we don't redo network work on every Enable.
	if _, err := exec.LookPath("tailscale"); err != nil {
		log.Println("Tailscale not installed; running upstream installer")
		install := exec.Command("sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh")
		out, instErr := install.CombinedOutput()
		if instErr != nil {
			return fmt.Errorf("tailscale install failed: %s: %w", strings.TrimSpace(string(out)), instErr)
		}
		if _, err := exec.LookPath("tailscale"); err != nil {
			return fmt.Errorf("tailscale install succeeded but binary not on PATH: %w", err)
		}
	}

	// `tailscale up` prints the auth URL to stderr and then BLOCKS until
	// the user completes authorization in their browser (or we time
	// out). We:
	//   - capture stderr so we can scrape the URL
	//   - run the process under its own goroutine so the executor returns
	//   - keep a generous deadline so the user has time to switch
	//     devices and click; if they don't, `tailscale up` exits with
	//     an error and we report failure.
	//
	// Note: deliberately NOT passing --reset. That flag resets unspecified
	// settings to defaults, which would wipe out user-configured flags
	// (e.g. --advertise-routes, --advertise-exit-node, --accept-routes)
	// the user may have set manually on the VPS. `tailscale up` is
	// itself idempotent for the fields we DO pass, so for the
	// re-authorize / re-enable paths we just re-assert hostname /
	// accept-dns / ssh and leave everything else alone.
	args := []string{
		"up",
		"--hostname=" + hostname,
		"--accept-dns=true",
		"--ssh=false",
		"--timeout=10m",
	}
	cmd := exec.Command("tailscale", args...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	// Some Tailscale CLI versions print the URL on stdout, others on
	// stderr. Merge so the scraper sees both without caring.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tailscale up: %w", err)
	}

	// urlChan is buffered so the scraper goroutine doesn't block on
	// send when nobody is listening (e.g. the wait goroutine got there
	// first because the process exited fast).
	urlChan := make(chan string, 1)
	go scanForAuthURL(io.MultiReader(stderr, stdout), urlChan)

	// Detached goroutine: wait for process exit, report final failure
	// if the process dies before user authorizes. We DO NOT report
	// success here — that comes from the heartbeat handler on the
	// server when `tailscale status --json` first shows Connected.
	go func(opID string) {
		waitErr := cmd.Wait()
		if waitErr != nil {
			log.Printf("Tailscale up for op %s exited with error: %v", opID, waitErr)
			_ = e.Client.UpdateStatus(opID, &client.StatusUpdate{
				Status: "failed",
				Result: map[string]interface{}{
					"error": fmt.Sprintf("tailscale up exited: %v", waitErr),
				},
			})
			return
		}
		// Process exited 0. Heartbeat takes it from here.
		log.Printf("Tailscale up for op %s exited cleanly; heartbeat will finalize op", opID)
	}(op.ID)

	// Wait briefly for the URL. If the binary changes its output
	// format we'd rather report failure than leave the op stuck
	// forever.
	select {
	case authURL := <-urlChan:
		// Retry with short backoff: the dashboard might be briefly
		// unreachable (deploy, cold start, transient network), and
		// unlike other UpdateStatus calls this one is
		// once-in-10-minutes — if it's dropped the user sees
		// "Waiting for agent to emit auth URL…" until the parent
		// process times out. Three attempts with 1s/3s/9s backoff
		// covers the common transient-failure window without
		// blocking the executor for long. Even if all three fail
		// we don't surface an error: the wait goroutine will mark
		// the op failed when `tailscale up` eventually times out.
		update := &client.StatusUpdate{
			Status: "running",
			Result: map[string]interface{}{
				"authUrl": authURL,
			},
		}
		delays := []time.Duration{0, 1 * time.Second, 3 * time.Second}
		var lastErr error
		for _, d := range delays {
			if d > 0 {
				time.Sleep(d)
			}
			if lastErr = e.Client.UpdateStatus(op.ID, update); lastErr == nil {
				break
			}
			log.Printf("Tailscale auth URL post failed (op %s, retrying): %v", op.ID, lastErr)
		}
		if lastErr != nil {
			log.Printf("Tailscale auth URL post gave up after retries for op %s: %v", op.ID, lastErr)
		}
	case <-time.After(15 * time.Second):
		// No URL within 15s usually means either (a) the device is
		// already authenticated (re-running `tailscale up` on a node
		// that's still valid emits no URL and returns instantly) or
		// (b) the CLI changed its output. In case (a) the wait
		// goroutine will mark the op success-equivalent via heartbeat;
		// in case (b) it'll fail with a normal error. Either way we
		// return errOpenEnded so the executor leaves the running
		// state alone.
		log.Printf("Tailscale auth URL not seen within 15s for op %s; deferring to wait goroutine", op.ID)
	}

	return errOpenEnded
}

// scanForAuthURL reads `r` line-by-line and writes the first matching
// tailscale auth URL to `out`. Returns when the reader is exhausted or
// a URL is found. Best-effort: errors are swallowed because the wait
// goroutine handles process-exit failure separately.
func scanForAuthURL(r io.Reader, out chan<- string) {
	scanner := bufio.NewScanner(r)
	// 64KB default buffer is fine; tailscale's first-run prose is short.
	for scanner.Scan() {
		line := scanner.Text()
		if match := tailscaleAuthURLRe.FindString(line); match != "" {
			select {
			case out <- match:
			default:
			}
			return
		}
	}
}

// TailscaleDisable runs `tailscale down`. Fast, blocking, no goroutine
// gymnastics needed — the CLI returns within a second or two.
//
// We do NOT uninstall the binary on disable. Keeping it around makes
// re-enable instant and avoids a second apt run on every toggle. The
// `machines.tailscale*` columns are cleared server-side on op success.
func (e *Executor) TailscaleDisable(op client.Operation) error {
	if _, err := exec.LookPath("tailscale"); err != nil {
		// Already not installed → nothing to disable. Reporting
		// success matches the user intent ("be off").
		return nil
	}
	out, err := exec.Command("tailscale", "down").CombinedOutput()
	if err != nil {
		return fmt.Errorf("tailscale down: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
