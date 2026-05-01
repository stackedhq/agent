// Package runtimelogs streams `docker logs -f` output for Stacked-managed
// service containers up to the server's runtime log endpoint. One Forwarder
// per service container; lifecycle is owned by the Manager which reconciles
// against the live container set on each heartbeat tick.
package runtimelogs

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const (
	// Flush whichever comes first.
	flushInterval = 1 * time.Second
	maxBatchSize  = 50

	// Hard cap per line — defends server's Redis ring buffer from a single
	// container spamming megabyte log lines. The server independently
	// truncates as well; this is just a courtesy.
	maxLineBytes = 8 * 1024

	// Where we persist per-service resume cursors. Surviving a brief agent
	// restart without replaying the entire log history is the only goal —
	// best-effort, not authoritative.
	logsRootDir = "/opt/stacked/logs"
)

// Forwarder runs `docker logs -f --timestamps` for one container and pushes
// batched lines to the server. Stop via Stop().
type Forwarder struct {
	serviceID   string
	containerID string
	client      *client.Client

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	buffer []string

	// Last RFC3339Nano timestamp seen on a log line. Persisted on shutdown
	// so a restarted agent picks up where it left off (with `--since`).
	lastTimestamp string
}

// NewForwarder creates a Forwarder. Start it with Run() in a goroutine.
func NewForwarder(c *client.Client, serviceID, containerID string) *Forwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &Forwarder{
		serviceID:   serviceID,
		containerID: containerID,
		client:      c,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
}

// Run blocks until Stop is called or the underlying `docker logs` command
// exits (container removed). Always closes the done channel before returning.
func (f *Forwarder) Run() {
	defer close(f.done)

	since := f.readCursor()

	args := []string{"logs", "-f", "--timestamps"}
	if since != "" {
		args = append(args, "--since", since)
	} else {
		// First run for this service: avoid replaying days of history.
		// One minute is enough for "I just deployed and want to see boot".
		args = append(args, "--since", "1m")
	}
	args = append(args, f.containerID)

	cmd := exec.CommandContext(f.ctx, "docker", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("runtimelogs[%s]: stdout pipe: %v", f.serviceID, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("runtimelogs[%s]: stderr pipe: %v", f.serviceID, err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("runtimelogs[%s]: docker logs start: %v", f.serviceID, err)
		return
	}

	// Periodic flush in background.
	flushDone := make(chan struct{})
	go func() {
		t := time.NewTicker(flushInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				f.flush()
			case <-flushDone:
				return
			}
		}
	}()

	// Scan stdout and stderr concurrently; both feed the same buffer.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); f.scan(stdout) }()
	go func() { defer wg.Done(); f.scan(stderr) }()
	wg.Wait()

	close(flushDone)
	f.flush()

	// Don't care about exit code — the container ending or being removed
	// will cause `docker logs` to exit non-zero, which is normal.
	_ = cmd.Wait()

	f.writeCursor()
}

// Stop signals the forwarder to terminate. Returns once Run has unwound.
func (f *Forwarder) Stop() {
	f.cancel()
	<-f.done
}

// scan reads lines from r, splitting timestamp from payload and buffering.
func (f *Forwarder) scan(r io.Reader) {
	scanner := bufio.NewScanner(r)
	// Default buffer is 64KB; bump to 1MB so a single fat JSON log line
	// doesn't kill the scanner.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		raw := scanner.Text()
		ts, line := splitTimestamp(raw)
		if len(line) > maxLineBytes {
			line = line[:maxLineBytes] + " …[truncated]"
		}

		f.mu.Lock()
		if ts != "" {
			f.lastTimestamp = ts
		}
		f.buffer = append(f.buffer, line)
		shouldFlush := len(f.buffer) >= maxBatchSize
		f.mu.Unlock()

		if shouldFlush {
			f.flush()
		}
	}
	// Errors from scanner.Err() are not actionable — the most common cause
	// is the agent shutting down or the container being removed. Either
	// way the loop exits and Run() returns.
}

// flush sends the current buffer to the server. Drops the batch on transport
// error (logs are best-effort; we'd rather lose lines than block the
// forwarder or back up memory).
func (f *Forwarder) flush() {
	f.mu.Lock()
	if len(f.buffer) == 0 {
		f.mu.Unlock()
		return
	}
	batch := f.buffer
	f.buffer = nil
	f.mu.Unlock()

	if err := f.client.SendServiceLogs(f.serviceID, batch); err != nil {
		log.Printf("runtimelogs[%s]: send failed (%d lines dropped): %v", f.serviceID, len(batch), err)
	}
}

// splitTimestamp pulls the leading RFC3339Nano timestamp prepended by
// `docker logs --timestamps`. Returns ("", raw) if no timestamp is found
// (defensive: keeps the line rather than dropping it).
func splitTimestamp(raw string) (ts, rest string) {
	idx := strings.IndexByte(raw, ' ')
	if idx <= 0 {
		return "", raw
	}
	candidate := raw[:idx]
	// Cheap shape check: docker timestamps always contain 'T' and end in 'Z'
	// or a timezone offset. Avoids parsing every line.
	if !strings.Contains(candidate, "T") {
		return "", raw
	}
	if _, err := time.Parse(time.RFC3339Nano, candidate); err != nil {
		return "", raw
	}
	return candidate, raw[idx+1:]
}

// cursorPath returns the on-disk file used to persist the last-seen
// timestamp for this service.
func (f *Forwarder) cursorPath() string {
	return filepath.Join(logsRootDir, f.serviceID, ".cursor")
}

// readCursor returns the persisted resume timestamp or empty string if none.
func (f *Forwarder) readCursor() string {
	data, err := os.ReadFile(f.cursorPath())
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		return ""
	}
	return s
}

// writeCursor persists the last-seen timestamp. Best-effort: failures are
// logged and ignored, since a missing cursor only causes a brief replay on
// the next start.
func (f *Forwarder) writeCursor() {
	f.mu.Lock()
	ts := f.lastTimestamp
	f.mu.Unlock()
	if ts == "" {
		return
	}

	dir := filepath.Dir(f.cursorPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("runtimelogs[%s]: cursor mkdir: %v", f.serviceID, err)
		return
	}
	if err := os.WriteFile(f.cursorPath(), []byte(ts), 0o644); err != nil {
		log.Printf("runtimelogs[%s]: cursor write: %v", f.serviceID, err)
	}
}
