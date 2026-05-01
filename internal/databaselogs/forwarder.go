package databaselogs

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
	flushInterval = 1 * time.Second
	maxBatchSize  = 50

	maxLineBytes = 8 * 1024

	// Cursors live alongside the per-database working dir's sibling tree
	// so they're easy to wipe with the database itself if it's destroyed.
	logsRootDir = "/opt/stacked/logs/db"
)

// Forwarder runs `docker logs -f --timestamps` for one database container
// and pushes batched lines to the server. Stop via Stop().
type Forwarder struct {
	databaseID  string
	containerID string
	client      *client.Client

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu     sync.Mutex
	buffer []string

	lastTimestamp string
}

func NewForwarder(c *client.Client, databaseID, containerID string) *Forwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &Forwarder{
		databaseID:  databaseID,
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
		// First run for this database: avoid replaying days of init logs
		// after a fresh agent process attaches to a long-running DB.
		args = append(args, "--since", "1m")
	}
	args = append(args, f.containerID)

	cmd := exec.CommandContext(f.ctx, "docker", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("databaselogs[%s]: stdout pipe: %v", f.databaseID, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("databaselogs[%s]: stderr pipe: %v", f.databaseID, err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("databaselogs[%s]: docker logs start: %v", f.databaseID, err)
		return
	}

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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); f.scan(stdout) }()
	go func() { defer wg.Done(); f.scan(stderr) }()
	wg.Wait()

	close(flushDone)
	f.flush()

	_ = cmd.Wait()

	f.writeCursor()
}

func (f *Forwarder) Stop() {
	f.cancel()
	<-f.done
}

func (f *Forwarder) scan(r io.Reader) {
	scanner := bufio.NewScanner(r)
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
}

func (f *Forwarder) flush() {
	f.mu.Lock()
	if len(f.buffer) == 0 {
		f.mu.Unlock()
		return
	}
	batch := f.buffer
	f.buffer = nil
	f.mu.Unlock()

	if err := f.client.SendDatabaseLogs(f.databaseID, batch); err != nil {
		log.Printf("databaselogs[%s]: send failed (%d lines dropped): %v", f.databaseID, len(batch), err)
	}
}

// splitTimestamp pulls the leading RFC3339Nano timestamp prepended by
// `docker logs --timestamps`. Returns ("", raw) if no timestamp is found.
func splitTimestamp(raw string) (ts, rest string) {
	idx := strings.IndexByte(raw, ' ')
	if idx <= 0 {
		return "", raw
	}
	candidate := raw[:idx]
	if !strings.Contains(candidate, "T") {
		return "", raw
	}
	if _, err := time.Parse(time.RFC3339Nano, candidate); err != nil {
		return "", raw
	}
	return candidate, raw[idx+1:]
}

func (f *Forwarder) cursorPath() string {
	return filepath.Join(logsRootDir, f.databaseID, ".cursor")
}

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

func (f *Forwarder) writeCursor() {
	f.mu.Lock()
	ts := f.lastTimestamp
	f.mu.Unlock()
	if ts == "" {
		return
	}

	dir := filepath.Dir(f.cursorPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("databaselogs[%s]: cursor mkdir: %v", f.databaseID, err)
		return
	}
	if err := os.WriteFile(f.cursorPath(), []byte(ts), 0o644); err != nil {
		log.Printf("databaselogs[%s]: cursor write: %v", f.databaseID, err)
	}
}
