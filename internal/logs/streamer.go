package logs

import (
	"bufio"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const (
	flushInterval = 1 * time.Second
	maxBatchSize  = 50
)

// tokenURLPattern matches the `x-access-token:<token>@github.com` shape
// we embed installation tokens into for `git clone`. When git or any
// downstream tool echoes the clone URL on failure, this regex strips
// the token so it doesn't end up in the deploy log streamed to the
// dashboard (or, worse, archived to R2).
//
// The token character class is length-agnostic on purpose: GitHub's new
// stateless `ghs_…` JWT format (rolling out per the May 2026 changelog)
// can be ~520 chars and contains dots and underscores. We match
// anything that isn't `@` or whitespace.
var tokenURLPattern = regexp.MustCompile(`x-access-token:[^@\s]+@`)

// redactLine strips embedded installation tokens from a log line. Safe
// to apply unconditionally — lines without the pattern are returned
// unchanged.
func redactLine(s string) string {
	return tokenURLPattern.ReplaceAllString(s, "x-access-token:***@")
}

// Streamer reads lines from an io.Reader and batches them to the Stacked API.
type Streamer struct {
	client      *client.Client
	operationID string
	mu          sync.Mutex
	buffer      []string
	progress    *int
}

func NewStreamer(c *client.Client, operationID string) *Streamer {
	return &Streamer{
		client:      c,
		operationID: operationID,
	}
}

// SetProgress sets the current deploy progress percentage (0-100).
func (s *Streamer) SetProgress(p int) {
	s.mu.Lock()
	s.progress = &p
	s.mu.Unlock()
}

// AddLine injects a synthetic log line into the buffer.
func (s *Streamer) AddLine(msg string) {
	line := "[" + time.Now().UTC().Format("15:04:05") + "] " + redactLine(msg)
	s.mu.Lock()
	s.buffer = append(s.buffer, line)
	s.mu.Unlock()
}

// Stream reads lines from r, batching and sending them to the server.
// Blocks until r is closed/EOF. Call Flush() after to send remaining lines.
func (s *Streamer) Stream(r io.Reader) {
	scanner := bufio.NewScanner(r)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	// Flush on timer in background
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				s.flush()
			case <-done:
				return
			}
		}
	}()

	for scanner.Scan() {
		line := "[" + time.Now().UTC().Format("15:04:05") + "] " + redactLine(scanner.Text())
		s.mu.Lock()
		s.buffer = append(s.buffer, line)
		shouldFlush := len(s.buffer) >= maxBatchSize
		s.mu.Unlock()

		if shouldFlush {
			s.flush()
		}
	}

	close(done)
}

// Flush sends any remaining buffered lines to the server.
func (s *Streamer) Flush() {
	s.flush()
}

func (s *Streamer) flush() {
	s.mu.Lock()
	if len(s.buffer) == 0 && s.progress == nil {
		s.mu.Unlock()
		return
	}
	lines := s.buffer
	s.buffer = nil
	progress := s.progress
	// Clear progress after capturing so we don't re-send the same value
	s.progress = nil
	s.mu.Unlock()

	// Best-effort send — don't block on failure
	_ = s.client.SendLogs(s.operationID, lines, progress)
}
