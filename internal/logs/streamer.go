package logs

import (
	"bufio"
	"io"
	"sync"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const (
	flushInterval = 1 * time.Second
	maxBatchSize  = 50
)

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
	line := "[" + time.Now().UTC().Format("15:04:05") + "] " + msg
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
		line := "[" + time.Now().UTC().Format("15:04:05") + "] " + scanner.Text()
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
