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
}

func NewStreamer(c *client.Client, operationID string) *Streamer {
	return &Streamer{
		client:      c,
		operationID: operationID,
	}
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
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	lines := s.buffer
	s.buffer = nil
	s.mu.Unlock()

	// Best-effort send — don't block on failure
	_ = s.client.SendLogs(s.operationID, lines)
}
