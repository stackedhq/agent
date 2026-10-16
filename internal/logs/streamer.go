package logs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const (
	flushInterval = 1 * time.Second
	maxBatchSize  = 50

	// MaxLineBytes caps one log line. The server keeps only the last
	// ~512 KiB of an operation's log, so longer lines are noise.
	MaxLineBytes = 64 << 10
	// readChunkBytes is the bufio buffer used by ReadLines.
	readChunkBytes = 64 << 10
	// maxBufferedLines bounds memory while the server is slow; further
	// streamed lines are dropped (and counted) instead of blocking the
	// child process.
	maxBufferedLines = 10000
	// maxBufferedBytes bounds the same buffer by size: 10000 lines of up
	// to MaxLineBytes each would otherwise be ~640 MiB.
	maxBufferedBytes = 4 << 20
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
//
// Reading never waits on the network: Stream only appends to an in-memory
// buffer (bounded, see maxBufferedLines / maxBufferedBytes) and a separate goroutine does the
// HTTP sends. A child process writing to the pipe therefore never blocks
// because the server is slow, and an over-long line is truncated instead of
// stopping the reader.
type Streamer struct {
	client      *client.Client
	operationID string
	mu          sync.Mutex
	buffer      []string
	// bufferedBytes is the total length of the lines in buffer.
	bufferedBytes int
	progress      *int
	// dropped counts streamed lines discarded because the buffer was full.
	dropped int
	// sendMu serialises sends so batches reach the server in order.
	sendMu sync.Mutex
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
	s.bufferedBytes += len(line)
	s.mu.Unlock()
}

// Stream reads lines from r, batching and sending them to the server.
// Blocks until r is closed/EOF (or fails, in which case the rest of r is
// drained). Call Flush() after to send remaining lines.
func (s *Streamer) Stream(r io.Reader) {
	kick := make(chan struct{}, 1)
	done := make(chan struct{})
	flusherDone := make(chan struct{})
	go func() {
		defer close(flusherDone)
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.flush()
			case <-kick:
				s.flush()
			case <-done:
				return
			}
		}
	}()

	_ = ReadLines(r, MaxLineBytes, func(text string) {
		line := "[" + time.Now().UTC().Format("15:04:05") + "] " + redactLine(text)
		s.mu.Lock()
		if len(s.buffer) >= maxBufferedLines || s.bufferedBytes+len(line) > maxBufferedBytes {
			s.dropped++
			s.mu.Unlock()
			return
		}
		s.buffer = append(s.buffer, line)
		s.bufferedBytes += len(line)
		shouldFlush := len(s.buffer) >= maxBatchSize
		s.mu.Unlock()

		if shouldFlush {
			// Never block the reader on a send: the flusher picks
			// this up as soon as its current send finishes.
			select {
			case kick <- struct{}{}:
			default:
			}
		}
	})

	close(done)
	<-flusherDone
}

// Flush sends any remaining buffered lines to the server.
func (s *Streamer) Flush() {
	s.flush()
}

func (s *Streamer) flush() {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.mu.Lock()
	if s.dropped > 0 {
		s.buffer = append(s.buffer, fmt.Sprintf("[%s] [stacked] %d log lines dropped: output arrived faster than it could be uploaded",
			time.Now().UTC().Format("15:04:05"), s.dropped))
		s.dropped = 0
	}
	if len(s.buffer) == 0 && s.progress == nil {
		s.mu.Unlock()
		return
	}
	lines := s.buffer
	s.buffer = nil
	s.bufferedBytes = 0
	progress := s.progress
	// Clear progress after capturing so we don't re-send the same value
	s.progress = nil
	s.mu.Unlock()

	if s.client == nil {
		return
	}
	// Best-effort send — don't block on failure
	_ = s.client.SendLogs(s.operationID, lines, progress)
}

// ReadLines calls fn for every line of r (without the trailing "\n" or
// "\r\n"). A line longer than maxLen bytes is cut at a UTF-8 boundary and
// gets a truncation marker; the rest of it is discarded without being
// buffered, so a child that prints megabytes without a newline can't make
// the reader stop. If reading fails, the remainder of r is drained to
// io.Discard so the writer is never left blocked on a full pipe, and the
// read error is returned. EOF returns nil.
func ReadLines(r io.Reader, maxLen int, fn func(string)) error {
	if maxLen <= 0 {
		maxLen = MaxLineBytes
	}
	br := bufio.NewReaderSize(r, readChunkBytes)
	var line []byte
	skipped := 0
	emit := func() {
		text := string(line)
		if skipped > 0 {
			text += fmt.Sprintf(" … [line truncated, %d more bytes]", skipped)
		}
		fn(text)
		line = line[:0]
		skipped = 0
	}
	for {
		chunk, err := br.ReadSlice('\n')
		complete := err == nil
		if complete {
			chunk = chunk[:len(chunk)-1]
			if n := len(chunk); n > 0 && chunk[n-1] == '\r' {
				chunk = chunk[:n-1]
			}
		}
		if len(chunk) > 0 {
			room := maxLen - len(line)
			if skipped > 0 || room <= 0 {
				skipped += len(chunk)
			} else if len(chunk) <= room {
				line = append(line, chunk...)
			} else {
				cut := room
				for cut > 0 && !utf8.RuneStart(chunk[cut]) {
					cut--
				}
				line = append(line, chunk[:cut]...)
				skipped += len(chunk) - cut
			}
		}
		switch {
		case complete:
			emit()
		case errors.Is(err, bufio.ErrBufferFull):
			// Mid-line; keep reading.
		case errors.Is(err, io.EOF):
			if len(line) > 0 || skipped > 0 {
				emit()
			}
			return nil
		default:
			if len(line) > 0 || skipped > 0 {
				emit()
			}
			_, _ = io.Copy(io.Discard, r)
			return err
		}
	}
}
