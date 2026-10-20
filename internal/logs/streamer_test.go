package logs

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func collectLines(t *testing.T, input string, maxLen int) []string {
	t.Helper()
	var got []string
	if err := ReadLines(strings.NewReader(input), maxLen, func(s string) { got = append(got, s) }); err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	return got
}

func TestReadLinesSplitsAndStripsLineEndings(t *testing.T) {
	got := collectLines(t, "a\nb\r\n\nlast", 100)
	want := []string{"a", "b", "", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadLinesTruncatesLongLinesWithMarker(t *testing.T) {
	long := strings.Repeat("x", 300_000)
	got := collectLines(t, "start\n"+long+"\nafter\n", 1000)
	if len(got) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(got))
	}
	if got[0] != "start" || got[2] != "after" {
		t.Fatalf("neighbouring lines corrupted: %q / %q", got[0], got[2])
	}
	if !strings.HasPrefix(got[1], strings.Repeat("x", 1000)+" … [line truncated, 299000 more bytes]") {
		t.Fatalf("unexpected truncated line: %q", got[1][:1100])
	}
}

func TestReadLinesTruncatesOnRuneBoundary(t *testing.T) {
	// "é" is two bytes; a cut after 3 bytes must back off to 2.
	got := collectLines(t, "ééé\n", 3)
	if !strings.HasPrefix(got[0], "é …") {
		t.Fatalf("cut split a rune: %q", got[0])
	}
}

type failingReader struct {
	data     io.Reader
	failed   bool
	drained  bool
	failWith error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		return copy(p, "partial"), f.failWith
	}
	f.drained = true
	return f.data.Read(p)
}

func TestReadLinesDrainsAfterReadError(t *testing.T) {
	fr := &failingReader{data: strings.NewReader("rest of output"), failWith: errors.New("boom")}
	var got []string
	err := ReadLines(fr, 100, func(s string) { got = append(got, s) })
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected boom, got %v", err)
	}
	if !fr.drained {
		t.Fatalf("reader was not drained after the error")
	}
	if len(got) != 1 || got[0] != "partial" {
		t.Fatalf("partial line not emitted: %q", got)
	}
}

// A child writing a multi-megabyte line with no newline must never block on
// the pipe: the reader keeps consuming and only keeps the first MaxLineBytes.
func TestStreamNeverBlocksWriterOnHugeLine(t *testing.T) {
	s := NewStreamer(nil, "op")
	pr, pw := io.Pipe()
	writerDone := make(chan error, 1)
	go func() {
		_, err := pw.Write([]byte(strings.Repeat("y", 8<<20)))
		if err == nil {
			_, err = pw.Write([]byte("\nnext line\n"))
		}
		_ = pw.Close()
		writerDone <- err
	}()
	streamDone := make(chan struct{})
	go func() {
		s.Stream(pr)
		close(streamDone)
	}()
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer blocked on a long line")
	}
	<-streamDone
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buffer) != 2 {
		t.Fatalf("expected 2 buffered lines, got %d", len(s.buffer))
	}
	if len(s.buffer[0]) > MaxLineBytes+200 || !strings.Contains(s.buffer[0], "line truncated") {
		t.Fatalf("long line not truncated (len %d)", len(s.buffer[0]))
	}
	if !strings.HasSuffix(s.buffer[1], "next line") {
		t.Fatalf("line after the long one lost: %q", s.buffer[1])
	}
}

// A slow log endpoint must not slow the child down: Stream buffers (bounded)
// while a separate goroutine sends.
func TestStreamDoesNotBlockOnSlowServer(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		var batch client.LogBatch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		mu.Lock()
		received = append(received, batch.Lines...)
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	s := NewStreamer(client.New(srv.URL, "tok"), "op")
	pr, pw := io.Pipe()
	const total = maxBufferedLines * 3
	writerDone := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			_, _ = pw.Write([]byte("line\n"))
		}
		_ = pw.Close()
		close(writerDone)
	}()
	streamDone := make(chan struct{})
	go func() {
		s.Stream(pr)
		close(streamDone)
	}()

	select {
	case <-writerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writer blocked while the log endpoint was stalled")
	}
	close(release)
	<-streamDone
	s.Flush()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("nothing was sent")
	}
	// The flusher may emit the dropped-lines marker in any batch (and
	// more than once) with normal lines after it, so don't look at a
	// specific position: every input line must be either delivered or
	// counted by some marker.
	markers, dropped, delivered := 0, 0, 0
	for _, l := range received {
		if m := droppedMarkerRe.FindStringSubmatch(l); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("bad marker %q", l)
			}
			markers++
			dropped += n
			continue
		}
		if !strings.HasSuffix(l, "] line") {
			t.Fatalf("unexpected line %q", l)
		}
		delivered++
	}
	if markers == 0 || dropped == 0 {
		t.Fatalf("expected a dropped-lines marker in some batch; got %d lines, none a marker", len(received))
	}
	if dropped+delivered != total {
		t.Fatalf("dropped %d + delivered %d != %d lines written", dropped, delivered, total)
	}
}

var droppedMarkerRe = regexp.MustCompile(`\] \[stacked\] (\d+) log lines dropped`)

// Long lines must hit the byte cap well before the line cap: the buffer
// stays under maxBufferedBytes while the server is stalled, and the
// overflow is reported as dropped lines.
func TestStreamCapsBufferedBytes(t *testing.T) {
	s := NewStreamer(nil, "op")
	line := strings.Repeat("x", MaxLineBytes-100) + "\n"
	const total = 200 // ~12.5 MiB of input, far fewer than maxBufferedLines
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < total; i++ {
			_, _ = pw.Write([]byte(line))
		}
		_ = pw.Close()
	}()

	// Hold the send lock so the background flusher can't drain the
	// buffer, simulating a stalled server.
	s.sendMu.Lock()
	done := make(chan struct{})
	go func() {
		s.Stream(pr)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		kept, dropped, size := len(s.buffer), s.dropped, s.bufferedBytes
		s.mu.Unlock()
		if kept+dropped == total {
			if size > maxBufferedBytes {
				t.Fatalf("buffered %d bytes, cap is %d", size, maxBufferedBytes)
			}
			if dropped == 0 {
				t.Fatal("expected lines to be dropped once the byte cap was reached")
			}
			if kept >= maxBufferedLines {
				t.Fatalf("byte cap did not apply: kept %d lines", kept)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reader stalled: kept=%d dropped=%d", kept, dropped)
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.sendMu.Unlock()
	<-done

	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffer, s.bufferedBytes = nil, 0
}

func TestFlushResetsBufferedBytes(t *testing.T) {
	s := NewStreamer(nil, "op")
	s.AddLine("hello")
	if s.bufferedBytes == 0 {
		t.Fatal("AddLine should count bytes")
	}
	s.Flush()
	if s.bufferedBytes != 0 || len(s.buffer) != 0 {
		t.Fatalf("flush left %d bytes / %d lines", s.bufferedBytes, len(s.buffer))
	}
}
