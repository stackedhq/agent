package runtimelogs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Archiver mirrors the per-service Forwarder, but instead of pushing every
// line to the live SSE pipeline it batches lines into gzipped NDJSON
// chunks and uploads them directly to R2 via short-lived presigned PUT
// URLs. The server only sees a manifest row.
//
// One Archiver per running container, owned by the Forwarder for
// lifecycle parity. Stop() drains the buffer before returning.
type Archiver struct {
	serviceID string
	client    *client.Client
	httpC     *http.Client

	mu     sync.Mutex
	buf    bytes.Buffer
	lines  int
	fromTs time.Time
	lastTs time.Time

	// Set to non-zero once the server has told us archival is disabled
	// (or we've seen too many consecutive failures to bother). Cheap
	// fast-path so Add() doesn't bother building NDJSON we'll throw
	// away. Reset only by process restart.
	disabled atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// archiveRecord is the on-the-wire NDJSON shape per log line. Kept
// intentionally minimal — adding fields later is forward-compat as long
// as the reader skips unknown keys (the dashboard's `JSON.parse` does).
// `Lvl` is "info" (stdout) or "error" (stderr); omitted for legacy chunks
// that pre-date severity tagging.
type archiveRecord struct {
	Ts  string `json:"ts,omitempty"`
	Lvl string `json:"lvl,omitempty"`
	Msg string `json:"msg"`
}

const (
	// Whichever fires first.
	archiveFlushInterval = 60 * time.Second
	// Raw NDJSON cap. Log text typically gzips ~4×, so this lands near
	// the agreed 256 KiB compressed target without us having to track
	// gzip output size mid-write.
	archiveMaxRawBytes = 1 * 1024 * 1024
)

func NewArchiver(c *client.Client, serviceID string) *Archiver {
	ctx, cancel := context.WithCancel(context.Background())
	return &Archiver{
		serviceID: serviceID,
		client:    c,
		httpC:     &http.Client{Timeout: 60 * time.Second},
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
}

// Run drives the periodic flush loop until Stop is called. Always closes
// `done` before returning, even if the final drain fails.
func (a *Archiver) Run() {
	defer close(a.done)
	t := time.NewTicker(archiveFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flush()
		case <-a.ctx.Done():
			a.flush() // final drain on shutdown
			return
		}
	}
}

// Stop signals the archiver to drain and exit. Returns once Run unwinds.
func (a *Archiver) Stop() {
	a.cancel()
	<-a.done
}

// Add buffers one log line. Called from Forwarder.scan() in addition to
// the live forward path. The Forwarder owns the line-truncation policy,
// so this is a pure append.
func (a *Archiver) Add(ts, lvl, line string) {
	if a.disabled.Load() {
		return
	}
	rec := archiveRecord{Ts: ts, Lvl: lvl, Msg: line}
	data, err := json.Marshal(&rec)
	if err != nil {
		return
	}

	var t time.Time
	if ts != "" {
		if parsed, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			t = parsed
		}
	}

	a.mu.Lock()
	if a.lines == 0 && !t.IsZero() {
		a.fromTs = t
	}
	if !t.IsZero() {
		a.lastTs = t
	}
	a.buf.Write(data)
	a.buf.WriteByte('\n')
	a.lines++
	shouldFlush := a.buf.Len() >= archiveMaxRawBytes
	a.mu.Unlock()

	if shouldFlush {
		a.flush()
	}
}

// flush snapshots the buffer, gzips it, requests a presigned PUT URL,
// uploads, and confirms. Errors at any stage drop the chunk — runtime
// logs are best-effort by design and we'd rather lose a window than back
// up the live forwarder.
func (a *Archiver) flush() {
	if a.disabled.Load() {
		return
	}
	a.mu.Lock()
	if a.lines == 0 {
		a.mu.Unlock()
		return
	}
	raw := make([]byte, a.buf.Len())
	copy(raw, a.buf.Bytes())
	lines := a.lines
	fromTs := a.fromTs
	lastTs := a.lastTs
	a.buf.Reset()
	a.lines = 0
	a.fromTs = time.Time{}
	a.lastTs = time.Time{}
	a.mu.Unlock()

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(raw); err != nil {
		log.Printf("archiver[%s]: gzip write: %v", a.serviceID, err)
		return
	}
	if err := gw.Close(); err != nil {
		log.Printf("archiver[%s]: gzip close: %v", a.serviceID, err)
		return
	}
	gzipped := gz.Bytes()

	issued, err := a.client.RequestLogArchiveURL(a.serviceID)
	if err != nil {
		if errors.Is(err, client.ErrArchivalDisabled) {
			log.Printf("archiver[%s]: archival disabled by server; skipping further uploads", a.serviceID)
			a.disabled.Store(true)
			return
		}
		log.Printf("archiver[%s]: request URL failed (chunk dropped: %d lines): %v", a.serviceID, lines, err)
		return
	}

	req, err := http.NewRequestWithContext(a.ctx, "PUT", issued.URL, bytes.NewReader(gzipped))
	if err != nil {
		log.Printf("archiver[%s]: build PUT: %v", a.serviceID, err)
		return
	}
	req.ContentLength = int64(len(gzipped))
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := a.httpC.Do(req)
	if err != nil {
		log.Printf("archiver[%s]: PUT failed: %v", a.serviceID, err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("archiver[%s]: PUT %d: %s", a.serviceID, resp.StatusCode, snippet(body))
		return
	}

	confirm := &client.LogArchiveConfirm{
		Key:       issued.Key,
		SizeBytes: len(gzipped),
		LineCount: lines,
	}
	if !fromTs.IsZero() {
		confirm.FromTs = fromTs.Format(time.RFC3339Nano)
	}
	if !lastTs.IsZero() {
		confirm.ToTs = lastTs.Format(time.RFC3339Nano)
	}
	if err := a.client.ConfirmLogArchive(a.serviceID, confirm); err != nil {
		if errors.Is(err, client.ErrArchivalDisabled) {
			a.disabled.Store(true)
			return
		}
		// Non-fatal: object is already in R2 and lifecycle will GC it
		// in 30 days if confirm never lands. We just lose the manifest
		// row, which means this chunk won't be readable from the
		// dashboard. Log and move on.
		log.Printf("archiver[%s]: confirm failed (chunk in R2 but unmanifested): %v", a.serviceID, err)
	}
}

func snippet(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return fmt.Sprintf("%s…", string(b[:max]))
}
