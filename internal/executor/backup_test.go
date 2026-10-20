package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(s))
	_ = gw.Close()
	return buf.Bytes()
}

// backupServer serves the agent download-url endpoint (with an optional
// sha256) and the object itself.
func backupServer(t *testing.T, objectStatus int, object []byte, sha string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/download-url"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{
				"url": srv.URL + "/object", "key": "k", "sha256": sha,
			}})
		case r.URL.Path == "/object":
			w.WriteHeader(objectStatus)
			_, _ = w.Write(object)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useTempBackupDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := backupTmpDir
	backupTmpDir = dir
	t.Cleanup(func() { backupTmpDir = prev })
	return dir
}

func dirEmpty(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries) == 0
}

func TestDownloadBackupToFile(t *testing.T) {
	good := gzipBytes(t, "dump bytes")
	sum := sha256.Sum256(good)
	goodSha := hex.EncodeToString(sum[:])
	truncated := good[:len(good)-6]

	cases := []struct {
		name    string
		status  int
		body    []byte
		sha     string
		wantErr string
	}{
		{"ok with checksum", 200, good, goodSha, ""},
		{"ok without checksum", 200, good, "", ""},
		{"missing object", 404, []byte("NoSuchKey"), "", "404"},
		{"checksum mismatch", 200, good, strings.Repeat("a", 64), "checksum mismatch"},
		{"truncated gzip", 200, truncated, "", "corrupt or truncated"},
		{"not gzip", 200, []byte("plain text"), "", "not a valid gzip"},
		{"empty", 200, nil, "", "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := useTempBackupDir(t)
			srv := backupServer(t, c.status, c.body, c.sha)
			path, err := downloadBackupToFile(client.New(srv.URL, "tok"), "b1")
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				info, statErr := os.Stat(path)
				if statErr != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("download file mode: %v %v", info, statErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
			if !dirEmpty(t, dir) {
				t.Fatalf("failed download left a temp file behind")
			}
		})
	}
}

// Gzip verification honours the op deadline: an already-expired op stops
// it before any decompression, with an error that says why.
func TestVerifyBackupFileStopsOnCancelledOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.gz")
	if err := os.WriteFile(path, gzipBytes(t, strings.Repeat("row\n", 1<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupFile(path, "", ""); err != nil {
		t.Fatalf("valid dump rejected: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restore := setOpContext(ctx)
	defer restore()
	err := verifyBackupFile(path, "", "")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "verification stopped") {
		t.Fatalf("expected verification to stop on the cancelled op, got %v", err)
	}
}

// infiniteZeros is an endless stream that cancels ctx once it has served
// cancelAfter bytes.
type infiniteZeros struct {
	served, cancelAfter int64
	cancel              func()
}

func (z *infiniteZeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	z.served += int64(len(p))
	if z.served >= z.cancelAfter {
		z.cancel()
	}
	return len(p), nil
}

// A deadline that expires mid-read stops the reader within one check
// interval.
func TestOpCtxReaderStopsWithinCheckInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &infiniteZeros{cancelAfter: 3 << 20, cancel: cancel}
	n, err := io.Copy(io.Discard, newOpCtxReader(ctx, src))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if n < 3<<20 || n > 3<<20+2*opCtxCheckBytes {
		t.Fatalf("read %d bytes after cancelling at %d", n, 3<<20)
	}
}
