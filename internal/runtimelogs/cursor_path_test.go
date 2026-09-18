package runtimelogs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteCursorRejectsMalformedServiceID(t *testing.T) {
	root := t.TempDir()
	prev := logsRootDir
	logsRootDir = filepath.Join(root, "logs")
	t.Cleanup(func() { logsRootDir = prev })
	if err := os.MkdirAll(logsRootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "SENTINEL")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &Forwarder{
		serviceID:     "..",
		lastTimestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if _, ok := f.cursorPath(); ok {
		t.Fatal("cursorPath must reject ..")
	}
	f.writeCursor()

	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("cursor write escaped logs root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".cursor")); !os.IsNotExist(err) {
		t.Fatal("wrote .cursor on the parent of logsRootDir")
	}
	if entries, err := os.ReadDir(logsRootDir); err != nil {
		t.Fatal(err)
	} else if len(entries) != 0 {
		t.Fatalf("wrote under logs root: %v", entries)
	}
}
