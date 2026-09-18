package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireTailscale_Missing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := requireTailscale()
	if err == nil {
		t.Fatal("expected error when tailscale is not on PATH")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("error = %q, want it to mention not installed", err)
	}
}

func TestRequireTailscale_Present(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailscale")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if err := requireTailscale(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
