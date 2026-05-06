package slots

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempStateFile redirects the package-level stateFile path to a
// per-test tmpdir so the tests don't fight each other or the real
// /opt/stacked file. Returns a restore func.
func withTempStateFile(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	prev := stateFile
	stateFile = filepath.Join(dir, "active-slots.json")
	return func() { stateFile = prev }
}

func TestActiveReturnsEmptyWhenNoFile(t *testing.T) {
	defer withTempStateFile(t)()
	if got := Active("svc-a"); got != "" {
		t.Fatalf("expected empty slot, got %q", got)
	}
}

func TestSetActiveAndRead(t *testing.T) {
	defer withTempStateFile(t)()
	if err := SetActive("svc-a", Blue); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if got := Active("svc-a"); got != Blue {
		t.Fatalf("expected blue, got %q", got)
	}
	if err := SetActive("svc-a", Green); err != nil {
		t.Fatalf("SetActive overwrite: %v", err)
	}
	if got := Active("svc-a"); got != Green {
		t.Fatalf("expected green after overwrite, got %q", got)
	}
}

func TestClearRemovesEntry(t *testing.T) {
	defer withTempStateFile(t)()
	_ = SetActive("svc-a", Blue)
	_ = SetActive("svc-b", Green)
	if err := Clear("svc-a"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := Active("svc-a"); got != "" {
		t.Fatalf("expected empty after clear, got %q", got)
	}
	if got := Active("svc-b"); got != Green {
		t.Fatalf("svc-b should be unaffected, got %q", got)
	}
}

func TestAllReturnsCopy(t *testing.T) {
	defer withTempStateFile(t)()
	_ = SetActive("svc-a", Blue)
	m := All()
	m["svc-a"] = Green // mutate the returned copy
	if got := Active("svc-a"); got != Blue {
		t.Fatalf("All() must return a defensive copy; got %q", got)
	}
}

func TestOther(t *testing.T) {
	cases := []struct {
		in, want Slot
	}{
		{Blue, Green},
		{Green, Blue},
		{"", Blue},       // no state -> default first slot
		{Legacy, Blue},   // legacy migrates to blue on first flip
	}
	for _, c := range cases {
		if got := c.in.Other(); got != c.want {
			t.Errorf("(%q).Other() = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCorruptFileFallsBackToEmpty(t *testing.T) {
	defer withTempStateFile(t)()
	// Write garbage so JSON unmarshal fails.
	if err := os.WriteFile(stateFile, []byte("{not json"), 0644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if got := Active("svc-a"); got != "" {
		t.Fatalf("expected empty for corrupt file, got %q", got)
	}
	// Subsequent SetActive should heal the file.
	if err := SetActive("svc-a", Blue); err != nil {
		t.Fatalf("SetActive on corrupt file: %v", err)
	}
	if got := Active("svc-a"); got != Blue {
		t.Fatalf("expected blue after heal, got %q", got)
	}
}
