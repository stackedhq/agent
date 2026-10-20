package runtimelogs

import "testing"

func TestCursorPathRequiresUUID(t *testing.T) {
	for _, id := range []string{"../../etc", "proxy", ""} {
		f := &Forwarder{serviceID: id}
		if p := f.cursorPath(); p != "" {
			t.Fatalf("cursorPath(%q) = %q, want empty", id, p)
		}
		f.lastTimestamp = "2026-01-01T00:00:00Z"
		f.writeCursor() // must be a no-op, not a write outside logsRootDir
		if f.readCursor() != "" {
			t.Fatalf("readCursor for %q should be empty", id)
		}
	}
	f := &Forwarder{serviceID: "11111111-1111-1111-1111-111111111111"}
	if f.cursorPath() == "" {
		t.Fatalf("valid UUID rejected")
	}
}
