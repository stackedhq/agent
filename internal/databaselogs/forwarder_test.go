package databaselogs

import "testing"

func TestCursorPathRequiresUUID(t *testing.T) {
	for _, id := range []string{"../../etc", "proxy", "", "11111111-1111-1111-1111-11111111111/"} {
		f := &Forwarder{databaseID: id}
		if p := f.cursorPath(); p != "" {
			t.Fatalf("cursorPath(%q) = %q, want empty", id, p)
		}
	}
	f := &Forwarder{databaseID: "11111111-1111-1111-1111-111111111111"}
	if f.cursorPath() == "" {
		t.Fatalf("valid UUID rejected")
	}
}
