package ids

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validID = "ebe83b46-8e71-4bec-b21e-8ec9812c8af6"

func TestValid(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{validID, true},
		{"EBE83B46-8E71-4BEC-B21E-8EC9812C8AF6", true},
		{"00000000-0000-0000-0000-000000000000", true},
		{"", false},
		{".", false},
		{"..", false},
		{"proxy", false},
		{"not-a-uuid", false},
		{"ebe83b468-e71-4bec-b21e-8ec9812c8af6", false},
		{"gbe83b46-8e71-4bec-b21e-8ec9812c8af6", false},
		{validID + "x", false},
		{"/tmp/" + validID, false},
		{validID + "/../" + validID, false},
	}
	for _, c := range cases {
		if got := Valid(c.in); got != c.want {
			t.Errorf("Valid(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	bads := []string{
		"",
		".",
		"..",
		"/",
		"/etc/passwd",
		"/opt/stacked/services/" + validID,
		`\windows\path`,
		"foo/bar",
		`foo\bar`,
		"../" + validID,
		validID + "/..",
		"not-a-uuid",
		"svc-1",
	}
	for _, id := range bads {
		if err := Validate(id); err == nil {
			t.Errorf("Validate(%q) = nil, want error", id)
		}
	}
	if err := Validate(validID); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
}

func TestChildConfines(t *testing.T) {
	root := filepath.Join(t.TempDir(), "services")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Child(root, validID)
	if err != nil {
		t.Fatalf("Child(valid): %v", err)
	}
	want := filepath.Join(root, validID)
	if got != want {
		t.Fatalf("Child = %q, want %q", got, want)
	}
	rel, err := filepath.Rel(root, got)
	if err != nil || rel != validID || strings.ContainsRune(rel, filepath.Separator) {
		t.Fatalf("resolved %q is not a single child of %s", got, root)
	}

	for _, id := range []string{"", ".", "..", "/", "foo/bar", validID + "/../x", "not-a-uuid"} {
		if path, err := Child(root, id); err == nil {
			t.Errorf("Child(%q) = %q, want error", id, path)
		}
	}
}
