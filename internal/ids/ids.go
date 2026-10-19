// Package ids validates service/database identifiers before they are
// joined into filesystem paths. Control-plane UUIDs are the only legal
// names under /opt/stacked/{services,databases,logs,...}; anything else
// (including ".", "..", absolute paths, and separator-bearing strings)
// is rejected before any side effect.
package ids

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Valid reports whether s is an 8-4-4-4-12 hex UUID. Case-insensitive
// on the hex digits; version/variant bits are not checked — we only
// need a closed character set that cannot form a path component other
// than itself.
func Valid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// Validate rejects empty, ".", "..", absolute, separator-containing,
// and non-UUID identifiers. Call this before any I/O keyed by the ID.
func Validate(id string) error {
	if id == "" {
		return fmt.Errorf("id is empty")
	}
	if id == "." || id == ".." {
		return fmt.Errorf("id %q is not a UUID", id)
	}
	if filepath.IsAbs(id) || strings.HasPrefix(id, "/") || strings.HasPrefix(id, `\`) {
		return fmt.Errorf("id must not be an absolute path")
	}
	if strings.ContainsAny(id, `/\`) || strings.ContainsRune(id, filepath.Separator) {
		return fmt.Errorf("id must not contain path separators")
	}
	if !Valid(id) {
		return fmt.Errorf("id %q is not a UUID", id)
	}
	return nil
}

// Child joins id under root and verifies the result is exactly one
// directory component beneath that root. Validation happens first so
// filepath.Join never sees a traversal token.
func Child(root, id string) (string, error) {
	if err := Validate(id); err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	resolved := filepath.Join(root, id)
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return "", fmt.Errorf("resolve %q under %s: %w", id, root, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("id %q escapes %s", id, root)
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("id %q escapes %s", id, root)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 1 || parts[0] == "" || parts[0] == "." || parts[0] == ".." || parts[0] != id {
		return "", fmt.Errorf("id %q is not a single child of %s", id, root)
	}
	return resolved, nil
}
