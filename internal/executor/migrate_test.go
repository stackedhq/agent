package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMigratePathsAcceptsManagedTarget(t *testing.T) {
	target := managedVolumeRoot + testServiceID + "/data/"
	src, tgt, err := validateMigratePaths("/var/lib/dokploy/data/", target)
	if err != nil {
		t.Fatalf("validateMigratePaths returned error: %v", err)
	}
	if src != "/var/lib/dokploy/data" {
		t.Fatalf("source cleaned to %q", src)
	}
	if tgt != filepath.Clean(managedVolumeRoot+testServiceID+"/data") {
		t.Fatalf("target cleaned to %q", tgt)
	}
}

func TestValidateMigratePathsRejectsUnsafeSource(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"empty", ""},
		{"relative", "var/lib/data"},
		{"dotdot", "/var/lib/../etc"},
		{"nul", "/var/lib/data\x00tail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := validateMigratePaths(c.src, managedVolumeRoot+testServiceID+"/data")
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestValidateMigratePathsRejectsUnsafeTarget(t *testing.T) {
	cases := []struct {
		name string
		tgt  string
	}{
		{"empty", ""},
		{"relative", "opt/stacked/data/services/svc-1/data"},
		{"outside managed root", "/etc"},
		{"lookalike root", "/opt/stacked/data/services-backup/" + testServiceID + "/data"},
		{"exact managed root", filepath.Clean(managedVolumeRoot)},
		{"non-uuid service", managedVolumeRoot + "svc-1/data"},
		{"dotdot", managedVolumeRoot + testServiceID + "/../svc-2/data"},
		{"nul", managedVolumeRoot + testServiceID + "/data\x00tail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := validateMigratePaths("/var/lib/dokploy/data", c.tgt)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestValidateMigratePathsRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	managedRoot := filepath.Join(base, "managed")
	if err := os.MkdirAll(managedRoot, 0o755); err != nil {
		t.Fatalf("mkdir managed root: %v", err)
	}
	outside := t.TempDir()
	link := filepath.Join(managedRoot, "svc-1")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}

	_, _, err := validateMigratePathsWithRoot("/var/lib/dokploy/data", filepath.Join(link, "data"), managedRoot)
	if err == nil {
		t.Fatalf("expected symlink escape to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("expected resolves outside error, got %v", err)
	}
}
