package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMigratePathsAcceptsManagedTarget(t *testing.T) {
	src, tgt, err := validateMigratePaths("/var/lib/docker/volumes/pgdata/_data/", managedVolumeRoot+"svc-1/data/")
	if err != nil {
		t.Fatalf("validateMigratePaths returned error: %v", err)
	}
	if src != "/var/lib/docker/volumes/pgdata/_data" {
		t.Fatalf("source cleaned to %q", src)
	}
	if tgt != filepath.Clean(managedVolumeRoot+"svc-1/data") {
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
		{"dotdot", "/var/lib/docker/volumes/x/_data/../../../../etc"},
		{"nul", "/var/lib/docker/volumes/x/_data\x00tail"},
		{"outside allowlist", "/var/lib/dokploy/data"},
		{"home", "/home/user/data"},
		{"etc", "/etc/shadow"},
		{"lookalike dokploy root", "/etc/dokploy-evil/x"},
		{"dokploy root itself", "/etc/dokploy"},
		{"volumes root itself", "/var/lib/docker/volumes"},
		{"volume metadata", "/var/lib/docker/volumes/metadata.db"},
		{"volume dir not _data", "/var/lib/docker/volumes/x/opts.json"},
		{"docker internals", "/var/lib/docker/containers/abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := validateMigratePaths(c.src, managedVolumeRoot+"svc-1/data")
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
		{"lookalike root", "/opt/stacked/data/services-backup/svc-1/data"},
		{"exact managed root", filepath.Clean(managedVolumeRoot)},
		{"service dir itself", managedVolumeRoot + "svc-1"},
		{"dotdot", managedVolumeRoot + "svc-1/../svc-2/data"},
		{"nul", managedVolumeRoot + "svc-1/data\x00tail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := validateMigratePaths("/etc/dokploy/applications/app/files", c.tgt)
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

	_, _, err := validateMigratePathsWithRoot("/etc/dokploy/applications/app/files", filepath.Join(link, "data"), managedRoot)
	if err == nil {
		t.Fatalf("expected symlink escape to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside") {
		t.Fatalf("expected resolves outside error, got %v", err)
	}
}

func TestMigrateSourceMount(t *testing.T) {
	cases := []struct{ src, mount, rel string }{
		{"/var/lib/docker/volumes/pg/_data", "/var/lib/docker/volumes/pg/_data", "."},
		{"/var/lib/docker/volumes/pg/_data/sub/dir", "/var/lib/docker/volumes/pg/_data", "sub/dir"},
		{"/etc/dokploy/applications/app/files/x.conf", "/etc/dokploy", "applications/app/files/x.conf"},
	}
	for _, c := range cases {
		mount, rel, err := migrateSourceMount(c.src)
		if err != nil || mount != c.mount || rel != c.rel {
			t.Fatalf("migrateSourceMount(%q) = %q, %q, %v; want %q, %q", c.src, mount, rel, err, c.mount, c.rel)
		}
	}
}

func TestVolumeMigrateDockerArgsAreConfined(t *testing.T) {
	args := strings.Join(volumeMigrateDockerArgs("/etc/dokploy", "applications/a", "/opt/stacked/data/services/s/x", "vol"), " ")
	for _, want := range []string{
		"type=bind,source=/etc/dokploy,target=/src,readonly",
		"type=bind,source=/opt/stacked/data/services/s/x,target=/dst",
		"--network none", "--cap-drop ALL", "no-new-privileges", migrateHelperImage,
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %q", want, args)
		}
	}
	if strings.Contains(args, "--privileged") || strings.Contains(args, "SYS_ADMIN") {
		t.Fatalf("helper must not be privileged: %q", args)
	}
}

func TestRejectSymlinksInPath(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// t.TempDir may itself sit under a symlinked dir (macOS /var); resolve it.
	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	resolvedBase := filepath.Dir(resolvedReal)
	if err := rejectSymlinksInPath(filepath.Join(resolvedReal, "sub", "missing"), false); err != nil {
		t.Fatalf("plain path rejected: %v", err)
	}
	if err := rejectSymlinksInPath(filepath.Join(resolvedBase, "link", "sub"), false); err == nil {
		t.Fatalf("symlink component not rejected")
	}
	if err := rejectSymlinksInPath(filepath.Join(resolvedBase, "link"), false); err == nil {
		t.Fatalf("symlink final component not rejected")
	}
}
