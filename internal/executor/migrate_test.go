package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o600)
}

func mustEval(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("eval %s: %v", path, err)
	}
	return filepath.Clean(resolved)
}

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
		{"root", "/"},
		{"etc", "/etc"},
		{"passwd", "/etc/passwd"},
		{"docker state", "/var/lib/docker/volumes/foo/_data"},
		{"containerd", "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"},
		{"stacked internals", "/opt/stacked/agent.toml"},
		{"proc", "/proc/1/environ"},
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

func TestResolveVolumeMigrateIdentityBindsToCredentials(t *testing.T) {
	creds := &client.MigrationCredentials{
		Kind:       "volume",
		SourcePath: "/etc/dokploy/compose/app/data/",
		TargetPath: managedVolumeRoot + "svc-1/data/",
		Source:     &client.MigrationDBCreds{ContainerName: "dokploy-app-1"},
	}
	src, tgt, container, err := resolveVolumeMigrateIdentity(map[string]interface{}{
		"sourceVolumePath":    "/etc/dokploy/compose/app/data",
		"targetVolumePath":    managedVolumeRoot + "svc-1/data",
		"sourceContainerName": "dokploy-app-1",
	}, creds)
	if err != nil {
		t.Fatalf("resolveVolumeMigrateIdentity: %v", err)
	}
	if src != "/etc/dokploy/compose/app/data" {
		t.Fatalf("src=%q", src)
	}
	if tgt != filepath.Clean(managedVolumeRoot+"svc-1/data") {
		t.Fatalf("tgt=%q", tgt)
	}
	if container != "dokploy-app-1" {
		t.Fatalf("container=%q", container)
	}
}

func TestResolveVolumeMigrateIdentityRejectsMismatchedPath(t *testing.T) {
	creds := &client.MigrationCredentials{
		Kind:       "volume",
		SourcePath: "/etc/dokploy/compose/app/data",
		TargetPath: managedVolumeRoot + "svc-1/data",
		Source:     &client.MigrationDBCreds{ContainerName: "dokploy-app-1"},
	}
	_, _, _, err := resolveVolumeMigrateIdentity(map[string]interface{}{
		"sourceVolumePath": "/",
		"targetVolumePath": managedVolumeRoot + "svc-1/data",
	}, creds)
	if err == nil {
		t.Fatal("expected mismatched source path to be rejected")
	}
}

func TestResolveVolumeMigrateIdentityRejectsMismatchedContainer(t *testing.T) {
	creds := &client.MigrationCredentials{
		Kind:       "volume",
		SourcePath: "/etc/dokploy/compose/app/data",
		TargetPath: managedVolumeRoot + "svc-1/data",
		Source:     &client.MigrationDBCreds{ContainerName: "dokploy-app-1"},
	}
	_, _, _, err := resolveVolumeMigrateIdentity(map[string]interface{}{
		"sourceContainerName": "unrelated",
	}, creds)
	if err == nil {
		t.Fatal("expected mismatched container to be rejected")
	}
}

func TestResolveVolumeMigrateIdentityRejectsWrongKind(t *testing.T) {
	_, _, _, err := resolveVolumeMigrateIdentity(nil, &client.MigrationCredentials{Kind: "database"})
	if err == nil {
		t.Fatal("expected kind mismatch")
	}
}

func TestAuthorizeMigrateSourceAllowsDokployRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dokploy")
	src := filepath.Join(root, "compose", "app", "data")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got, err := authorizeMigrateSource(src+"/", []string{root}, nil)
	if err != nil {
		t.Fatalf("authorizeMigrateSource: %v", err)
	}
	want := mustEval(t, src)
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
}

func TestAuthorizeMigrateSourceAllowsBindMountAndNestedPath(t *testing.T) {
	mount := filepath.Join(t.TempDir(), "bind-src")
	nested := filepath.Join(mount, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got, err := authorizeMigrateSource(nested, nil, []string{mount})
	if err != nil {
		t.Fatalf("authorizeMigrateSource: %v", err)
	}
	want := mustEval(t, nested)
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
}

func TestAuthorizeMigrateSourceRejectsParentOfBindMount(t *testing.T) {
	base := t.TempDir()
	mount := filepath.Join(base, "app", "data")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, err := authorizeMigrateSource(base, nil, []string{mount})
	if err == nil {
		t.Fatal("expected parent of bind mount to be rejected")
	}
}

func TestAuthorizeMigrateSourceRejectsRootAndSystemPaths(t *testing.T) {
	for _, src := range []string{"/", "/etc", "/etc/passwd", "/var/lib/docker"} {
		t.Run(src, func(t *testing.T) {
			_, err := authorizeMigrateSource(src, defaultVolumeMigrateRoots(), []string{"/"})
			if err == nil {
				t.Fatalf("expected %s to be rejected even if mounted", src)
			}
		})
	}
}

func TestAuthorizeMigrateSourceRejectsNestedSymlinkEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "dokploy")
	mid := filepath.Join(root, "mid")
	if err := os.MkdirAll(mid, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("/etc", filepath.Join(mid, "etc")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := os.Symlink(filepath.Join(mid, "etc"), filepath.Join(root, "escape")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := authorizeMigrateSource(filepath.Join(root, "escape", "passwd"), []string{root}, nil)
	if err == nil {
		t.Fatal("expected nested symlink escape to be rejected")
	}
}

func TestAuthorizeMigrateSourceRejectsBindMountSymlinkEscape(t *testing.T) {
	mount := filepath.Join(t.TempDir(), "mount")
	if err := os.MkdirAll(mount, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(mount, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	_, err := authorizeMigrateSource(filepath.Join(mount, "link"), nil, []string{mount})
	if err == nil {
		t.Fatal("expected bind-mount symlink escape to be rejected")
	}
}

func TestAuthorizeMigrateSourceRejectsSiblingLookalikeRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "dokploy")
	sibling := filepath.Join(base, "dokploy-evil")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, err := authorizeMigrateSource(sibling, []string{root}, nil)
	if err == nil {
		t.Fatal("expected sibling lookalike root to be rejected")
	}
}

func TestAuthorizeMigrateSourceRejectsSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	if err := os.MkdirAll(filepath.Join(dir, "keep"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Unix sockets aren't creatable portably without syscall; skip if we
	// can't make one. Prefer a fifo which is also a rejected special file.
	if err := os.Mkdir(sock, 0o755); err != nil {
		t.Fatalf("mkdir sock placeholder: %v", err)
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if err := mkfifo(sock); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	_, err := authorizeMigrateSource(sock, []string{dir}, nil)
	if err == nil {
		t.Fatal("expected fifo/socket to be rejected")
	}
}

func TestParseDockerBindMountSourcesIgnoresVolumesAndDeniedPaths(t *testing.T) {
	raw := []byte(`[
		{"Type":"bind","Source":"/etc/dokploy/compose/app/data"},
		{"Type":"volume","Source":"/var/lib/docker/volumes/app/_data"},
		{"Type":"bind","Source":"/"},
		{"Type":"bind","Source":"/var/lib/docker/overlay2/xxx"}
	]`)
	got, err := parseDockerBindMountSources(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0] != "/etc/dokploy/compose/app/data" {
		t.Fatalf("got %#v", got)
	}
}

func TestVolumeMigrateRootsIgnoresDeniedConfiguredRoots(t *testing.T) {
	t.Setenv(volumeMigrateRootsEnv, "/:/etc:/etc/dokploy:/var/lib/docker")
	got := volumeMigrateRoots()
	if len(got) != 1 || got[0] != "/etc/dokploy" {
		t.Fatalf("got %#v", got)
	}
}
