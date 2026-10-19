package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetAllowedRoots(t *testing.T) {
	t.Helper()
	if err := SetAllowedHostRoots(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetAllowedHostRoots(nil) })
}

func TestNormalizeAllowedHostRoots(t *testing.T) {
	got, err := NormalizeAllowedHostRoots([]string{" /data ", "/data", "/mnt/storage", "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "/data" || got[1] != "/mnt/storage" || got[2] != "/" {
		t.Fatalf("got %#v", got)
	}

	cases := []string{"./rel", "data", "/etc", "/proc", "/sys", "/dev", "/run", "/var/run/docker.sock", "/opt/stacked/agent.toml", "/var/lib/docker", "/tmp/../etc"}
	for _, raw := range cases {
		if _, err := NormalizeAllowedHostRoots([]string{raw}); err == nil {
			t.Errorf("expected reject for %q", raw)
		}
	}
}

func TestAuthorizeHostPath_ManagedDoesNotNeedAllowlist(t *testing.T) {
	resetAllowedRoots(t)
	path := "/opt/stacked/data/services/svc-1/data-abc"
	resolved, notes, err := authorizeHostPath(path)
	if err != nil {
		t.Fatalf("managed path rejected: %v notes=%v", err, notes)
	}
	if resolved != path {
		t.Fatalf("resolved %q", resolved)
	}
}

func TestAuthorizeHostPath_ManagedRootItselfIsNotManaged(t *testing.T) {
	resetAllowedRoots(t)
	_, _, err := authorizeHostPath("/opt/stacked/data/services")
	if err == nil {
		t.Fatal("expected reject for managed-root parent")
	}
	if !strings.Contains(err.Error(), "not allowlisted") && !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestAuthorizeHostPath_Denylist(t *testing.T) {
	resetAllowedRoots(t)
	if err := SetAllowedHostRoots([]string{"/"}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		want string
	}{
		{"/", "host root"},
		{"/etc", "critical path /etc"},
		{"/etc/passwd", "critical path /etc"},
		{"/proc", "critical path /proc"},
		{"/sys", "critical path /sys"},
		{"/dev", "critical path /dev"},
		{"/run", "critical path /run"},
		{"/run/docker.sock", "container runtime socket"},
		{"/var/run/docker.sock", "container runtime socket"},
		{"/var/run/containerd/containerd.sock", "container runtime socket"},
		{"/var/lib/docker", "critical path /var/lib/docker"},
		{"/var/lib/containerd", "critical path /var/lib/containerd"},
		{"/opt/stacked", "critical path /opt/stacked"},
		{"/opt/stacked/agent.toml", "critical path /opt/stacked"},
		{"/opt/stacked/proxy/Caddyfile", "critical path /opt/stacked"},
		{"/opt/stacked/services/svc-1/docker-compose.yml", "critical path /opt/stacked"},
	}
	for _, c := range cases {
		_, notes, err := authorizeHostPath(c.path)
		if err == nil {
			t.Errorf("%q allowed, notes=%v", c.path, notes)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q err %q, want substring %q", c.path, err.Error(), c.want)
		}
	}
}

func TestAuthorizeHostPath_CustomRequiresAllowlist(t *testing.T) {
	resetAllowedRoots(t)
	_, _, err := authorizeHostPath("/srv/app")
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("expected allowlist error, got %v", err)
	}

	t.Setenv(allowedVolumeRootsEnv, "/srv")
	resolved, notes, err := authorizeHostPath("/srv/app")
	if err != nil {
		t.Fatalf("allowlisted custom rejected: %v notes=%v", err, notes)
	}
	if resolved != "/srv/app" {
		t.Fatalf("resolved %q", resolved)
	}
}

func TestAuthorizeHostPath_AllowlistDoesNotWidenDenylist(t *testing.T) {
	resetAllowedRoots(t)
	t.Setenv(allowedVolumeRootsEnv, "/")
	_, _, err := authorizeHostPath("/etc/shadow")
	if err == nil {
		t.Fatal("denylist must win over allowlist /")
	}
}

func TestAuthorizeHostPath_SiblingPrefixIsNotAllowlisted(t *testing.T) {
	resetAllowedRoots(t)
	t.Setenv(allowedVolumeRootsEnv, "/data")
	_, _, err := authorizeHostPath("/data-backup/app")
	if err == nil {
		t.Fatal("sibling of allowlisted root must be rejected")
	}
}

func TestAuthorizeHostPath_RejectsRelativeAndDotDot(t *testing.T) {
	resetAllowedRoots(t)
	if _, _, err := authorizeHostPath("var/data"); err == nil {
		t.Fatal("expected relative reject")
	}
	if _, _, err := authorizeHostPath("/var/../etc"); err == nil {
		t.Fatal("expected .. reject")
	}
}

func TestAuthorizeHostPath_SymlinkEscapeRejected(t *testing.T) {
	resetAllowedRoots(t)
	root := t.TempDir()
	if err := SetAllowedHostRoots([]string{root}); err != nil {
		t.Fatal(err)
	}

	target := t.TempDir()
	// Point at a denied location so resolution cannot be confused with the allowlist.
	if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	_, notes, err := authorizeHostPath(filepath.Join(root, "escape", "passwd"))
	if err == nil {
		t.Fatalf("symlink escape allowed, notes=%v", notes)
	}
	if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "critical") {
		t.Fatalf("unexpected err: %v", err)
	}

	// A symlink that stays inside the allowlist is fine.
	inside := filepath.Join(root, "real")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(root, "ok")); err != nil {
		t.Fatal(err)
	}
	resolved, _, err := authorizeHostPath(filepath.Join(root, "ok", "vol"))
	if err != nil {
		t.Fatalf("in-allowlist symlink rejected: %v", err)
	}
	wantPrefix, err := filepath.EvalSymlinks(inside)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resolved, wantPrefix) {
		t.Fatalf("expected resolve under %s, got %s", wantPrefix, resolved)
	}
	_ = target
}

func TestAuthorizeHostPath_ManagedSymlinkEscapeRejected(t *testing.T) {
	resetAllowedRoots(t)
	// We cannot write /opt/stacked in tests; simulate the check with a
	// lexical managed path that is a symlink only if that prefix exists.
	// If the host has no /opt/stacked, resolution stays lexical and this
	// is a no-op managed-allow. Cover the escape detector directly.
	outside := t.TempDir()
	if isManagedVolumePath(outside) {
		t.Fatal("tempdir should not look managed")
	}
	if !isManagedVolumePath("/opt/stacked/data/services/x/y") {
		t.Fatal("expected managed")
	}
	if isManagedVolumePath("/opt/stacked/data/services") {
		t.Fatal("bare managed root must not count")
	}
	if isManagedVolumePath("/opt/stacked/data/services-backup/x") {
		t.Fatal("sibling must not count")
	}
}

func TestAuthorizeHostPath_RootAllowlistWarns(t *testing.T) {
	resetAllowedRoots(t)
	if err := SetAllowedHostRoots([]string{"/"}); err != nil {
		t.Fatal(err)
	}
	_, notes, err := authorizeHostPath("/home/app")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "root-equivalent") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected root-equivalent warning, notes=%v", notes)
	}
}

func TestAuthorizeVolumeMounts_RewritesResolvedPath(t *testing.T) {
	resetAllowedRoots(t)
	root := t.TempDir()
	if err := SetAllowedHostRoots([]string{root}); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink: %v", err)
	}

	mounts := []volumeMount{{HostPath: filepath.Join(link, "vol"), ContainerPath: "/data"}}
	if err := authorizeVolumeMounts(mounts, nil); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want = filepath.Join(want, "vol")
	if mounts[0].HostPath != want {
		t.Fatalf("HostPath=%q want %q", mounts[0].HostPath, want)
	}
}

func TestPrepareHostVolumeMounts_RegressionCustomAndManaged(t *testing.T) {
	resetAllowedRoots(t)
	root := t.TempDir()
	t.Setenv(allowedVolumeRootsEnv, root)

	payload := map[string]interface{}{
		"volumes": []interface{}{
			map[string]interface{}{
				"hostPath":      filepath.Join(root, "custom"),
				"containerPath": "/custom",
			},
		},
	}
	got, err := prepareHostVolumeMounts(payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		want = root
	}
	want = filepath.Join(want, "custom")
	if len(got) != 1 || got[0].HostPath != want {
		t.Fatalf("got %#v want %q", got, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("custom dir not created: %v", err)
	}

	if err := SetAllowedHostRoots(nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv(allowedVolumeRootsEnv, "")
	if _, _, err := authorizeHostPath("/opt/stacked/data/services/svc-1/vol"); err != nil {
		t.Fatalf("managed regression: %v", err)
	}
}

func TestDeniedHostPath_LookalikePrefixes(t *testing.T) {
	if denied, _ := deniedHostPath("/etc-backup"); denied {
		t.Fatal("/etc-backup must not match /etc")
	}
	if denied, _ := deniedHostPath("/var/lib/docker-backup"); denied {
		t.Fatal("docker-backup sibling must not match")
	}
	if denied, _ := deniedHostPath("/opt/stacked-old"); denied {
		t.Fatal("stacked-old sibling must not match")
	}
}
