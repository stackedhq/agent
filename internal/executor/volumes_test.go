package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVolumes_EmptyOrMissing(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"nil payload field", map[string]interface{}{}},
		{"explicit nil", map[string]interface{}{"volumes": nil}},
		{"empty slice", map[string]interface{}{"volumes": []interface{}{}}},
		{"wrong type (string)", map[string]interface{}{"volumes": "nope"}},
		{"wrong type (map)", map[string]interface{}{"volumes": map[string]interface{}{"a": 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseVolumes(c.payload)
			if len(got) != 0 {
				t.Fatalf("expected empty mounts, got %d", len(got))
			}
		})
	}
}

func TestParseVolumes_HappyPath(t *testing.T) {
	payload := map[string]interface{}{
		"volumes": []interface{}{
			map[string]interface{}{
				"hostPath":      "/data/b",
				"containerPath": "/b",
				"readOnly":      true,
			},
			map[string]interface{}{
				"hostPath":      "/data/a",
				"containerPath": "/a",
			},
		},
	}
	got := parseVolumes(payload)
	if len(got) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(got))
	}
	// Sorted by container path: /a before /b.
	if got[0].ContainerPath != "/a" || got[1].ContainerPath != "/b" {
		t.Fatalf("mounts not sorted by container path: %+v", got)
	}
	if got[0].ReadOnly || !got[1].ReadOnly {
		t.Fatalf("readOnly not preserved: %+v", got)
	}
}

func TestParseVolumes_SkipsMalformedEntries(t *testing.T) {
	payload := map[string]interface{}{
		"volumes": []interface{}{
			map[string]interface{}{
				"hostPath":      "/ok",
				"containerPath": "/ok",
			},
			"not an object",
			map[string]interface{}{
				"hostPath": "/missing-container",
			},
			map[string]interface{}{
				"containerPath": "/missing-host",
			},
			map[string]interface{}{
				"hostPath":      "",
				"containerPath": "/empty-host",
			},
		},
	}
	got := parseVolumes(payload)
	if len(got) != 1 {
		t.Fatalf("expected 1 valid mount, got %d: %+v", len(got), got)
	}
	if got[0].HostPath != "/ok" || got[0].ContainerPath != "/ok" {
		t.Fatalf("wrong surviving mount: %+v", got[0])
	}
}

func TestRenderComposeVolumes_Empty(t *testing.T) {
	if out := renderComposeVolumes(nil); out != "" {
		t.Fatalf("expected empty string for nil, got %q", out)
	}
	if out := renderComposeVolumes([]volumeMount{}); out != "" {
		t.Fatalf("expected empty string for empty slice, got %q", out)
	}
}

func TestRenderComposeVolumes_RW(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/host/a", ContainerPath: "/c/a"},
	})
	want := "    volumes:\n      - /host/a:/c/a\n"
	if out != want {
		t.Fatalf("mismatch:\ngot:  %q\nwant: %q", out, want)
	}
}

func TestRenderComposeVolumes_RO(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/host/a", ContainerPath: "/c/a", ReadOnly: true},
	})
	if !strings.Contains(out, ":/c/a:ro\n") {
		t.Fatalf("expected :ro suffix in output, got %q", out)
	}
}

func TestRenderComposeVolumes_Multiple(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/h1", ContainerPath: "/c1"},
		{HostPath: "/h2", ContainerPath: "/c2", ReadOnly: true},
	})
	want := "    volumes:\n      - /h1:/c1\n      - /h2:/c2:ro\n"
	if out != want {
		t.Fatalf("mismatch:\ngot:  %q\nwant: %q", out, want)
	}
}

func TestGenerateCompose_NoVolumes_OmitsBlock(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", nil, resourceLimits{restartPolicy: "unless-stopped"})
	if strings.Contains(out, "volumes:") {
		t.Fatalf("expected no volumes: block when mounts is nil, got:\n%s", out)
	}
	// Sanity-check the structural bits we rely on.
	if !strings.Contains(out, "container_name: svc-1") {
		t.Fatalf("missing container_name in compose:\n%s", out)
	}
	if !strings.Contains(out, "image: img:latest") {
		t.Fatalf("missing image line in compose:\n%s", out)
	}
}

func TestGenerateCompose_WithVolumes_IncludesBlock(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", []volumeMount{
		{HostPath: "/host", ContainerPath: "/container"},
	}, resourceLimits{restartPolicy: "unless-stopped"})
	if !strings.Contains(out, "    volumes:\n      - /host:/container\n") {
		t.Fatalf("expected volumes block in compose, got:\n%s", out)
	}
}

func TestIsManagedHostPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/opt/stacked/data/services/svc-1/data-abc123", true},
		{"/opt/stacked/data/services/svc-1", true},
		// Exact root without trailing path: anchored on trailing slash,
		// so the bare root (which we never materialize as a volume) is
		// classified as not-managed. Harmless either way — we never
		// produce that path.
		{"/opt/stacked/data/services", false},
		// Look-alike sibling dirs must not match.
		{"/opt/stacked/data/services-backup/svc-1", false},
		{"/opt/stacked/data/other/svc-1", false},
		{"/srv/myapp/data", false},
		{"/data", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isManagedHostPath(c.path); got != c.want {
			t.Errorf("isManagedHostPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// withFakeManagedRoot reroutes the managed-root prefix at the path
// level by creating a tempdir that *looks like* a managed path. The
// const itself isn't swappable (intentional — it's a security boundary,
// not a tunable), so tests construct paths that satisfy the prefix.
func withFakeManagedRoot(t *testing.T) string {
	t.Helper()
	// Build a path under the real managedVolumeRoot prefix inside a
	// tempdir we control. We can't actually create /opt/stacked/... in
	// tests, so we mirror the prefix structure relative to t.TempDir()
	// and override isManagedHostPath via the test — except we can't
	// override consts. Instead, exercise healManagedVolumePerms
	// directly with an arbitrary root; the prefix check lives one level
	// up in ensureVolumeHostDirs and is covered by
	// TestIsManagedHostPath above.
	return t.TempDir()
}

func TestHealManagedVolumePerms_FreshDir_ChmodsLeafAndWritesSentinel(t *testing.T) {
	root := withFakeManagedRoot(t)

	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("heal failed: %v", err)
	}

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o777 {
		t.Errorf("leaf perm = %o, want 0o777", perm)
	}

	if _, err := os.Stat(filepath.Join(root, permsHealSentinel)); err != nil {
		t.Errorf("sentinel not written: %v", err)
	}
}

func TestHealManagedVolumePerms_ExistingContents_GetRelaxed(t *testing.T) {
	root := withFakeManagedRoot(t)

	// Simulate the broken state: a previous deploy left files owned by
	// the agent user with restrictive perms that a non-root container
	// can't open.
	nested := filepath.Join(root, "sub")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	dbFile := filepath.Join(root, "coworker.db")
	if err := os.WriteFile(dbFile, []byte("sqlite"), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}
	nestedFile := filepath.Join(nested, "wal")
	if err := os.WriteFile(nestedFile, []byte("wal"), 0o600); err != nil {
		t.Fatalf("write wal: %v", err)
	}

	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("heal failed: %v", err)
	}

	assertPerm := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != want {
			t.Errorf("%s perm = %o, want %o", path, perm, want)
		}
	}
	assertPerm(root, 0o777)
	assertPerm(nested, 0o777)
	assertPerm(dbFile, 0o666)
	assertPerm(nestedFile, 0o666)
}

func TestHealManagedVolumePerms_Idempotent_SentinelShortCircuits(t *testing.T) {
	root := withFakeManagedRoot(t)
	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("first heal: %v", err)
	}

	// After heal, drop a file with restrictive perms. A re-run should
	// NOT touch it — sentinel exists, recursive walk is skipped.
	late := filepath.Join(root, "late.db")
	if err := os.WriteFile(late, []byte("x"), 0o600); err != nil {
		t.Fatalf("write late: %v", err)
	}

	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("second heal: %v", err)
	}

	info, err := os.Stat(late)
	if err != nil {
		t.Fatalf("stat late: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("late perm = %o, want 0o600 (sentinel should have short-circuited the walk)", perm)
	}
}

func TestHealManagedVolumePerms_SkipsSymlinks(t *testing.T) {
	root := withFakeManagedRoot(t)

	// Target lives OUTSIDE the managed root — if we followed the
	// symlink and chmoded it, that would be the security bug we're
	// guarding against.
	outside := filepath.Join(t.TempDir(), "sensitive")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported on this fs: %v", err)
	}

	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("heal failed: %v", err)
	}

	info, err := os.Stat(outside)
	if err != nil {
		t.Fatalf("stat outside: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("symlink target perm = %o, want 0o600 (must not follow symlinks)", perm)
	}
}

func TestHealManagedVolumePerms_KillSwitch_ChmodsLeafOnly(t *testing.T) {
	t.Setenv(permsHealDisableEnv, "1")
	root := withFakeManagedRoot(t)

	nested := filepath.Join(root, "sub")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	restricted := filepath.Join(nested, "data")
	if err := os.WriteFile(restricted, []byte("x"), 0o600); err != nil {
		t.Fatalf("write restricted: %v", err)
	}

	if err := healManagedVolumePerms(root); err != nil {
		t.Fatalf("heal failed: %v", err)
	}

	// Leaf still chmoded (so newly-created managed volumes work even
	// with the kill-switch on).
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o777 {
		t.Errorf("leaf perm = %o, want 0o777 even with kill-switch", perm)
	}
	// Nested contents untouched.
	nestedInfo, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("stat nested: %v", err)
	}
	if perm := nestedInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("nested dir perm = %o, want 0o700 (kill-switch should skip recursive walk)", perm)
	}
	restrictedInfo, err := os.Stat(restricted)
	if err != nil {
		t.Fatalf("stat restricted: %v", err)
	}
	if perm := restrictedInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("restricted file perm = %o, want 0o600 (kill-switch should skip recursive walk)", perm)
	}
	// Sentinel must NOT be written when kill-switch is on, otherwise
	// turning the switch back off later wouldn't re-trigger the heal.
	if _, err := os.Stat(filepath.Join(root, permsHealSentinel)); !os.IsNotExist(err) {
		t.Errorf("sentinel should not exist when kill-switch is on, stat err = %v", err)
	}
}

func TestEnsureVolumeHostDirs_CustomPath_NotChmoded(t *testing.T) {
	// Custom (non-managed) paths must not have their perms touched —
	// that's user filesystem.
	customRoot := t.TempDir()
	customPath := filepath.Join(customRoot, "my-app-data")

	err := ensureVolumeHostDirs([]volumeMount{
		{HostPath: customPath, ContainerPath: "/data"},
	})
	if err != nil {
		t.Fatalf("ensure failed: %v", err)
	}

	info, err := os.Stat(customPath)
	if err != nil {
		t.Fatalf("stat custom path: %v", err)
	}
	// MkdirAll respects umask, so we don't assert an exact mode — only
	// that we didn't go to 0o777, and no sentinel was written.
	if perm := info.Mode().Perm(); perm == 0o777 {
		t.Errorf("custom path perm = 0o777, expected umask-default (we must not chmod custom paths)")
	}
	if _, err := os.Stat(filepath.Join(customPath, permsHealSentinel)); !os.IsNotExist(err) {
		t.Errorf("sentinel must not be written to custom paths, stat err = %v", err)
	}
}
