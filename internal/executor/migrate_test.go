package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/logs"
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
	args := strings.Join(volumeMigrateDockerArgs("stk-migrate-op1", "/etc/dokploy", "applications/a", "/opt/stacked/data/services/s/x", "vol"), " ")
	for _, want := range []string{
		"run --rm --name stk-migrate-op1 ",
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

func TestVolumeMigrateContainerName(t *testing.T) {
	if got := volumeMigrateContainerName("5f0c7a52-1b2c-4d3e-8f90-0123456789ab"); got != "stk-migrate-5f0c7a52-1b2c-4d3e-8f90-0123456789ab" {
		t.Fatalf("op id name = %q", got)
	}
	a, b := volumeMigrateContainerName("../evil"), volumeMigrateContainerName("")
	for _, n := range []string{a, b} {
		if !strings.HasPrefix(n, "stk-migrate-") || !volumeMigrateNameRe.MatchString(strings.TrimPrefix(n, "stk-migrate-")) {
			t.Fatalf("fallback name %q", n)
		}
	}
	if a == b {
		t.Fatalf("fallback names not unique: %q", a)
	}
}

// fakeDocker puts a `docker` stub first on PATH. It logs every call to
// <state>/calls; `run` marks a daemon-side container as present and then
// blocks like an attached `docker run`; the container only goes away via
// `kill` (asynchronously, like `--rm`, unless killRemoves is false) or
// `rm -f`. `container inspect` reports it until then.
func fakeDocker(t *testing.T, killRemoves bool) string {
	t.Helper()
	state := t.TempDir()
	bin := t.TempDir()
	removes := "1"
	if !killRemoves {
		removes = "0"
	}
	script := `#!/bin/sh
s="$FAKE_DOCKER_STATE"
echo "$*" >> "$s/calls"
case "$1" in
run)
  touch "$s/container"
  echo started
  exec sleep 60
  ;;
kill)
  if [ "$FAKE_DOCKER_KILL_REMOVES" = 1 ]; then
    ( sleep 0.3; rm -f "$s/container" ) >/dev/null 2>&1 &
  fi
  exit 0
  ;;
rm)
  rm -f "$s/container"
  exit 0
  ;;
container)
  if [ -f "$s/container" ]; then echo deadbeef; exit 0; fi
  echo "Error response from daemon: No such container: $5" >&2
  exit 1
  ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_STATE", state)
	t.Setenv("FAKE_DOCKER_KILL_REMOVES", removes)
	return state
}

// expireOpOnceContainerRuns installs an op context that is cancelled (the
// op deadline expiring) as soon as the fake container exists, so the
// deadline always hits a running copy regardless of machine speed.
func expireOpOnceContainerRuns(t *testing.T, state string) (restore func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan struct{})
	go func() {
		defer cancel()
		for {
			if _, err := os.Stat(filepath.Join(state, "container")); err == nil {
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	restoreCtx := setOpContext(ctx)
	return func() {
		close(stop)
		cancel()
		restoreCtx()
	}
}

func fakeDockerCalls(t *testing.T, state string) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(state, "calls"))
	return string(b)
}

// On op deadline the copy container is `docker kill`ed by name and
// VolumeMigrate's copy step only returns once it has been removed.
func TestVolumeMigrateCopyDeadlineKillsAndWaitsForRemoval(t *testing.T) {
	state := fakeDocker(t, true)
	name := volumeMigrateContainerName("op-1")
	args := volumeMigrateDockerArgs(name, "/etc/dokploy", "a", "/opt/stacked/data/services/s", "vol")
	restore := expireOpOnceContainerRuns(t, state)
	defer restore()

	start := time.Now()
	err := runVolumeMigrateCopy(logs.NewStreamer(nil, "op"), name, args)
	if err == nil || !strings.Contains(err.Error(), "operation deadline reached") || !strings.Contains(err.Error(), name+" was stopped") {
		t.Fatalf("expected deadline error naming the stopped container, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("copy outlived the deadline: %s", elapsed)
	}
	if _, err := os.Stat(filepath.Join(state, "container")); !os.IsNotExist(err) {
		t.Fatalf("returned while the copy container still existed")
	}
	calls := fakeDockerCalls(t, state)
	for _, want := range []string{"run --rm --name " + name + " ", "\nkill " + name + "\n", "container inspect --format {{.Id}} " + name} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing docker call %q in:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "\nrm ") {
		t.Fatalf("container was removed by --rm; rm -f should not run:\n%s", calls)
	}
}

// If `--rm` doesn't remove the killed container in time, it is
// force-removed before returning.
func TestVolumeMigrateCopyForceRemovesLingeringContainer(t *testing.T) {
	state := fakeDocker(t, false)
	prevWait, prevPoll := jobRemoveWait, jobRemovePoll
	jobRemoveWait, jobRemovePoll = 500*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { jobRemoveWait, jobRemovePoll = prevWait, prevPoll })

	name := volumeMigrateContainerName("op-2")
	args := volumeMigrateDockerArgs(name, "/etc/dokploy", "a", "/opt/stacked/data/services/s", "vol")
	restore := expireOpOnceContainerRuns(t, state)
	defer restore()

	err := runVolumeMigrateCopy(logs.NewStreamer(nil, "op"), name, args)
	if err == nil || !strings.Contains(err.Error(), "was stopped") {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "container")); !os.IsNotExist(err) {
		t.Fatalf("lingering copy container not removed")
	}
	if calls := fakeDockerCalls(t, state); !strings.Contains(calls, "\nrm -f "+name+"\n") {
		t.Fatalf("expected docker rm -f %s in:\n%s", name, calls)
	}
}

// A copy that finishes before the deadline doesn't trigger kill/cleanup.
func TestVolumeMigrateCopySuccessNoCleanup(t *testing.T) {
	state := t.TempDir()
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"$*\" >> \"$FAKE_DOCKER_STATE/calls\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_STATE", state)
	name := volumeMigrateContainerName("op-3")
	if err := runVolumeMigrateCopy(logs.NewStreamer(nil, "op"), name, volumeMigrateDockerArgs(name, "/etc/dokploy", "a", "/opt/stacked/data/services/s", "vol")); err != nil {
		t.Fatal(err)
	}
	if calls := fakeDockerCalls(t, state); !strings.HasPrefix(calls, "run --rm --name "+name) || strings.Contains(calls, "\nkill ") || strings.Contains(calls, "\nrm ") || strings.Contains(calls, "\ncontainer ") {
		t.Fatalf("unexpected docker calls:\n%s", calls)
	}
}
