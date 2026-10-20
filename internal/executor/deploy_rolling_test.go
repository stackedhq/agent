package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRollingContainerArgsStableAlias(t *testing.T) {
	serviceID := "svc-123"
	args := rollingContainerArgs(
		serviceID+"-blue", serviceID, "blue",
		"registry/app:tag", []string{"--env-file=/opt/stacked/services/svc-123/stacked.env"},
		resourceLimits{restartPolicy: "unless-stopped"},
		nil, "",
	)

	// The slot container is named per-slot but must alias the bare
	// serviceID so sibling containers get a stable internal hostname
	// across blue/green flips.
	if !containsFlag(args, "--network-alias="+serviceID) {
		t.Fatalf("expected stable --network-alias=%s, got: %v", serviceID, args)
	}
	if !containsFlag(args, "--network=stacked") {
		t.Fatalf("expected --network=stacked, got: %v", args)
	}
	if !containsFlag(args, "--name") {
		t.Fatalf("expected --name flag, got: %v", args)
	}

	// Image must be the final argument — everything after it is argv.
	if got := args[len(args)-1]; got != "registry/app:tag" {
		t.Fatalf("image must be last arg, got %q in %v", got, args)
	}
}

func TestRollingContainerArgsFriendlyAliases(t *testing.T) {
	args := rollingContainerArgs(
		"svc-1-blue", "svc-1", "blue", "img", []string{"--env-file=/env"},
		resourceLimits{restartPolicy: "unless-stopped"},
		[]string{"api", "old-name", "BAD ALIAS", ""}, "",
	)
	// Permanent UUID alias plus the two valid friendly aliases.
	for _, want := range []string{
		"--network-alias=svc-1",
		"--network-alias=api",
		"--network-alias=old-name",
	} {
		if !containsFlag(args, want) {
			t.Errorf("expected %s, got: %v", want, args)
		}
	}
	// Invalid labels must be dropped, never spliced in.
	for _, bad := range []string{
		"--network-alias=BAD ALIAS",
		"--network-alias=",
	} {
		if containsFlag(args, bad) {
			t.Errorf("invalid alias must be filtered, found %q in %v", bad, args)
		}
	}
}

func TestRollingContainerArgsAppliesLimits(t *testing.T) {
	args := rollingContainerArgs(
		"svc-1-green", "svc-1", "green", "img", []string{"--env-file=/env"},
		resourceLimits{cpuMillicores: 1500, memoryMB: 512, restartPolicy: "on-failure"},
		nil, "",
	)
	if !containsFlag(args, "--memory=512m") {
		t.Errorf("expected --memory=512m, got: %v", args)
	}
	if !containsFlag(args, "--cpus=1.5") {
		t.Errorf("expected --cpus=1.5, got: %v", args)
	}
	if !containsFlag(args, "--restart=on-failure") {
		t.Errorf("expected --restart=on-failure, got: %v", args)
	}
}

func TestRollingContainerArgsOmitsUnsetLimits(t *testing.T) {
	args := rollingContainerArgs(
		"svc-1-blue", "svc-1", "blue", "img", []string{"--env-file=/env"},
		resourceLimits{restartPolicy: "unless-stopped"},
		nil, "",
	)
	for _, a := range args {
		if strings.HasPrefix(a, "--memory=") || strings.HasPrefix(a, "--cpus=") {
			t.Errorf("unset limits must not emit %q (args: %v)", a, args)
		}
	}
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestNeedsUnslottedReconcile(t *testing.T) {
	cases := []struct {
		name        string
		hadSlot     bool
		blueExists  bool
		greenExists bool
		want        bool
	}{
		{"clean recreate, nothing to do", false, false, false, false},
		{"stale slot state only", true, false, false, true},
		{"orphan blue container only", false, true, false, true},
		{"orphan green container only", false, false, true, true},
		{"slot state plus blue container", true, true, false, true},
		{"both orphan containers", false, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsUnslottedReconcile(c.hadSlot, c.blueExists, c.greenExists); got != c.want {
				t.Fatalf("needsUnslottedReconcile(%v,%v,%v) = %v, want %v",
					c.hadSlot, c.blueExists, c.greenExists, got, c.want)
			}
		})
	}
}

func TestRequiresFastRestartForAnyAttachedStorage(t *testing.T) {
	cases := []struct {
		name       string
		volumes    bool
		fileMounts bool
		want       bool
	}{
		{"no storage", false, false, false},
		{"directory volume", true, false, true},
		{"managed file", false, true, true},
		{"both", true, true, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := requiresFastRestart(test.volumes, test.fileMounts); got != test.want {
				t.Fatalf("requiresFastRestart(%v, %v) = %v, want %v", test.volumes, test.fileMounts, got, test.want)
			}
		})
	}
}

func TestRollingContainerArgsAppliesDockerImageCommand(t *testing.T) {
	args := rollingContainerArgs("svc-blue", "svc", "blue", "image", []string{"--env-file=/env"},
		resourceLimits{restartPolicy: "unless-stopped"}, nil, "node server.js && echo ready")
	want := []string{"image", "sh", "-lc", "node server.js && echo ready"}
	if len(args) < len(want) {
		t.Fatalf("missing command args: %v", args)
	}
	for i, value := range want {
		if args[len(args)-len(want)+i] != value {
			t.Fatalf("command suffix = %v, want %v", args[len(args)-len(want):], want)
		}
	}
}

func TestBlueGreenMemoryNeedMB(t *testing.T) {
	cases := []struct {
		name        string
		live, limit int
		want        int
	}{
		{name: "unmeasurable live usage skips the budget", live: 0, limit: 1024, want: 0},
		{name: "negative live usage skips the budget", live: -1, limit: 512, want: 0},
		{name: "actual RSS plus 64 MB boot buffer", live: 180, limit: 1024, want: 244},
		{name: "never budgets more than the Docker cap", live: 500, limit: 512, want: 512},
		{name: "unlimited services still budget live RSS", live: 180, limit: 0, want: 244},
		{name: "cap equal to live RSS stays at the cap", live: 512, limit: 512, want: 512},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := blueGreenMemoryNeedMB(c.live, c.limit); got != c.want {
				t.Fatalf("blueGreenMemoryNeedMB(%d, %d) = %d, want %d", c.live, c.limit, got, c.want)
			}
		})
	}
}

func TestBlueGreenHeadroomError(t *testing.T) {
	if err := blueGreenHeadroomError(180, 1024, 300); err != nil {
		t.Fatalf("enough free RAM for live RSS must pass: %v", err)
	}
	if err := blueGreenHeadroomError(180, 1024, 244); err != nil {
		t.Fatalf("exactly the needed budget must pass: %v", err)
	}
	err := blueGreenHeadroomError(180, 1024, 100)
	if err == nil {
		t.Fatal("expected failure when free RAM is below live RSS + buffer")
	}
	if !strings.Contains(err.Error(), "live container is using 180 MB") {
		t.Fatalf("error should cite live usage, got %v", err)
	}
	if strings.Contains(err.Error(), "2×") || strings.Contains(err.Error(), "2048") {
		t.Fatalf("error must not treat the cap as reserved, got %v", err)
	}
	if err := blueGreenHeadroomError(180, 1024, 0); err != nil {
		t.Fatalf("unreadable meminfo must fail open: %v", err)
	}
	if err := blueGreenHeadroomError(0, 1024, 50); err != nil {
		t.Fatalf("unmeasurable live RSS must fail open even on a small box: %v", err)
	}
	// The old 2×-limit check would have failed this: 1 GB cap, 180 MB
	// live, 400 MB free. Caps are not reservations.
	if err := blueGreenHeadroomError(180, 1024, 400); err != nil {
		t.Fatalf("400 MB free for a 180 MB live container must pass: %v", err)
	}
}

// A blue/green deploy after a recreate deploy must rewrite the compose
// file's `environment:` map (and settings), or a Restart that falls back
// to `compose up -d` starts the service with stale env.
func TestRefreshBlueGreenComposeUpdatesEnvironment(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "docker-compose.yml")
	oldEnv := map[string]string{"API_KEY": "old", "GONE": "x", "HOST": "0.0.0.0"}
	old := generateCompose(goldenServiceID, "img:1", nil, resourceLimits{restartPolicy: "unless-stopped"}, nil, "", oldEnv)
	if err := writeFile(composePath, old); err != nil {
		t.Fatal(err)
	}

	newEnv := map[string]string{"API_KEY": "new", "HOST": "0.0.0.0", "PEM": "a\nb"}
	payload := map[string]interface{}{"memoryLimitMb": float64(256), "restartPolicy": "always"}
	if err := refreshBlueGreenCompose(dir, goldenServiceID, "img:2", payload, []string{"api"}, newEnv); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	want := generateCompose(goldenServiceID, "img:2", nil, resourceLimitsFromPayload(payload), []string{"api"}, "", newEnv)
	if string(got) != want {
		t.Fatalf("compose not regenerated:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "GONE") || strings.Contains(string(got), `"old"`) {
		t.Fatalf("stale env left in compose:\n%s", got)
	}
	info, err := os.Stat(composePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("compose mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files after atomic write: %v", entries)
	}
}

// The legacy `.env` is kept in sync while an old template references it,
// and removed once the compose file has been regenerated.
func TestRefreshBlueGreenComposeReplacesLegacyTemplate(t *testing.T) {
	dir := t.TempDir()
	legacy, err := os.ReadFile(filepath.Join("testdata", "compose_legacy", "service-min.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, "docker-compose.yml"), string(legacy)); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, ".env"), "API_KEY=old\n"); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"API_KEY": "new", "HOST": "0.0.0.0"}
	if err := syncLegacyEnvFile(dir, env); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".env")); !strings.Contains(string(b), "API_KEY=new") {
		t.Fatalf("legacy .env not synced: %q", b)
	}
	if err := refreshBlueGreenCompose(dir, goldenServiceID, "img:2", nil, nil, env); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if composeReferencesLegacyEnv(string(got)) || !strings.Contains(string(got), `API_KEY: "new"`) {
		t.Fatalf("compose not regenerated:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatalf("legacy .env not removed: %v", err)
	}
}

// A service that only ever deployed blue/green has no compose file; one
// isn't invented (Restart keeps reporting "redeploy required").
func TestRefreshBlueGreenComposeSkipsMissingFile(t *testing.T) {
	dir := t.TempDir()
	if err := refreshBlueGreenCompose(dir, goldenServiceID, "img:2", nil, nil, map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); !os.IsNotExist(err) {
		t.Fatalf("compose file created: %v", err)
	}
}
