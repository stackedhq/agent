package executor

import (
	"strings"
	"testing"
)

func TestRollingContainerArgsStableAlias(t *testing.T) {
	serviceID := "svc-123"
	args := rollingContainerArgs(
		serviceID+"-blue", serviceID, "blue",
		"registry/app:tag", "/opt/stacked/services/svc-123/.env",
		resourceLimits{restartPolicy: "unless-stopped"},
		isolationFromPayload(nil), networkPlanFromPayload(serviceID, map[string]interface{}{"networkIsolation": true}, nil), "",
	)

	// The slot container is named per-slot but must alias the bare
	// serviceID so sibling containers get a stable internal hostname
	// across blue/green flips.
	if !containsFlag(args, "--network-alias="+serviceID) {
		t.Fatalf("expected stable --network-alias=%s, got: %v", serviceID, args)
	}
	if !containsFlag(args, "--network="+serviceNetworkName(serviceID)) {
		t.Fatalf("expected isolated --network, got: %v", args)
	}
	if !containsFlag(args, "--security-opt=no-new-privileges:true") || !containsFlag(args, "--cap-drop=ALL") {
		t.Fatalf("expected default isolation flags, got: %v", args)
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
		"svc-1-blue", "svc-1", "blue", "img", "/env",
		resourceLimits{restartPolicy: "unless-stopped"},
		isolationFromPayload(nil), networkPlanFromPayload("svc-1", map[string]interface{}{"networkIsolation": true}, []string{"api", "old-name", "BAD ALIAS", ""}), "",
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
		"svc-1-green", "svc-1", "green", "img", "/env",
		resourceLimits{cpuMillicores: 1500, memoryMB: 512, restartPolicy: "on-failure"},
		isolationFromPayload(nil), networkPlanFromPayload("svc-1", map[string]interface{}{"networkIsolation": true}, nil), "",
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
		"svc-1-blue", "svc-1", "blue", "img", "/env",
		resourceLimits{restartPolicy: "unless-stopped"},
		isolationFromPayload(nil), networkPlanFromPayload("svc-1", nil, nil), "",
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
	args := rollingContainerArgs("svc-blue", "svc", "blue", "image", "/env",
		resourceLimits{restartPolicy: "unless-stopped"}, isolationFromPayload(nil), networkPlanFromPayload("svc", nil, nil), "node server.js && echo ready")
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
