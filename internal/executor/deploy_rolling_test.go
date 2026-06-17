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
		nil,
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
		"svc-1-blue", "svc-1", "blue", "img", "/env",
		resourceLimits{restartPolicy: "unless-stopped"},
		[]string{"api", "old-name", "BAD ALIAS", ""},
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
		nil,
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
		nil,
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
