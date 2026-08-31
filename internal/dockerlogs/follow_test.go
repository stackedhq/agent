package dockerlogs

import (
	"slices"
	"testing"
	"time"
)

func TestFollowArgsNeverReplaysHistory(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	container := "abc123def456"

	args := FollowArgs(container, "", now)

	if !slices.Contains(args, "-f") {
		t.Fatalf("missing -f: %v", args)
	}
	if !slices.Contains(args, "--timestamps") {
		t.Fatalf("missing --timestamps: %v", args)
	}
	if !containsPair(args, "--tail", "0") {
		t.Fatalf("expected --tail 0, got %v", args)
	}
	if !containsPair(args, "--since", "2m") {
		t.Fatalf("expected --since 2m on empty cursor, got %v", args)
	}
	if args[len(args)-1] != container {
		t.Fatalf("container id should be last, got %v", args)
	}
}

func TestFollowArgsIgnoresAncientCursor(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	// Production failure: a July cursor left on disk, so `--since` dumped
	// months of json-file history into POST /api/agent/logs.
	ancient := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)

	args := FollowArgs("ctr", ancient, now)

	if !containsPair(args, "--since", "2m") {
		t.Fatalf("ancient cursor must be clamped to 2m, got %v", args)
	}
	if slices.Contains(args, ancient) {
		t.Fatalf("ancient cursor leaked into args: %v", args)
	}
}

func TestFollowArgsHonoursRecentCursor(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-30 * time.Second).Format(time.RFC3339Nano)

	args := FollowArgs("ctr", recent, now)

	if !containsPair(args, "--tail", "0") {
		t.Fatalf("--tail 0 is required even with a recent cursor, got %v", args)
	}
	if !containsPair(args, "--since", recent) {
		t.Fatalf("recent cursor should be used as --since, got %v", args)
	}
}

func TestFollowArgsRejectsFutureCursor(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	future := now.Add(5 * time.Minute).Format(time.RFC3339Nano)

	args := FollowArgs("ctr", future, now)

	if !containsPair(args, "--since", "2m") {
		t.Fatalf("future cursor must be ignored, got %v", args)
	}
}

func TestFollowArgsRejectsMalformedCursor(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	args := FollowArgs("ctr", "not-a-timestamp", now)
	if !containsPair(args, "--since", "2m") {
		t.Fatalf("malformed cursor must be ignored, got %v", args)
	}
}

func containsPair(args []string, key, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
