package heartbeat

import (
	"strings"
	"testing"
)

// Regression test for the panic that used to bite when Docker emitted
// an empty `Reclaimable` field (older versions / Build Cache rows on
// some platforms). collectDockerDiskUsage must guard the `Fields[0]`
// indexing because `strings.Fields("")` is `[]` and a `[0]` would
// crash the heartbeat goroutine.
func TestReclaimableEmptyDoesNotPanic(t *testing.T) {
	row := dockerSystemDfRow{Type: "Build Cache", Reclaimable: ""}
	var reclaim uint64
	if fields := strings.Fields(row.Reclaimable); len(fields) > 0 {
		reclaim = parseSize(fields[0])
	}
	if reclaim != 0 {
		t.Fatalf("reclaim = %d, want 0", reclaim)
	}
}

func TestReclaimableWithPercent(t *testing.T) {
	row := dockerSystemDfRow{Reclaimable: "512MB (40%)"}
	var reclaim uint64
	if fields := strings.Fields(row.Reclaimable); len(fields) > 0 {
		reclaim = parseSize(fields[0])
	}
	// 512 * 1e6 — parseSize treats MB as decimal (1e6).
	if reclaim < 500_000_000 || reclaim > 520_000_000 {
		t.Fatalf("reclaim = %d, want ~512MB (5.0e8)", reclaim)
	}
}

func TestParseSizeUnits(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"0B", 0},
		{"1024B", 1024},
		// Existing convention in parseSize: "KB"/"KiB" both treat as
		// binary (1024). docker emits decimal MB/GB but binary KB; we
		// match docker's behaviour rather than enforce SI strictness.
		{"1KB", 1024},
		{"1KiB", 1024},
		{"1MB", 1_000_000},
		{"1MiB", 1024 * 1024},
		{"1.5GB", 1_500_000_000},
		{"1GiB", 1024 * 1024 * 1024},
		{"", 0},
		{"garbage", 0},
		{"1ZB", 0}, // unknown unit
	}
	for _, c := range cases {
		got := parseSize(c.in)
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
