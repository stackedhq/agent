package dockerlogs

import (
	"testing"
	"time"
)

func TestShouldShipDropsHistoricalTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	if ShouldShip(time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), now) {
		t.Fatal("July log line must not be shipped in August")
	}
	if ShouldShip(now.Add(-3*time.Minute).Format(time.RFC3339Nano), now) {
		t.Fatal("line older than MaxResumeAge must not be shipped")
	}
}

func TestShouldShipKeepsRecentAndUntimestamped(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	if !ShouldShip(now.Add(-30*time.Second).Format(time.RFC3339Nano), now) {
		t.Fatal("30s-old line should ship")
	}
	if !ShouldShip("", now) {
		t.Fatal("untimestamped line should ship (legacy / malformed)")
	}
	if !ShouldShip("not-a-timestamp", now) {
		t.Fatal("malformed timestamp should ship rather than drop")
	}
}
