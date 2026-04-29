package heartbeat

import "math"

// clampPercent guarantees a percentage value lies in [0, 100]. Non-finite
// inputs (NaN, ±Inf) and negatives collapse to 0; values above 100 collapse
// to 100.
//
// This is a defence-in-depth measure: every percent-returning function in
// this package should already produce a sane value, but a single arithmetic
// bug (e.g. unsigned underflow on a kernel quirk) used to produce values
// like 7.85e13 which overflowed the server's numeric(5,2) columns and 500'd
// every heartbeat. Clamping at the boundary makes that class of bug
// impossible to reach the wire.
func clampPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
