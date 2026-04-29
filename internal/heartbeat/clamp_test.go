package heartbeat

import (
	"math"
	"testing"
)

func TestClampPercent(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want float64
	}{
		{"NaN", math.NaN(), 0},
		{"+Inf", math.Inf(1), 0},
		{"-Inf", math.Inf(-1), 0},
		{"negative", -1, 0},
		{"zero", 0, 0},
		{"mid", 50, 50},
		{"hundred", 100, 100},
		{"slightly over", 100.0001, 100},
		{"absurdly over", 1e15, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clampPercent(tt.in)
			if got != tt.want {
				t.Errorf("clampPercent(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
