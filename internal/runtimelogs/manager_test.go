package runtimelogs

import "testing"

func TestIsUUID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Valid 8-4-4-4-12 hex forms, mixed case.
		{"ebe83b46-8e71-4bec-b21e-8ec9812c8af6", true},
		{"EBE83B46-8E71-4BEC-B21E-8EC9812C8AF6", true},
		{"00000000-0000-0000-0000-000000000000", true},

		// The exact strings that triggered the production 500s.
		{"proxy", false},
		{"watchlist-dumb-szixkg", false},

		// Other shapes we must reject.
		{"", false},
		{"not-a-uuid", false},
		// Right length, wrong dash placement.
		{"ebe83b468-e71-4bec-b21e-8ec9812c8af6", false},
		// Right shape, non-hex digit.
		{"gbe83b46-8e71-4bec-b21e-8ec9812c8af6", false},
		// Trailing junk.
		{"ebe83b46-8e71-4bec-b21e-8ec9812c8af6x", false},
	}
	for _, c := range cases {
		if got := isUUID(c.in); got != c.want {
			t.Errorf("isUUID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
