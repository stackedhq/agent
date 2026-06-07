package executor

import "testing"

// TestValidExtensionName locks down the regex against the names we
// expect the server's catalog to send (mirrors
// `src/lib/postgres-extensions.ts` in stackedhq/stacked) plus a handful
// of obviously-malicious payloads. If the catalog grows to include
// names this rejects, this test will catch the mismatch before it ships.
func TestValidExtensionName(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		// Catalog v1 — every entry must pass.
		{"pg_stat_statements", true},
		{"pgcrypto", true},
		{"uuid-ossp", true},
		{"vector", true},
		{"pg_trgm", true},
		{"postgis", true},
		{"pg_cron", true},
		{"pgaudit", true},
		{"pg_partman", true},
		{"pg_repack", true},
		{"hypopg", true},
		{"btree_gin", true},
		{"btree_gist", true},
		{"hstore", true},
		{"citext", true},
		{"ltree", true},
		{"intarray", true},
		{"unaccent", true},
		{"tablefunc", true},

		// Rejections — defense in depth against a tampered payload.
		{"", false},                    // empty
		{"PgVector", false},            // uppercase
		{"1starts_with_digit", false},  // leading digit
		{"-leading-hyphen", false},     // leading non-letter
		{"_leading_underscore", false}, // leading non-letter
		{"name with space", false},     // whitespace
		{`name"quote`, false},          // double-quote
		{"name'quote", false},          // single-quote
		{"name;DROP", false},           // semicolon
		{"name--comment", true},        // hyphens are fine, `--` not a comment in identifier context
		{"name/*injection*/", false},   // slash
		{"name`backtick", false},       // backtick
		{"name\\backslash", false},     // backslash
		{"name\nnewline", false},       // newline
		{"name\tnewline", false},       // tab
		{"a" + repeat("b", 63), false}, // length > 63
	}

	for _, tc := range cases {
		got := validExtensionName(tc.name)
		if got != tc.valid {
			t.Errorf("validExtensionName(%q) = %v, want %v", tc.name, got, tc.valid)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
