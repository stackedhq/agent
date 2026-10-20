package executor

import "testing"

// buildEnvFile writes a `docker run --env-file` file. The docker CLI does
// NOT quote-strip values, so quote characters would be passed through as
// literal content. Regression test for a bug where values containing spaces
// (or other "special" characters) got wrapped in quotes here, baking literal
// `"…"` characters into container env vars like
// `SMTP_FROM="Riffado <noreply@riffado.com>"`.
func TestBuildEnvFileDoesNotQuoteValues(t *testing.T) {
	got := buildEnvFile(map[string]string{
		"SMTP_FROM": "Riffado <noreply@riffado.com>",
		"PLAIN":     "value",
		"HAS_HASH":  "a#b",
		"HAS_QUOTE": `has "quotes" inside`,
	})

	want := "HAS_HASH=a#b\n" +
		"HAS_QUOTE=has \"quotes\" inside\n" +
		"PLAIN=value\n" +
		"SMTP_FROM=Riffado <noreply@riffado.com>\n"

	if got != want {
		t.Fatalf("buildEnvFile() =\n%q\nwant\n%q", got, want)
	}
}
