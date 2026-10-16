package executor

import (
	"strings"
	"testing"
)

func TestValidReadOnlyQuery(t *testing.T) {
	for _, query := range []string{"SELECT 1", " select id FROM users; ", "SELECT\n* FROM users"} {
		if !validReadOnlyQuery(query) {
			t.Fatalf("expected valid query %q", query)
		}
	}
	for _, query := range []string{"DELETE FROM users", "SELECT 1; DELETE FROM users", "SELECT\x00 1"} {
		if validReadOnlyQuery(query) {
			t.Fatalf("expected invalid query %q", query)
		}
	}
}

func TestParseQueryCSV(t *testing.T) {
	result, err := parseQueryCSV(strings.NewReader("id,name\n1,Ada\n2,\\N\n"))
	if err != nil {
		t.Fatal(err)
	}
	columns := result["columns"].([]string)
	if len(columns) != 2 || columns[1] != "name" {
		t.Fatalf("unexpected columns: %#v", columns)
	}
	rows := result["rows"].([][]interface{})
	if rows[1][1] != nil {
		t.Fatalf("expected null, got %#v", rows[1][1])
	}
}

func TestCheckReadOnlyQueryRejectsBackslashes(t *testing.T) {
	for _, q := range []string{
		"SELECT 1) TO STDOUT \\g\nCOMMIT \\g\nDROP TABLE t \\g",
		"SELECT 1 \\! id",
		"SELECT '\\\\'",
		"SELECT E'\\n'",
	} {
		err := checkReadOnlyQuery(q)
		if err == nil || !strings.Contains(err.Error(), "backslash") {
			t.Fatalf("query %q: expected backslash rejection, got %v", q, err)
		}
	}
	if err := checkReadOnlyQuery("SELECT chr(92)"); err != nil {
		t.Fatalf("plain query rejected: %v", err)
	}
}

func TestReadOnlyQueryScriptIsolatesQueryLines(t *testing.T) {
	script := readOnlyQueryScript("SELECT 1 --;")
	// The query sits on its own line, so a trailing comment can't swallow
	// the closing COPY clause or the ROLLBACK.
	if !strings.Contains(script, "COPY (\nSELECT 1 --\n) TO STDOUT") {
		t.Fatalf("query not isolated on its own line:\n%s", script)
	}
	if !strings.HasPrefix(script, "BEGIN READ ONLY;\n") || !strings.HasSuffix(script, "ROLLBACK;\n") {
		t.Fatalf("unexpected script:\n%s", script)
	}
}

func TestReadOnlyQueryArgs(t *testing.T) {
	args := strings.Join(readOnlyQueryArgs("db1", "app", "appdb"), " ")
	for _, want := range []string{"-e PGOPTIONS db1", "--no-psqlrc", "-v ON_ERROR_STOP=1"} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %q", want, args)
		}
	}
	if readOnlyPGOptions != "PGOPTIONS=-c default_transaction_read_only=on" {
		t.Fatalf("unexpected PGOPTIONS %q", readOnlyPGOptions)
	}
}
