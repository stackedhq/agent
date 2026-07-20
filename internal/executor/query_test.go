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
