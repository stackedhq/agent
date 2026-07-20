package executor

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const (
	maxQueryRows  = 1000
	maxQueryBytes = 1_000_000
)

// QueryDatabase runs one SELECT in a read-only transaction. SQL is passed to
// psql on stdin, never to a shell; the agent also rejects statement chaining
// before embedding it in COPY (...).
func (e *Executor) QueryDatabase(op client.Operation) (map[string]interface{}, error) {
	query, err := e.Client.GetDatabaseQuery(op.ID)
	if err != nil {
		return nil, fmt.Errorf("fetch query: %w", err)
	}
	if !validReadOnlyQuery(query.Query) {
		return nil, fmt.Errorf("invalid read-only query")
	}
	user, dbName := query.Creds["user"], query.Creds["dbName"]
	if query.ContainerName == "" || user == "" || dbName == "" {
		return nil, fmt.Errorf("query credentials incomplete")
	}

	// COPY yields machine-readable CSV only; BEGIN/ROLLBACK are quiet. A
	// read-only transaction, lock timeout, and wall timeout bound impact even
	// if a syntactically valid SELECT is unexpectedly expensive.
	script := fmt.Sprintf("BEGIN READ ONLY; SET LOCAL statement_timeout = '10s'; SET LOCAL lock_timeout = '2s'; COPY (%s) TO STDOUT WITH (FORMAT csv, HEADER true, NULL '\\N'); ROLLBACK;", query.Query)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", query.ContainerName,
		"psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", dbName)
	cmd.Stdin = strings.NewReader(script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("query stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("query stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}
	result, parseErr := parseQueryCSV(io.LimitReader(stdout, maxQueryBytes+1))
	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, 4096))
	waitErr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("query timed out after 10 seconds")
	}
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		return nil, fmt.Errorf("query failed: %s", strings.TrimSpace(string(stderrBytes)))
	}
	return result, nil
}

func validReadOnlyQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query), ";"))
	return trimmed != "" && len(trimmed) <= 16*1024 && !strings.Contains(trimmed, "\x00") && !strings.Contains(trimmed, ";") && strings.HasPrefix(strings.ToLower(trimmed), "select") && (len(trimmed) == 6 || isSQLWhitespace(trimmed[6]))
}

func isSQLWhitespace(char byte) bool {
	return char == ' ' || char == '\n' || char == '\t' || char == '\r' || char == '('
}

func parseQueryCSV(r io.Reader) (map[string]interface{}, error) {
	reader := csv.NewReader(r)
	columns, err := reader.Read()
	if err == io.EOF {
		return map[string]interface{}{"columns": []string{}, "rows": [][]interface{}{}, "truncated": false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("parse query result: %w", err)
	}
	rows := make([][]interface{}, 0)
	truncated := false
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse query result: %w", err)
		}
		if len(rows) >= maxQueryRows {
			truncated = true
			break
		}
		row := make([]interface{}, len(record))
		for i, value := range record {
			if value == `\N` {
				row[i] = nil
			} else {
				row[i] = value
			}
		}
		rows = append(rows, row)
	}
	return map[string]interface{}{"columns": columns, "rows": rows, "truncated": truncated}, nil
}
