package executor

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
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
	if err := checkReadOnlyQuery(query.Query); err != nil {
		return nil, err
	}
	user, dbName := query.Creds["user"], query.Creds["dbName"]
	if query.ContainerName == "" || user == "" || dbName == "" {
		return nil, fmt.Errorf("query credentials incomplete")
	}
	return runReadOnlyQuery(query.ContainerName, user, dbName, query.Query)
}

// runReadOnlyQuery runs an already-validated SELECT through psql in the
// container and parses the CSV result.
func runReadOnlyQuery(container, user, dbName, sql string) (map[string]interface{}, error) {
	if err := checkReadOnlyQuery(sql); err != nil {
		return nil, err
	}
	// COPY yields machine-readable CSV only; BEGIN/ROLLBACK are quiet. A
	// read-only transaction, lock timeout, and wall timeout bound impact even
	// if a syntactically valid SELECT is unexpectedly expensive.
	ctx, cancel := context.WithTimeout(currentOpContext(), 12*time.Second)
	defer cancel()
	cmd := opCommandContext(ctx, "docker", readOnlyQueryArgs(container, user, dbName)...)
	cmd.Env = append(os.Environ(), readOnlyPGOptions)
	script := readOnlyQueryScript(sql)
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
	// stderr is read concurrently and both pipes are drained to EOF, so
	// psql never blocks on a full pipe (e.g. after the row cap is hit).
	stderrCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(stderr, 4096))
		_, _ = io.Copy(io.Discard, stderr)
		stderrCh <- b
	}()
	result, parseErr := parseQueryCSV(io.LimitReader(stdout, maxQueryBytes+1))
	_, _ = io.Copy(io.Discard, stdout)
	stderrBytes := <-stderrCh
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

// readOnlyPGOptions makes every transaction in the psql session read-only
// at the server, independent of the BEGIN READ ONLY in the script. Passed
// to `docker exec` as `-e PGOPTIONS` with the value in the CLI's env.
const readOnlyPGOptions = "PGOPTIONS=-c default_transaction_read_only=on"

// readOnlyQueryArgs is the `docker exec` argv for the query console.
//   - `--no-psqlrc` (-X): a psqlrc in the container can't run meta-commands;
//   - `ON_ERROR_STOP=1`: the first error aborts the script, so nothing after
//     a failed statement runs.
func readOnlyQueryArgs(container, user, dbName string) []string {
	return []string{
		"exec", "-i", "-e", "PGOPTIONS", container,
		"psql", "--no-psqlrc", "-q", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", dbName,
	}
}

// readOnlyQueryScript wraps the query in COPY (...) inside a read-only
// transaction. The query sits on its own lines so a trailing `--` comment
// can't swallow the closing `) TO STDOUT ...; ROLLBACK;`; unterminated
// quotes/comments swallow it instead and the server rejects the statement.
func readOnlyQueryScript(query string) string {
	q := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query), ";"))
	return "BEGIN READ ONLY;\n" +
		"SET LOCAL statement_timeout = '10s';\n" +
		"SET LOCAL lock_timeout = '2s';\n" +
		"COPY (\n" + q + "\n) TO STDOUT WITH (FORMAT csv, HEADER true, NULL '\\N');\n" +
		"ROLLBACK;\n"
}

// checkReadOnlyQuery accepts a single SELECT. The query is fed to psql on
// stdin, so psql's own lexer sees it: a backslash anywhere could start a
// meta-command (`\g` executes the buffer early, `\!` runs a shell), which
// would escape the COPY wrapper and the read-only transaction. psql only
// ignores backslashes inside quoted literals, and re-implementing its lexer
// isn't worth it, so any backslash is rejected (use chr(92) for a literal
// backslash).
func checkReadOnlyQuery(query string) error {
	if strings.Contains(query, "\\") {
		return fmt.Errorf("invalid read-only query: backslashes are not allowed (psql would treat them as meta-commands); use chr(92) for a literal backslash")
	}
	if !validReadOnlyQuery(query) {
		return fmt.Errorf("invalid read-only query")
	}
	return nil
}

func validReadOnlyQuery(query string) bool {
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(query), ";"))
	return trimmed != "" && len(trimmed) <= 16*1024 && !strings.Contains(trimmed, "\x00") && !strings.Contains(trimmed, "\\") && !strings.Contains(trimmed, ";") && strings.HasPrefix(strings.ToLower(trimmed), "select") && (len(trimmed) == 6 || isSQLWhitespace(trimmed[6]))
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
