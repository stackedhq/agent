package executor

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// RotatePassword changes the database password in the running engine, then
// rewrites docker-compose.yml so future container restarts pick up the new
// credentials from env vars.
//
// Flow per engine:
//   - postgres: ALTER USER ... WITH PASSWORD '...' via docker exec psql (stdin)
//   - mysql:    ALTER USER for both the app user and root (stdin, MYSQL_PWD)
//   - mongo:    db.changeUserPassword() via docker exec mongosh (process.env)
//   - redis:    CONFIG SET requirepass via redis-cli -x (stdin, REDISCLI_AUTH)
//
// After the engine-level change succeeds, we rewrite the compose file
// (identical to what db_provision/db_set_access produce) and `compose up -d`
// to reconcile the env vars. The data volume is preserved.
func (e *Executor) RotatePassword(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	dbType := getStringPayload(op.Payload, "dbType")
	containerName := getStringPayload(op.Payload, "containerName")
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	port := getIntPayload(op.Payload, "port")
	accessMode := getStringPayload(op.Payload, "accessMode")
	bindHost := getStringPayload(op.Payload, "tailscaleIp")
	oldCreds := getMapPayload(op.Payload, "oldCredentials")
	newCreds := getMapPayload(op.Payload, "newCredentials")

	if databaseID == "" {
		return fmt.Errorf("db_rotate_password requires databaseId")
	}
	if dbType == "" {
		return fmt.Errorf("db_rotate_password requires dbType")
	}
	if containerName == "" {
		return fmt.Errorf("db_rotate_password requires containerName")
	}
	if err := checkContainerName("database", containerName); err != nil {
		return err
	}
	if dockerImage == "" {
		return fmt.Errorf("db_rotate_password requires dockerImage")
	}
	if len(oldCreds) == 0 || len(newCreds) == 0 {
		return fmt.Errorf("db_rotate_password requires oldCredentials and newCredentials")
	}
	if accessMode == "" {
		accessMode = "internal"
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.AddLine(fmt.Sprintf("Rotating %s password for %s", dbType, containerName))
	streamer.Flush()

	// Step 1: ALTER the password in the running engine.
	if err := alterPassword(containerName, dbType, oldCreds, newCreds, streamer, e); err != nil {
		return fail(fmt.Errorf("alter password: %w", err))
	}

	// Step 2: Rewrite docker-compose.yml with new credentials so a future
	// container restart picks them up from env.
	compose, err := generateDatabaseCompose(dbType, port, containerName, dockerImage, newCreds, accessMode, bindHost)
	if err != nil {
		return fail(fmt.Errorf("generate compose: %w", err))
	}
	dir := databaseDir(databaseID)
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}

	// Step 3: Reconcile the container (picks up new env vars without
	// losing data — the named volume survives).
	streamer.AddLine("Reconciling container with new credentials")
	streamer.Flush()
	if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "up", "-d", "--remove-orphans")...); err != nil {
		return fail(fmt.Errorf("compose up: %w", err))
	}

	streamer.AddLine("Password rotated successfully")
	streamer.Flush()
	return nil
}

func alterPassword(containerName, dbType string, oldCreds, newCreds map[string]string, streamer *logs.Streamer, e *Executor) error {
	step, err := buildAlterPassword(containerName, dbType, oldCreds, newCreds)
	if err != nil {
		return err
	}
	streamer.AddLine(step.message)
	streamer.Flush()
	cmd := step.exec.Command()
	if step.stdin != "" {
		cmd.Stdin = strings.NewReader(step.stdin)
	}
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if trimmed != "" {
		for _, line := range sanitizeAlterPasswordOutput(trimmed, oldCreds, newCreds) {
			streamer.AddLine(line)
		}
		streamer.Flush()
	}
	if err != nil {
		return fmt.Errorf("docker exec %s: %w", dbType, err)
	}
	if step.expectOutput != "" && trimmed != step.expectOutput {
		// redis-cli exits 0 even when AUTH or the command fails.
		return fmt.Errorf("%s did not confirm the change (expected %q)", dbType, step.expectOutput)
	}
	return nil
}

// sanitizeAlterPasswordOutput splits the engine's output into log lines
// with anything that could carry a password removed. psql echoes the
// failing statement on error (`LINE 2: ALTER USER "u" WITH PASSWORD '...'`)
// even with -q, so those lines are dropped along with their `^` marker,
// and any literal credential value left in a line is masked.
func sanitizeAlterPasswordOutput(out string, credSets ...map[string]string) []string {
	var secrets []string
	for _, creds := range credSets {
		for k, v := range creds {
			if v != "" && strings.Contains(strings.ToLower(k), "password") {
				secrets = append(secrets, v)
			}
		}
	}
	var lines []string
	dropCaret := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if dropCaret && strings.Trim(trimmed, "^ ") == "" {
			dropCaret = false
			continue
		}
		dropCaret = false
		if strings.HasPrefix(trimmed, "LINE ") && strings.Contains(strings.ToUpper(line), "PASSWORD") {
			lines = append(lines, "LINE (statement omitted: contains a password)")
			dropCaret = true
			continue
		}
		for _, secret := range secrets {
			line = strings.ReplaceAll(line, secret, "***")
		}
		lines = append(lines, line)
	}
	return lines
}

// alterPasswordStep is one engine-level password change. Neither the old
// nor the new password appears in argv: the old one authenticates through
// the docker CLI's env (`-e NAME`), the new one goes over stdin (SQL,
// redis-cli -x) or env (mongosh reads process.env).
type alterPasswordStep struct {
	message string
	exec    dockerExec
	stdin   string
	// expectOutput, when set, must equal the command's trimmed output.
	expectOutput string
}

func buildAlterPassword(containerName, dbType string, oldCreds, newCreds map[string]string) (alterPasswordStep, error) {
	switch dbType {
	case "postgres":
		user := oldCreds["user"]
		newPw := newCreds["password"]
		dbName := oldCreds["dbName"]
		if user == "" || newPw == "" || dbName == "" {
			return alterPasswordStep{}, fmt.Errorf("postgres credentials incomplete")
		}
		// ALTER USER via psql inside the container. Local-socket peer
		// auth means we don't need the old password to connect. The
		// statement (which carries the new password) is read from stdin.
		// standard_conforming_strings is pinned so backslashes in the
		// password stay literal.
		sql := fmt.Sprintf("SET standard_conforming_strings = on;\nALTER USER \"%s\" WITH PASSWORD '%s';\n",
			sqlIdentEscape(user), strings.ReplaceAll(newPw, "'", "''"))
		return alterPasswordStep{
			message: "Altering postgres user password",
			exec: newDockerExec(true, containerName, nil,
				"psql", "--no-psqlrc", "-q", "-U", user, "-d", dbName, "-v", "ON_ERROR_STOP=1"),
			stdin: sql,
		}, nil

	case "mysql":
		user := oldCreds["user"]
		oldRootPw := oldCreds["rootPassword"]
		newPw := newCreds["password"]
		newRootPw := newCreds["rootPassword"]
		if user == "" || oldRootPw == "" || newPw == "" || newRootPw == "" {
			return alterPasswordStep{}, fmt.Errorf("mysql credentials incomplete")
		}
		// Connect as root with the old password (MYSQL_PWD), change both
		// passwords with SQL on stdin.
		// root exists as both 'root'@'%' and 'root'@'localhost' in the
		// official images; the agent's own `docker exec mysql -u root`
		// (backups, restores) connects over the socket as the latter, so
		// both must change.
		sql := fmt.Sprintf(
			"ALTER USER '%s'@'%%' IDENTIFIED BY '%s'; ALTER USER 'root'@'%%' IDENTIFIED BY '%s'; ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED BY '%s'; FLUSH PRIVILEGES;\n",
			escapeSQLString(user), escapeSQLString(newPw), escapeSQLString(newRootPw), escapeSQLString(newRootPw),
		)
		return alterPasswordStep{
			message: "Altering mysql user and root passwords",
			exec: newDockerExec(true, containerName, map[string]string{"MYSQL_PWD": oldRootPw},
				"mysql", "-u", "root"),
			stdin: sql,
		}, nil

	case "mongo":
		user := oldCreds["user"]
		oldPw := oldCreds["password"]
		newPw := newCreds["password"]
		if user == "" || oldPw == "" || newPw == "" {
			return alterPasswordStep{}, fmt.Errorf("mongo credentials incomplete")
		}
		// mongosh has no password env var: connect unauthenticated, then
		// auth and change the password with values read from the exec'd
		// process env. The script itself holds no secret.
		userJSON, _ := json.Marshal(user)
		js := fmt.Sprintf(`const u = %s; const admin = db.getSiblingDB("admin"); admin.auth(u, process.env.STACKED_MONGO_OLD_PASSWORD); admin.changeUserPassword(u, process.env.STACKED_MONGO_NEW_PASSWORD);`, userJSON)
		return alterPasswordStep{
			message: "Altering mongo user password",
			exec: newDockerExec(false, containerName, map[string]string{
				"STACKED_MONGO_OLD_PASSWORD": oldPw,
				"STACKED_MONGO_NEW_PASSWORD": newPw,
			}, "mongosh", "--quiet", "--norc", "admin", "--eval", js),
		}, nil

	case "redis":
		oldPw := oldCreds["password"]
		newPw := newCreds["password"]
		if oldPw == "" || newPw == "" {
			return alterPasswordStep{}, fmt.Errorf("redis credentials incomplete")
		}
		// REDISCLI_AUTH authenticates with the old password; `-x` reads
		// the last argument (the new password) from stdin.
		return alterPasswordStep{
			message: "Setting new redis password",
			exec: newDockerExec(true, containerName, map[string]string{"REDISCLI_AUTH": oldPw},
				"redis-cli", "-x", "CONFIG", "SET", "requirepass"),
			stdin:        newPw,
			expectOutput: "OK",
		}, nil

	default:
		return alterPasswordStep{}, fmt.Errorf("unsupported database type for password rotation: %s", dbType)
	}
}

// escapeSQLString escapes single quotes for SQL string literals.
func escapeSQLString(s string) string {
	result := ""
	for _, c := range s {
		if c == '\'' {
			result += "''"
		} else if c == '\\' {
			result += "\\\\"
		} else {
			result += string(c)
		}
	}
	return result
}

// escapeJSString escapes double quotes and backslashes for JS string literals.
func escapeJSString(s string) string {
	result := ""
	for _, c := range s {
		if c == '"' {
			result += `\"`
		} else if c == '\\' {
			result += "\\\\"
		} else {
			result += string(c)
		}
	}
	return result
}
