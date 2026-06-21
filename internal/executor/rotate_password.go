package executor

import (
	"fmt"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// RotatePassword changes the database password in the running engine, then
// rewrites docker-compose.yml so future container restarts pick up the new
// credentials from env vars.
//
// Flow per engine:
//   - postgres: ALTER USER ... WITH PASSWORD '...' via docker exec psql
//   - mysql:    ALTER USER for both the app user and root
//   - mongo:    db.changeUserPassword() via docker exec mongosh
//   - redis:    CONFIG SET requirepass via docker exec redis-cli
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
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d", "--remove-orphans"); err != nil {
		return fail(fmt.Errorf("compose up: %w", err))
	}

	streamer.AddLine("Password rotated successfully")
	streamer.Flush()
	return nil
}

func alterPassword(containerName, dbType string, oldCreds, newCreds map[string]string, streamer *logs.Streamer, e *Executor) error {
	switch dbType {
	case "postgres":
		user := oldCreds["user"]
		newPw := newCreds["password"]
		dbName := oldCreds["dbName"]
		if user == "" || newPw == "" || dbName == "" {
			return fmt.Errorf("postgres credentials incomplete")
		}
		// ALTER USER via psql inside the container. Local-socket peer
		// auth means we don't need the old password to connect.
		sql := fmt.Sprintf(`ALTER USER %s WITH PASSWORD '%s';`, user, escapeSQLString(newPw))
		streamer.AddLine("Altering postgres user password")
		streamer.Flush()
		return e.runCommandWithStreamer(streamer, "", "docker", "exec",
			containerName,
			"psql", "-U", user, "-d", dbName,
			"-v", "ON_ERROR_STOP=1",
			"-c", sql,
		)

	case "mysql":
		user := oldCreds["user"]
		oldRootPw := oldCreds["rootPassword"]
		newPw := newCreds["password"]
		newRootPw := newCreds["rootPassword"]
		if user == "" || oldRootPw == "" || newPw == "" || newRootPw == "" {
			return fmt.Errorf("mysql credentials incomplete")
		}
		// Connect as root with old password, change both passwords.
		sql := fmt.Sprintf(
			`ALTER USER '%s'@'%%' IDENTIFIED BY '%s'; ALTER USER 'root'@'%%' IDENTIFIED BY '%s'; FLUSH PRIVILEGES;`,
			escapeSQLString(user), escapeSQLString(newPw), escapeSQLString(newRootPw),
		)
		streamer.AddLine("Altering mysql user and root passwords")
		streamer.Flush()
		return e.runCommandWithStreamer(streamer, "", "docker", "exec",
			containerName,
			"mysql", "-u", "root", "-p"+oldRootPw,
			"-e", sql,
		)

	case "mongo":
		user := oldCreds["user"]
		oldPw := oldCreds["password"]
		newPw := newCreds["password"]
		if user == "" || oldPw == "" || newPw == "" {
			return fmt.Errorf("mongo credentials incomplete")
		}
		// mongosh with old credentials, then changeUserPassword.
		js := fmt.Sprintf(`db.changeUserPassword("%s", "%s")`, escapeJSString(user), escapeJSString(newPw))
		streamer.AddLine("Altering mongo user password")
		streamer.Flush()
		return e.runCommandWithStreamer(streamer, "", "docker", "exec",
			containerName,
			"mongosh",
			"-u", user, "-p", oldPw,
			"--authenticationDatabase", "admin",
			"admin",
			"--eval", js,
		)

	case "redis":
		oldPw := oldCreds["password"]
		newPw := newCreds["password"]
		if oldPw == "" || newPw == "" {
			return fmt.Errorf("redis credentials incomplete")
		}
		streamer.AddLine("Setting new redis password")
		streamer.Flush()
		// AUTH with old password, then CONFIG SET requirepass.
		// Two separate commands: AUTH first, then CONFIG SET.
		if err := e.runCommandWithStreamer(streamer, "", "docker", "exec",
			containerName,
			"redis-cli", "-a", oldPw,
			"CONFIG", "SET", "requirepass", newPw,
		); err != nil {
			return err
		}
		return nil

	default:
		return fmt.Errorf("unsupported database type for password rotation: %s", dbType)
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
