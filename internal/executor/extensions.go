package executor

import (
	"fmt"
	"regexp"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// extensionNameRe constrains what we accept as a Postgres extension name
// before it ever reaches `psql -c "CREATE EXTENSION ..."`. Names in the
// server-side catalog (`src/lib/postgres-extensions.ts`) all match this
// pattern (lowercase, underscores, hyphens), so a payload that doesn't
// match was either tampered with or sent by a future server version we
// haven't shipped agent support for yet — either way, refuse.
//
// Postgres identifier max length is 63; we use 64 here as belt-and-braces.
var extensionNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

func validExtensionName(s string) bool {
	return extensionNameRe.MatchString(s)
}

// EnableExtension runs `CREATE EXTENSION IF NOT EXISTS "<name>"` against
// the live database container. Idempotent — `IF NOT EXISTS` makes a retry
// after a partial failure (e.g. agent crash before reporting back) a
// no-op.
//
// We connect via `docker exec ... psql` rather than over the published
// port for two reasons:
//
//   1. The official `postgres` image trusts local-socket peer auth, so
//      we don't need the password in the payload.
//   2. It works regardless of the host's network config, including hosts
//      where the database port isn't bound to localhost.
//
// Defense-in-depth on the extension name: the server already validates
// against a closed allowlist, but we re-validate here with a strict
// regex before splicing into SQL. The name is then double-quoted as a
// Postgres identifier — safe because the regex rejects quotes and
// backslashes outright.
func (e *Executor) EnableExtension(op client.Operation) error {
	return e.runExtensionOp(op, true)
}

// DisableExtension is the mirror of EnableExtension. `IF EXISTS` makes
// it idempotent against a database where the extension was never
// installed.
func (e *Executor) DisableExtension(op client.Operation) error {
	return e.runExtensionOp(op, false)
}

func (e *Executor) runExtensionOp(op client.Operation, enable bool) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	containerName := getStringPayload(op.Payload, "containerName")
	extName := getStringPayload(op.Payload, "extensionName")
	dbUser := getStringPayload(op.Payload, "dbUser")
	dbName := getStringPayload(op.Payload, "dbName")

	verb := "db_extension_enable"
	if !enable {
		verb = "db_extension_disable"
	}

	if databaseID == "" {
		return fmt.Errorf("%s requires databaseId", verb)
	}
	if containerName == "" {
		return fmt.Errorf("%s requires containerName", verb)
	}
	if extName == "" {
		return fmt.Errorf("%s requires extensionName", verb)
	}
	if dbUser == "" {
		return fmt.Errorf("%s requires dbUser", verb)
	}
	if dbName == "" {
		return fmt.Errorf("%s requires dbName", verb)
	}
	if !validExtensionName(extName) {
		return fmt.Errorf("%s: invalid extension name %q", verb, extName)
	}

	var sql, action string
	if enable {
		sql = fmt.Sprintf(`CREATE EXTENSION IF NOT EXISTS "%s";`, extName)
		action = "Enabling"
	} else {
		sql = fmt.Sprintf(`DROP EXTENSION IF EXISTS "%s";`, extName)
		action = "Disabling"
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	streamer.AddLine(fmt.Sprintf("%s extension %s in %s", action, extName, dbName))
	streamer.Flush()

	if err := e.runCommandWithStreamer(streamer, "", "docker", "exec",
		containerName,
		"psql", "-U", dbUser, "-d", dbName,
		"-v", "ON_ERROR_STOP=1",
		"-c", sql,
	); err != nil {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return fmt.Errorf("%s: %w", verb, err)
	}

	streamer.AddLine("Done")
	streamer.Flush()
	return nil
}
