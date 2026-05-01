package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

const databasesDir = "/opt/stacked/databases"

// databaseDir returns the working directory for a given database. Mirrors
// `serviceDir` in shape so debugging / on-disk inspection feels familiar.
func databaseDir(databaseID string) string {
	return filepath.Join(databasesDir, databaseID)
}

// Provision pulls the database image and brings up its container. Streams
// progress through the same logs.Streamer used for service deploys so the
// dashboard's Activity tab gets real lines (the server stores these into
// `operations.result.lines`, see G1 in the server PR).
//
// Idempotent on retry: `compose up -d` is a no-op against an already-running
// container, and `docker pull` is a fast no-op when the image is cached.
func (e *Executor) Provision(op client.Operation) (map[string]interface{}, error) {
	databaseID := getStringPayload(op.Payload, "databaseId")
	dbType := getStringPayload(op.Payload, "dbType")
	port := getIntPayload(op.Payload, "port")
	containerName := getStringPayload(op.Payload, "containerName")
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	credentials := getMapPayload(op.Payload, "credentials")

	if databaseID == "" {
		return nil, fmt.Errorf("db_provision requires databaseId")
	}
	if dbType == "" {
		return nil, fmt.Errorf("db_provision requires dbType")
	}
	if port == 0 {
		return nil, fmt.Errorf("db_provision requires port")
	}
	if dockerImage == "" {
		return nil, fmt.Errorf("db_provision requires dockerImage")
	}
	if containerName == "" {
		return nil, fmt.Errorf("db_provision requires containerName")
	}

	dir := databaseDir(databaseID)
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("create database dir: %w", err)
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("Provisioning %s database (%s)", dbType, dockerImage))
	streamer.Flush()

	compose, err := generateDatabaseCompose(dbType, port, containerName, dockerImage, credentials)
	if err != nil {
		return nil, fail(err)
	}
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return nil, fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}

	// Ensure the stacked network exists. Same idempotent call services use,
	// so a fresh-host provision works even if `setup` hasn't been re-run.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	streamer.SetProgress(20)
	streamer.AddLine("Pulling image " + dockerImage + "...")
	streamer.Flush()

	if err := e.runCommandWithStreamer(streamer, dir, "docker", "pull", dockerImage); err != nil {
		return nil, fail(fmt.Errorf("docker pull %s: %w", dockerImage, err))
	}

	streamer.SetProgress(80)
	streamer.AddLine("Starting container...")
	streamer.Flush()

	log.Printf("Provisioning database %s (%s)", databaseID, containerName)
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d", "--remove-orphans"); err != nil {
		return nil, fail(fmt.Errorf("docker compose up: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Database provisioned")
	streamer.Flush()

	return map[string]interface{}{
		"containerName": containerName,
	}, nil
}

// StartDB resumes a previously-stopped database. Uses `compose start` (not
// `up`) because the container metadata is preserved across a Stop, so a
// straight start is faster and avoids re-pulling the image.
//
// Falls back to `compose up -d` if the container is missing — the only way
// that happens normally is a manual `docker rm` between Stop and Start, but
// it's a recoverable state we shouldn't punish the user for.
func (e *Executor) StartDB(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	if databaseID == "" {
		return fmt.Errorf("db_start requires databaseId")
	}

	dir := databaseDir(databaseID)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); os.IsNotExist(err) {
		return fmt.Errorf("database %s has no compose file at %s — re-provision required", databaseID, dir)
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	streamer.AddLine(fmt.Sprintf("Starting database %s", databaseID))
	streamer.Flush()

	log.Printf("Starting database %s", databaseID)

	// `compose start` errors out if the container doesn't exist yet (e.g.
	// after a manual `docker rm`); fall back to `up -d` which creates it.
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "start"); err != nil {
		log.Printf("compose start failed for %s, falling back to up -d: %v", databaseID, err)
		streamer.AddLine("compose start failed; recreating container with up -d")
		streamer.Flush()
		if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d"); err != nil {
			streamer.AddLine("ERROR: " + err.Error())
			streamer.Flush()
			return fmt.Errorf("docker compose up: %w", err)
		}
	}

	streamer.AddLine("Database started")
	streamer.Flush()
	return nil
}

// StopDB pauses a database. Uses `compose stop` (NOT `down`) so container
// metadata stays intact for the next Start. Volumes obviously persist
// either way; the difference is whether the container shell sticks around.
func (e *Executor) StopDB(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	if databaseID == "" {
		return fmt.Errorf("db_stop requires databaseId")
	}

	dir := databaseDir(databaseID)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); os.IsNotExist(err) {
		// No compose file = nothing to stop. Treat as success; the row is
		// already in a no-database-running state and a Start will surface
		// the "re-provision required" error path.
		log.Printf("StopDB: no compose file for %s, treating as no-op", databaseID)
		return nil
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	streamer.AddLine(fmt.Sprintf("Stopping database %s", databaseID))
	streamer.Flush()

	log.Printf("Stopping database %s", databaseID)
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "stop"); err != nil {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return fmt.Errorf("docker compose stop: %w", err)
	}

	streamer.AddLine("Database stopped")
	streamer.Flush()
	return nil
}

// DestroyDB tears down a database for good. `down -v` removes containers AND
// volumes — destruction is intentional, the user clicked Delete and confirmed.
// Idempotent on a missing dir so a retry after a partial failure still
// succeeds (e.g. compose down ran but rm -rf raced with another process).
func (e *Executor) DestroyDB(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	if databaseID == "" {
		return fmt.Errorf("db_destroy requires databaseId")
	}

	dir := databaseDir(databaseID)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("DestroyDB: dir %s already gone, treating as success", dir)
		return nil
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	streamer.AddLine(fmt.Sprintf("Destroying database %s", databaseID))
	streamer.Flush()

	log.Printf("Destroying database %s", databaseID)
	// `down -v` errors out if the compose file is missing — at that point
	// the container/volumes were already cleaned up so swallow the error.
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
		if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "down", "-v"); err != nil {
			streamer.AddLine("ERROR: " + err.Error())
			streamer.Flush()
			return fmt.Errorf("docker compose down: %w", err)
		}
	}

	if err := os.RemoveAll(dir); err != nil {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return fmt.Errorf("remove %s: %w", dir, err)
	}

	streamer.AddLine("Database destroyed")
	streamer.Flush()
	return nil
}

// generateDatabaseCompose returns a docker-compose.yml tailored to the DB
// engine. Sets `com.stacked.kind=database` so the runtimelogs manager
// correctly skips DB containers, and the new databaselogs manager picks
// them up.
//
// The volume is named `data` and is compose-managed (not a bind mount) —
// `compose down -v` cleans it up on destroy, plain stop/start preserves it.
func generateDatabaseCompose(dbType string, port int, containerName, image string, creds map[string]string) (string, error) {
	switch dbType {
	case "postgres":
		user := creds["user"]
		password := creds["password"]
		dbName := creds["dbName"]
		if user == "" || password == "" || dbName == "" {
			return "", fmt.Errorf("postgres credentials incomplete")
		}
		return fmt.Sprintf(`services:
  database:
    image: %s
    container_name: %s
    restart: unless-stopped
    environment:
      POSTGRES_USER: %s
      POSTGRES_PASSWORD: %s
      POSTGRES_DB: %s
    volumes:
      - data:/var/lib/postgresql/data
    ports:
      - "%d:5432"
    networks:
      - stacked
    labels:
      com.stacked.kind: database

volumes:
  data:

networks:
  stacked:
    name: stacked
    external: true
`, image, containerName, yamlEscape(user), yamlEscape(password), yamlEscape(dbName), port), nil

	case "mysql":
		user := creds["user"]
		password := creds["password"]
		dbName := creds["dbName"]
		rootPw := creds["rootPassword"]
		if user == "" || password == "" || dbName == "" || rootPw == "" {
			return "", fmt.Errorf("mysql credentials incomplete")
		}
		return fmt.Sprintf(`services:
  database:
    image: %s
    container_name: %s
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: %s
      MYSQL_DATABASE: %s
      MYSQL_USER: %s
      MYSQL_PASSWORD: %s
    volumes:
      - data:/var/lib/mysql
    ports:
      - "%d:3306"
    networks:
      - stacked
    labels:
      com.stacked.kind: database

volumes:
  data:

networks:
  stacked:
    name: stacked
    external: true
`, image, containerName, yamlEscape(rootPw), yamlEscape(dbName), yamlEscape(user), yamlEscape(password), port), nil

	case "mongo":
		user := creds["user"]
		password := creds["password"]
		dbName := creds["dbName"]
		if user == "" || password == "" || dbName == "" {
			return "", fmt.Errorf("mongo credentials incomplete")
		}
		return fmt.Sprintf(`services:
  database:
    image: %s
    container_name: %s
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: %s
      MONGO_INITDB_ROOT_PASSWORD: %s
      MONGO_INITDB_DATABASE: %s
    volumes:
      - data:/data/db
    ports:
      - "%d:27017"
    networks:
      - stacked
    labels:
      com.stacked.kind: database

volumes:
  data:

networks:
  stacked:
    name: stacked
    external: true
`, image, containerName, yamlEscape(user), yamlEscape(password), yamlEscape(dbName), port), nil

	case "redis":
		password := creds["password"]
		if password == "" {
			return "", fmt.Errorf("redis credentials incomplete")
		}
		// `command:` is a YAML sequence to keep the password out of a
		// re-parsed shell string. The password is base64url so YAML-escape
		// is still cheap insurance against future credential generators.
		return fmt.Sprintf(`services:
  database:
    image: %s
    container_name: %s
    restart: unless-stopped
    command: ["redis-server", "--requirepass", %s]
    volumes:
      - data:/data
    ports:
      - "%d:6379"
    networks:
      - stacked
    labels:
      com.stacked.kind: database

volumes:
  data:

networks:
  stacked:
    name: stacked
    external: true
`, image, containerName, yamlQuote(password), port), nil
	}
	return "", fmt.Errorf("unsupported database type: %s", dbType)
}

// yamlEscape returns a YAML-safe form for an environment value. Postgres
// passwords from base64url alphabet (A-Za-z0-9_-) don't need quoting, but
// imported databases (e.g. via the Dokploy importer) can carry arbitrary
// strings — quote when in doubt.
func yamlEscape(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\n\"'#:&*?{}[]|<>=!%@`,") {
		return yamlQuote(s)
	}
	// Numbers / booleans need quoting too, otherwise YAML parses them
	// out of string context.
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "null", "~":
		return yamlQuote(s)
	}
	return s
}

// yamlQuote double-quotes and escapes a string for YAML.
func yamlQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

// getIntPayload pulls an int from a JSON-decoded payload. JSON numbers come
// in as float64, so we coerce.
func getIntPayload(payload map[string]interface{}, key string) int {
	v, ok := payload[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// getMapPayload pulls a string-keyed string-valued sub-map from a JSON
// payload. Used for `credentials` which is `{user, password, dbName, ...}`.
func getMapPayload(payload map[string]interface{}, key string) map[string]string {
	v, ok := payload[key]
	if !ok {
		return nil
	}
	raw, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, vv := range raw {
		if s, ok := vv.(string); ok {
			out[k] = s
		}
	}
	return out
}
