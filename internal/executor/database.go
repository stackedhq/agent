package executor

import (
	"fmt"
	"log"
	"net/netip"
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
	// External exposure. Absent → "public" to preserve historical behavior
	// for older servers that don't send the field (the new server always
	// sends "internal" for freshly-provisioned databases). bindHost carries
	// the machine's Tailscale IP and is only consulted in tailnet mode.
	accessMode := getStringPayload(op.Payload, "accessMode")
	if accessMode == "" {
		accessMode = "public"
	}
	bindHost := getStringPayload(op.Payload, "tailscaleIp")

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
	if version := getStringPayload(op.Payload, "version"); version != "" && !validDBVersion(version) {
		return nil, fmt.Errorf("db_provision: invalid version %q", truncateForError(version))
	}
	// generateDatabaseCompose validates the image and container name; check
	// them before any directory is created.
	if err := validateImageReference(dockerImage); err != nil {
		return nil, fmt.Errorf("db_provision: %w", err)
	}
	if err := validateContainerName(containerName); err != nil {
		return nil, fmt.Errorf("db_provision: %w", err)
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

	compose, err := generateDatabaseCompose(dbType, port, containerName, dockerImage, credentials, accessMode, bindHost)
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
	if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "up", "-d", "--remove-orphans")...); err != nil {
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

	// Ensure the stacked network exists — it vanishes on Docker/machine restart.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	// `compose start` errors out if the container doesn't exist yet (e.g.
	// after a manual `docker rm`); fall back to `up -d` which creates it.
	if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "start")...); err != nil {
		log.Printf("compose start failed for %s, falling back to up -d: %v", databaseID, err)
		streamer.AddLine("compose start failed; recreating container with up -d")
		streamer.Flush()
		// Tear down the stale container (releases the port binding) but keep
		// volumes so data survives. Without this, `up -d` fails with
		// "port is already allocated" when a ghost container holds the port.
		_ = e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "down")...)
		if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "up", "-d")...); err != nil {
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
	if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "stop")...); err != nil {
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

	if !isUUID(databaseID) {
		return fmt.Errorf("db_destroy: invalid databaseId")
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
		if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "down", "-v")...); err != nil {
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
// databaseNativePort is the port the engine listens on inside its container —
// the target of the host port mapping and the port siblings reach over the
// `stacked` network.
func databaseNativePort(dbType string) int {
	switch dbType {
	case "postgres":
		return 5432
	case "mysql":
		return 3306
	case "mongo":
		return 27017
	case "redis":
		return 6379
	}
	return 0
}

// databasePortSpecs returns the compose `ports:` entries for a database
// based on its access mode, or none.
//
//   - internal: none — no host binding. Reachable only over the `stacked`
//     Docker network; closed to the host and internet by construction.
//   - tailnet:  bind to the machine's Tailscale IP (bindHost) so the port is
//     reachable only over the tailnet. If bindHost is empty (Tailscale not
//     ready) we publish nothing rather than fall back to 0.0.0.0 — failing
//     closed is the safe choice. A bindHost that isn't an IP address is an
//     error.
//   - public:   bind 0.0.0.0. Source-IP restriction is the user's
//     responsibility at their cloud firewall (see access.go).
func databasePortSpecs(accessMode, bindHost string, hostPort, nativePort int) ([]string, error) {
	switch accessMode {
	case "tailnet":
		if bindHost == "" {
			return nil, nil
		}
		addr, err := netip.ParseAddr(bindHost)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("invalid tailscale IP %q", truncateForError(bindHost))
		}
		host := addr.String()
		if addr.Is6() && !addr.Is4In6() {
			host = "[" + host + "]"
		}
		return []string{fmt.Sprintf("%s:%d:%d", host, hostPort, nativePort)}, nil
	case "public":
		return []string{fmt.Sprintf("%d:%d", hostPort, nativePort)}, nil
	default: // internal (and any unknown value — fail closed)
		return nil, nil
	}
}

// redisConfigQuote renders s as a double-quoted redis.conf string with every
// byte hex-escaped, so any password survives redis's config parser intact.
func redisConfigQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, `\x%02x`, s[i])
	}
	b.WriteByte('"')
	return b.String()
}

// redisStartScript keeps the password out of every argv. The compose
// `environment:` hands the container a pre-quoted `requirepass` value; the
// script (running inside the container) writes it to a config file and
// starts redis-server with that file. It re-enters the official image's
// docker-entrypoint.sh when present so redis still drops to the `redis`
// user and gets the image's protected-mode handling. Defaults are
// otherwise unchanged (persistence to /data, the working directory).
const redisStartScript = `set -e
conf=/tmp/stacked-redis.conf
umask 077
printf 'requirepass %s\n' "$STACKED_REDIS_REQUIREPASS" > "$conf"
chmod 0644 "$conf"
if command -v docker-entrypoint.sh >/dev/null 2>&1; then
  exec docker-entrypoint.sh redis-server "$conf"
fi
exec redis-server "$conf"
`

// generateDatabaseCompose returns a docker-compose.yml tailored to the DB
// engine. Sets `com.stacked.kind=database` so the runtimelogs manager
// correctly skips DB containers, and the databaselogs manager picks them
// up. The volume is named `data` and is compose-managed (not a bind
// mount) — `compose down -v` cleans it up on destroy, plain stop/start
// preserves it.
//
// Every scalar goes through compose_yaml.go (JSON-quoted, `$` escaped), so
// credentials are passed to the container verbatim, whatever they contain.
func generateDatabaseCompose(dbType string, port int, containerName, image string, creds map[string]string, accessMode, bindHost string) (string, error) {
	if err := validateImageReference(image); err != nil {
		return "", err
	}
	if err := validateContainerName(containerName); err != nil {
		return "", err
	}
	ports, err := databasePortSpecs(accessMode, bindHost, port, databaseNativePort(dbType))
	if err != nil {
		return "", err
	}

	var env yMap
	var command yNode
	var dataPath string
	switch dbType {
	case "postgres":
		user, password, dbName := creds["user"], creds["password"], creds["dbName"]
		if user == "" || password == "" || dbName == "" {
			return "", fmt.Errorf("postgres credentials incomplete")
		}
		env = yMap{
			{Key: "POSTGRES_USER", Value: yStr(user)},
			{Key: "POSTGRES_PASSWORD", Value: yStr(password)},
			{Key: "POSTGRES_DB", Value: yStr(dbName)},
		}
		dataPath = "/var/lib/postgresql/data"
	case "mysql":
		user, password, dbName, rootPw := creds["user"], creds["password"], creds["dbName"], creds["rootPassword"]
		if user == "" || password == "" || dbName == "" || rootPw == "" {
			return "", fmt.Errorf("mysql credentials incomplete")
		}
		env = yMap{
			{Key: "MYSQL_ROOT_PASSWORD", Value: yStr(rootPw)},
			{Key: "MYSQL_DATABASE", Value: yStr(dbName)},
			{Key: "MYSQL_USER", Value: yStr(user)},
			{Key: "MYSQL_PASSWORD", Value: yStr(password)},
		}
		dataPath = "/var/lib/mysql"
	case "mongo":
		user, password, dbName := creds["user"], creds["password"], creds["dbName"]
		if user == "" || password == "" || dbName == "" {
			return "", fmt.Errorf("mongo credentials incomplete")
		}
		env = yMap{
			{Key: "MONGO_INITDB_ROOT_USERNAME", Value: yStr(user)},
			{Key: "MONGO_INITDB_ROOT_PASSWORD", Value: yStr(password)},
			{Key: "MONGO_INITDB_DATABASE", Value: yStr(dbName)},
		}
		dataPath = "/data/db"
	case "redis":
		password := creds["password"]
		if password == "" {
			return "", fmt.Errorf("redis credentials incomplete")
		}
		env = yMap{{Key: "STACKED_REDIS_REQUIREPASS", Value: yStr(redisConfigQuote(password))}}
		command = yStrList("sh", "-c", redisStartScript)
		dataPath = "/data"
	default:
		return "", fmt.Errorf("unsupported database type: %s", dbType)
	}

	svc := yMap{
		{Key: "image", Value: yStr(image)},
		{Key: "container_name", Value: yStr(containerName)},
		{Key: "restart", Value: yStr("unless-stopped")},
	}
	if command != nil {
		svc = append(svc, yKV{Key: "command", Value: command})
	}
	svc = append(svc,
		yKV{Key: "environment", Value: env},
		yKV{Key: "volumes", Value: yStrList("data:" + dataPath)},
	)
	if len(ports) > 0 {
		svc = append(svc, yKV{Key: "ports", Value: yStrList(ports...)})
	}
	svc = append(svc,
		yKV{Key: "networks", Value: yStrList("stacked")},
		yKV{Key: "labels", Value: yMap{{Key: "com.stacked.kind", Value: yStr("database")}}},
	)
	return renderYAML(yMap{
		{Key: "services", Value: yMap{{Key: "database", Value: svc}}},
		{Key: "volumes", Value: yMap{{Key: "data", Value: yNull{}}}},
		{Key: "networks", Value: stackedNetworkDecl()},
	}), nil
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
