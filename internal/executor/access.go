package executor

import (
	"fmt"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// SetAccess reconciles a database's external exposure to match the server's
// desired access mode + allowlist. It rewrites the compose port binding and
// recreates the container, then reconciles the DOCKER-USER firewall:
//
//   - internal: no host port published; firewall rules (if any) removed.
//   - tailnet:  port bound to the machine's Tailscale IP; firewall removed.
//   - public:   port bound to 0.0.0.0; DOCKER-USER allowlist reconciled to the
//     supplied CIDRs.
//
// The container is recreated with `docker compose up -d`; compose only
// replaces it when the port mapping actually changes, so a no-op reconcile is
// cheap and the data volume is always preserved.
func (e *Executor) SetAccess(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	dbType := getStringPayload(op.Payload, "dbType")
	containerName := getStringPayload(op.Payload, "containerName")
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	port := getIntPayload(op.Payload, "port")
	accessMode := getStringPayload(op.Payload, "accessMode")
	bindHost := getStringPayload(op.Payload, "tailscaleIp")
	allowedIPs := getStringSlicePayload(op.Payload, "allowedIps")
	credentials := getMapPayload(op.Payload, "credentials")

	if databaseID == "" {
		return fmt.Errorf("db_set_access requires databaseId")
	}
	if dbType == "" {
		return fmt.Errorf("db_set_access requires dbType")
	}
	if containerName == "" {
		return fmt.Errorf("db_set_access requires containerName")
	}
	if port == 0 {
		return fmt.Errorf("db_set_access requires port")
	}
	switch accessMode {
	case "internal", "tailnet", "public":
	default:
		return fmt.Errorf("db_set_access: invalid accessMode %q", accessMode)
	}
	if accessMode == "tailnet" && bindHost == "" {
		return fmt.Errorf("db_set_access: tailnet mode requires a tailscale IP")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.AddLine(fmt.Sprintf("Setting %s access mode to %s", dbType, accessMode))
	streamer.Flush()

	compose, err := generateDatabaseCompose(dbType, port, containerName, dockerImage, credentials, accessMode, bindHost)
	if err != nil {
		return fail(fmt.Errorf("generate compose: %w", err))
	}
	dir := databaseDir(databaseID)
	if err := ensureDir(dir); err != nil {
		return fail(fmt.Errorf("create database dir: %w", err))
	}
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}

	// Recreate the container so the new port binding takes effect. compose
	// leaves it untouched if nothing changed; the named volume survives.
	streamer.AddLine("Applying network binding...")
	streamer.Flush()
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d", "--remove-orphans"); err != nil {
		return fail(fmt.Errorf("docker compose up: %w", err))
	}

	// Firewall: only public mode restricts source IPs. For internal/tailnet
	// the port isn't on a public interface, so any stale rules are removed.
	if accessMode == "public" {
		streamer.AddLine(fmt.Sprintf("Reconciling firewall allowlist (%d CIDR(s))...", len(allowedIPs)))
		streamer.Flush()
		if err := reconcileDatabaseFirewall(containerName, port, allowedIPs); err != nil {
			// Don't silently leave the port wide open: surface the failure
			// so the server can mark the op failed and warn the user.
			return fail(fmt.Errorf("firewall reconcile: %w", err))
		}
	} else {
		if err := clearDatabaseFirewall(containerName); err != nil {
			return fail(fmt.Errorf("firewall clear: %w", err))
		}
	}

	streamer.AddLine("Done")
	streamer.Flush()
	return nil
}

// getStringSlicePayload pulls a JSON array of strings from a payload. JSON
// decodes arrays as []interface{}, so we coerce element-wise and drop
// non-strings. Returns nil when the key is absent.
func getStringSlicePayload(payload map[string]interface{}, key string) []string {
	v, ok := payload[key]
	if !ok {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
