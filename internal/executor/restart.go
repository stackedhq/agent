package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Restart resumes or restarts a service.
//
// Prefer `compose restart` when containers still exist (covers both an
// in-place restart of a running service and resume after `compose stop`).
// Fall back to `compose up -d` when containers are missing — the common
// cases are a pre-fix agent that used `compose down` for pause, or a
// manual `docker rm`. Mirrors StartDB's recovery path.
func (e *Executor) Restart(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("restart requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); os.IsNotExist(err) {
		return fmt.Errorf("service %s has no compose file at %s — redeploy required", serviceID, dir)
	}

	// Ensure the stacked network exists — it vanishes on Docker/machine restart.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	log.Printf("Restarting service %s", serviceID)
	if err := e.runCommand(op.ID, dir, "docker", "compose", "restart"); err != nil {
		log.Printf("compose restart failed for %s, falling back to up -d: %v", serviceID, err)
		// Tear down any half-present containers (releases port bindings) but
		// keep volumes so data survives.
		_ = e.runCommand(op.ID, dir, "docker", "compose", "down")
		if err := e.runCommand(op.ID, dir, "docker", "compose", "up", "-d"); err != nil {
			return fmt.Errorf("docker compose up: %w", err)
		}
	}

	log.Printf("Service %s restarted", serviceID)
	return nil
}
