package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Stop pauses a service. Uses `compose stop` (NOT `down`) so container
// metadata stays intact for the next Restart/Resume. Volumes persist either
// way; destruction goes through `service_destroy`.
//
// Mirrors StopDB. A missing compose file is treated as success — nothing is
// running and a later Restart will surface the real error if the dir is gone.
func (e *Executor) Stop(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("stop requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); os.IsNotExist(err) {
		log.Printf("Stop: no compose file for %s, treating as no-op", serviceID)
		return nil
	}

	log.Printf("Stopping service %s", serviceID)
	if err := e.runCommand(op.ID, dir, "docker", "compose", "stop"); err != nil {
		return fmt.Errorf("docker compose stop: %w", err)
	}

	log.Printf("Service %s stopped", serviceID)
	return nil
}
