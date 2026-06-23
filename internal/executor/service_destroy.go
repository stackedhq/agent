package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// managedVolumeDataDir is the parent of per-service managed-volume dirs.
// Keep in sync with packages/web/src/lib/volume-paths.ts MANAGED_VOLUME_ROOT.
const managedVolumeDataDir = "/opt/stacked/data/services"

// ServiceDestroy tears down a service for good: stops the container(s),
// removes the compose dir, and optionally deletes managed-volume host dirs.
// Mirrors DestroyDB semantics. Idempotent — missing dirs are a no-op.
func (e *Executor) ServiceDestroy(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("service_destroy requires serviceId in payload")
	}

	removeVolumes := true
	if rv, ok := op.Payload["removeVolumes"].(bool); ok {
		removeVolumes = rv
	}

	dir := serviceDir(serviceID)
	streamer := logs.NewStreamer(e.Client, op.ID)
	streamer.AddLine(fmt.Sprintf("Destroying service %s", serviceID))
	streamer.Flush()

	// 1. docker compose down -v (removes containers + docker-managed volumes)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
		log.Printf("Running docker compose down -v for service %s", serviceID)
		if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "down", "-v"); err != nil {
			streamer.AddLine("ERROR: " + err.Error())
			streamer.Flush()
			return fmt.Errorf("docker compose down: %w", err)
		}
	}

	// 2. Remove the service compose dir (/opt/stacked/services/<id>)
	if _, err := os.Stat(dir); err == nil {
		log.Printf("Removing service dir %s", dir)
		if err := os.RemoveAll(dir); err != nil {
			streamer.AddLine("ERROR: " + err.Error())
			streamer.Flush()
			return fmt.Errorf("remove service dir %s: %w", dir, err)
		}
		streamer.AddLine("Removed service directory")
	}

	// 3. Remove managed-volume data dir (/opt/stacked/data/services/<id>)
	if removeVolumes {
		volumeDir := filepath.Join(managedVolumeDataDir, serviceID)
		if _, err := os.Stat(volumeDir); err == nil {
			log.Printf("Removing managed volume dir %s", volumeDir)
			if err := os.RemoveAll(volumeDir); err != nil {
				streamer.AddLine("ERROR: " + err.Error())
				streamer.Flush()
				return fmt.Errorf("remove volume dir %s: %w", volumeDir, err)
			}
			streamer.AddLine("Removed volume data")
		}
	} else {
		streamer.AddLine("Volume data preserved on disk")
	}

	streamer.AddLine("Service destroyed")
	streamer.Flush()
	log.Printf("Service %s destroyed (removeVolumes=%v)", serviceID, removeVolumes)
	return nil
}
