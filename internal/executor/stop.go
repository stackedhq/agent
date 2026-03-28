package executor

import (
	"fmt"
	"log"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Stop(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("stop requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	log.Printf("Stopping service %s", serviceID)

	if err := e.runCommand(op.ID, dir, "docker", "compose", "down"); err != nil {
		return fmt.Errorf("docker compose down: %w", err)
	}

	log.Printf("Service %s stopped", serviceID)
	return nil
}
