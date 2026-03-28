package executor

import (
	"fmt"
	"log"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Restart(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("restart requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	log.Printf("Restarting service %s", serviceID)

	if err := e.runCommand(op.ID, dir, "docker", "compose", "restart"); err != nil {
		return fmt.Errorf("docker compose restart: %w", err)
	}

	log.Printf("Service %s restarted", serviceID)
	return nil
}
