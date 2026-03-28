package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Deploy(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	gitRepo := getStringPayload(op.Payload, "gitRepo")
	gitBranch := getStringPayload(op.Payload, "gitBranch")
	commitSha := getStringPayload(op.Payload, "commitSha")
	buildCommand := getStringPayload(op.Payload, "buildCommand")
	startCommand := getStringPayload(op.Payload, "startCommand")

	if serviceID == "" || gitRepo == "" {
		return fmt.Errorf("deploy requires serviceId and gitRepo in payload")
	}
	if gitBranch == "" {
		gitBranch = "main"
	}

	dir := serviceDir(serviceID)
	repoDir := filepath.Join(dir, "repo")

	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create service dir: %w", err)
	}

	// Clone or pull
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		log.Printf("Cloning %s into %s", gitRepo, repoDir)
		if err := e.runCommand(op.ID, dir, "git", "clone", "--branch", gitBranch, "--single-branch", gitRepo, "repo"); err != nil {
			return fmt.Errorf("git clone: %w", err)
		}
	} else {
		log.Printf("Pulling latest for %s", serviceID)
		if err := e.runCommand(op.ID, repoDir, "git", "fetch", "origin"); err != nil {
			return fmt.Errorf("git fetch: %w", err)
		}
		if err := e.runCommand(op.ID, repoDir, "git", "reset", "--hard", "origin/"+gitBranch); err != nil {
			return fmt.Errorf("git reset: %w", err)
		}
	}

	// Checkout specific commit if requested
	if commitSha != "" {
		if err := e.runCommand(op.ID, repoDir, "git", "checkout", commitSha); err != nil {
			return fmt.Errorf("git checkout %s: %w", commitSha, err)
		}
	}

	// Generate docker-compose.yml
	compose := generateCompose(serviceID, buildCommand, startCommand)
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return fmt.Errorf("write docker-compose.yml: %w", err)
	}

	// Build and start
	log.Printf("Running docker compose up for %s", serviceID)
	if err := e.runCommand(op.ID, dir, "docker", "compose", "up", "-d", "--build", "--remove-orphans"); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}

	log.Printf("Deploy complete for %s", serviceID)
	return nil
}

func generateCompose(serviceID, buildCommand, startCommand string) string {
	compose := fmt.Sprintf(`services:
  %s:
    build:
      context: ./repo
`, serviceID)

	if buildCommand != "" {
		compose += fmt.Sprintf("      args:\n        BUILD_COMMAND: %q\n", buildCommand)
	}

	if startCommand != "" {
		compose += fmt.Sprintf("    command: %s\n", startCommand)
	}

	compose += fmt.Sprintf(`    restart: unless-stopped
    env_file:
      - .env
    networks:
      - stacked

networks:
  stacked:
    name: stacked
    external: true
`)
	return compose
}
