package executor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Deploy(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	dockerImage := getStringPayload(op.Payload, "dockerImage")

	if serviceID == "" {
		return fmt.Errorf("deploy requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create service dir: %w", err)
	}

	// Request fresh credentials from the server (short-lived token, env vars)
	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		return fmt.Errorf("get credentials: %w", err)
	}

	// Authenticate with GHCR if a registry token was provided
	if creds.RegistryToken != "" {
		log.Printf("Logging in to ghcr.io for %s", serviceID)
		cmd := exec.Command("docker", "login", "ghcr.io", "-u", "x-access-token", "--password-stdin")
		cmd.Stdin = strings.NewReader(creds.RegistryToken)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("GHCR login failed (non-fatal): %s", string(out))
		}
	}

	// Write .env file from server-managed env vars
	if len(creds.EnvVars) > 0 {
		envContent := buildEnvFile(creds.EnvVars)
		envPath := filepath.Join(dir, ".env")
		if err := writeFile(envPath, envContent); err != nil {
			return fmt.Errorf("write .env: %w", err)
		}
	} else {
		// Ensure .env exists (docker compose requires it with env_file directive)
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); os.IsNotExist(err) {
			if err := writeFile(envPath, ""); err != nil {
				return fmt.Errorf("write .env: %w", err)
			}
		}
	}

	var imageName string

	if dockerImage != "" {
		// Docker image mode: pull the pre-built image
		imageName = dockerImage
		log.Printf("Pulling Docker image %s for %s", imageName, serviceID)
		if err := e.runCommand(op.ID, dir, "docker", "pull", imageName); err != nil {
			return fmt.Errorf("docker pull %s: %w", imageName, err)
		}
	} else {
		// VPS build mode: clone repo + build with Nixpacks
		imageName, err = e.buildFromSource(op, serviceID, dir, creds)
		if err != nil {
			return err
		}
	}

	// Generate docker-compose.yml using the image
	compose := generateCompose(serviceID, imageName)
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return fmt.Errorf("write docker-compose.yml: %w", err)
	}

	// Start container
	log.Printf("Starting container for %s", serviceID)
	if err := e.runCommand(op.ID, dir, "docker", "compose", "up", "-d", "--remove-orphans"); err != nil {
		return fmt.Errorf("docker compose up: %w", err)
	}

	log.Printf("Deploy complete for %s", serviceID)
	return nil
}

// buildFromSource clones the repo and builds an image with Nixpacks.
func (e *Executor) buildFromSource(op client.Operation, serviceID, dir string, creds *client.Credentials) (string, error) {
	gitBranch := getStringPayload(op.Payload, "gitBranch")
	commitSha := getStringPayload(op.Payload, "commitSha")
	buildCommand := getStringPayload(op.Payload, "buildCommand")
	startCommand := getStringPayload(op.Payload, "startCommand")

	if gitBranch == "" {
		gitBranch = "main"
	}

	repoDir := filepath.Join(dir, "repo")

	gitRepo := creds.GitCloneUrl
	if gitRepo == "" {
		gitRepo = getStringPayload(op.Payload, "gitRepo")
		if gitRepo == "" {
			return "", fmt.Errorf("no git clone URL available")
		}
	}

	// Clone or pull
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		log.Printf("Cloning into %s", repoDir)
		if err := e.runCommand(op.ID, dir, "git", "clone", "--branch", gitBranch, "--single-branch", gitRepo, "repo"); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	} else {
		log.Printf("Pulling latest for %s", serviceID)
		_, _ = runCommandSilent(repoDir, "git", "remote", "set-url", "origin", gitRepo)
		if err := e.runCommand(op.ID, repoDir, "git", "fetch", "origin"); err != nil {
			return "", fmt.Errorf("git fetch: %w", err)
		}
		if err := e.runCommand(op.ID, repoDir, "git", "reset", "--hard", "origin/"+gitBranch); err != nil {
			return "", fmt.Errorf("git reset: %w", err)
		}
	}

	// Checkout specific commit if requested
	if commitSha != "" {
		if err := e.runCommand(op.ID, repoDir, "git", "checkout", commitSha); err != nil {
			return "", fmt.Errorf("git checkout %s: %w", commitSha, err)
		}
	}

	// Build image with Nixpacks
	imageName := "stacked-" + serviceID
	log.Printf("Building image with Nixpacks for %s", serviceID)

	nixpacksArgs := []string{"build", repoDir, "--name", imageName}
	if buildCommand != "" {
		nixpacksArgs = append(nixpacksArgs, "--build-cmd", buildCommand)
	}
	if startCommand != "" {
		nixpacksArgs = append(nixpacksArgs, "--start-cmd", startCommand)
	}
	for k, v := range creds.EnvVars {
		nixpacksArgs = append(nixpacksArgs, "--env", k+"="+v)
	}

	if err := e.runCommand(op.ID, dir, "nixpacks", nixpacksArgs...); err != nil {
		return "", fmt.Errorf("nixpacks build: %w", err)
	}

	return imageName, nil
}

// buildEnvFile creates a .env file content from a key-value map.
// Keys are sorted for deterministic output.
func buildEnvFile(vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		// Quote values that contain spaces, newlines, or special chars
		v := vars[k]
		if strings.ContainsAny(v, " \t\n\"'$`\\#") {
			v = "\"" + strings.ReplaceAll(strings.ReplaceAll(v, "\\", "\\\\"), "\"", "\\\"") + "\""
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

func generateCompose(serviceID, imageName string) string {
	return fmt.Sprintf(`services:
  %s:
    image: %s
    restart: unless-stopped
    env_file:
      - .env
    networks:
      - stacked

networks:
  stacked:
    name: stacked
    external: true
`, serviceID, imageName)
}
