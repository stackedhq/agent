package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Setup(op client.Operation) error {
	log.Println("Running setup...")

	// Verify Docker is available
	if out, err := runCommandSilent("", "docker", "info"); err != nil {
		return fmt.Errorf("docker not available: %s: %w", out, err)
	}

	// Create the stacked Docker network if it doesn't exist
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	// Ensure proxy directory and compose file exist
	if err := ensureDir(proxyDir); err != nil {
		return fmt.Errorf("create proxy dir: %w", err)
	}

	composePath := filepath.Join(proxyDir, "docker-compose.yml")
	if _, err := os.Stat(composePath); os.IsNotExist(err) {
		if err := writeFile(composePath, proxyCompose()); err != nil {
			return fmt.Errorf("write proxy compose: %w", err)
		}
	}

	// Write empty Caddyfile if it doesn't exist
	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	if _, err := os.Stat(caddyfilePath); os.IsNotExist(err) {
		if err := writeFile(caddyfilePath, "# Managed by Stacked\n"); err != nil {
			return fmt.Errorf("write Caddyfile: %w", err)
		}
	}

	// Start Caddy
	log.Println("Starting Caddy proxy...")
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "up", "-d"); err != nil {
		return fmt.Errorf("start caddy: %s: %w", out, err)
	}

	log.Println("Setup complete")
	return nil
}

func proxyCompose() string {
	return `services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - stacked

volumes:
  caddy_data:
  caddy_config:

networks:
  stacked:
    name: stacked
    external: true
`
}
