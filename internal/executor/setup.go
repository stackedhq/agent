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

	// Write empty Caddyfile if it doesn't exist
	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	if _, err := os.Stat(caddyfilePath); os.IsNotExist(err) {
		if err := writeFile(caddyfilePath, "# Managed by Stacked\n"); err != nil {
			return fmt.Errorf("write Caddyfile: %w", err)
		}
	}

	// Ensure Caddy proxy is running
	if err := ensureProxy(); err != nil {
		return err
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
