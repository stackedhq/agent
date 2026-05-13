package executor

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) Setup(op client.Operation) error {
	log.Println("Running setup...")

	// Verify Docker is available
	if out, err := runCommandSilent("", "docker", "info"); err != nil {
		return fmt.Errorf("docker not available: %s: %w", out, err)
	}

	// Ensure the Caddyfile exists as a regular file. ensureRegularFile
	// also self-heals if a previous failed `compose up` left a directory
	// here (docker auto-mkdir on missing bind-mount source).
	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	if err := ensureRegularFile(caddyfilePath, "# Managed by Stacked\n"); err != nil {
		return fmt.Errorf("ensure Caddyfile: %w", err)
	}

	// Ensure Caddy proxy is running
	if err := ensureProxy(); err != nil {
		return err
	}

	log.Println("Setup complete")
	return nil
}

func proxyCompose() string {
	// `host.docker.internal:host-gateway` makes the host reachable from
	// inside the Caddy container under a stable hostname. Required for
	// port-bound domains where the user types host=127.0.0.1 expecting
	// "this VPS" — inside a bridged container, 127.0.0.1 resolves to
	// the container itself, not the host. The agent's Caddyfile
	// renderer transparently rewrites 127.0.0.1/localhost to this
	// hostname so the user-facing form stays simple.
	//
	// `host-gateway` is a synthetic value Docker resolves to the host's
	// gateway IP at container start time. Supported on Docker 20.10+
	// (Q4 2020) on Linux; older daemons will silently fail to add the
	// host entry but Caddy still starts. We accept that fallback.
	return `services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    extra_hosts:
      - "host.docker.internal:host-gateway"
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
