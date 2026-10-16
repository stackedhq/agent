package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
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

// proxyCompose returns the proxy docker-compose.yml content: Caddy plus
// the auth gate sidecar. The gate is always part of the definition so
// every writer of this file (Setup, ensureProxy, proxy_config) agrees on
// it and it can never be orphaned; with no gated domains it just denies
// everything and costs a few MB of RAM.
//
// Gate isolation: the gate is only on the private `stacked-gate-internal`
// network (internal: no outbound route), shared with Caddy alone. User
// containers on the `stacked` network can't reach it or shadow its name
// there, and Caddy reaches it as `stacked-gate:9876`.
//
// The gate runs the agent's own static binary (bind-mounted read-only)
// inside the already-pulled Caddy image, so there is no separate gate
// image to publish or pull. It runs as the agent's uid:gid so it can read
// the 0600 config.json the agent writes and create its signing key. The
// agent-version label changes on every self-update, which makes
// `docker compose up -d` recreate the gate onto the new binary.
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
	return fmt.Sprintf(`services:
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
      - gate
  %[1]s:
    image: caddy:2-alpine
    container_name: %[1]s
    entrypoint: ["/stacked-agent", "gate"]
    user: "%[2]d:%[3]d"
    restart: unless-stopped
    read_only: true
    # tmpfs over the caddy image's VOLUME paths so no anonymous volumes
    # pile up each time the gate is recreated.
    tmpfs:
      - /data
      - /config
    cap_drop:
      - ALL
    security_opt:
      - "no-new-privileges:true"
    mem_limit: 64m
    labels:
      com.stacked.kind: gate
      com.stacked.agent-version: %[4]q
    volumes:
      - %[5]s:/stacked-agent:ro
      - %[6]s:/opt/stacked/gate
    networks:
      - gate

volumes:
  caddy_data:
  caddy_config:

networks:
  stacked:
    name: stacked
    external: true
  gate:
    name: %[7]s
    internal: true
`, gateServiceName, os.Getuid(), os.Getgid(), heartbeat.Version, agentBinaryPath, gateDir, gateNetworkName)
}
