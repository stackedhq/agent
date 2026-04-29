# Stacked Agent

## Overview

Go binary that runs on VPS machines, polls the Stacked server for operations (deploy, stop, restart, etc.), and executes them. Communicates outbound only — no inbound ports needed.

## Project Structure

```
cmd/agent/main.go          # Entry point, starts heartbeat + poller goroutines
internal/
├── client/client.go       # HTTP client for Stacked API (heartbeat, poll, logs, credentials)
├── config/config.go       # TOML config loader (/opt/stacked/agent.toml)
├── executor/
│   ├── executor.go        # Operation dispatcher + runCommand helpers
│   ├── deploy.go          # Deploy: git clone → nixpacks build → docker compose up
│   ├── selfupdate.go      # Self-update: download binary → replace → os.Exit(0)
│   ├── stop.go            # Stop: docker compose down
│   ├── restart.go         # Restart: docker compose restart
│   ├── setup.go           # Setup: verify docker, create network, start caddy
│   └── proxy.go           # Proxy config: regenerate Caddyfile, reload caddy
├── heartbeat/heartbeat.go # Version const, system metrics, 10s heartbeat loop
├── logs/streamer.go       # Batches command output → POST /agent/ops/:id/logs
└── poller/poller.go       # 5s poll loop, claims + executes operations sequentially
```

## Build & Release

```bash
# Local build
make build-local

# Cross-compile (linux/amd64 + linux/arm64)
make build

# Version is injected via ldflags at build time:
# -X github.com/stackedapp/stacked/agent/internal/heartbeat.Version=X.Y.Z
```

**Releasing:** Tag with `vX.Y.Z` and push — GitHub Actions builds binaries and creates a release.

```bash
git tag v0.6.2
git push origin main v0.6.2
```

Use **patch** version bumps (v0.6.x) unless there's a breaking change.

If the release requires changes to `install.sh` (new system deps, config changes, etc.), include `REQUIRES-REINSTALL` in the GitHub release notes body. The dashboard checks for this keyword and shows a manual reinstall banner instead of the auto-update button.

## Development Guidelines

- Use `pnpm` / `bun` only in the server repo — this is pure Go
- Standard library over external dependencies
- No external frameworks — just `net/http`, `os/exec`, `encoding/json`
- Agent runs as `stacked` user (not root) with write access to `/opt/stacked/`
- Systemd manages the process: `Restart=always`, `RestartSec=5`

## Key Patterns

- **Log streaming**: Commands run via `runCommand` or `runCommandWithStreamer`, output goes through `logs.Streamer` which batches lines and POSTs to the server every 1s or 50 lines
- **Progress reporting**: `streamer.SetProgress(N)` + `streamer.AddLine("==> Phase...")` at deploy phase boundaries
- **Self-update**: Downloads new binary → replaces in-place → `os.Exit(0)` → systemd restarts with new binary
- **All operations are sequential**: Poller claims pending ops and executes them one at a time

## Server Repo

The Stacked server (Next.js) lives at `../stacked`. Agent changes often require corresponding server changes (API schema, UI).
