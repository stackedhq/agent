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
git tag v0.7.0
git push origin v0.7.0
```

### Versioning (SemVer, pre-1.0)

Pick the bump from what *the user sees*, not from whether the change is technically backward compatible. Almost everything we ship is backward compatible (recreate keeps working, old payload fields stay honored), so "no breaking change" alone is not the patch test.

- **Patch** (`v0.X.Y → v0.X.Y+1`) — bug fixes, log/UX tweaks, refactors, perf, dependency bumps. No new operation type, no new on-disk state, no new behavior the user has to learn or opt into.
- **Minor** (`v0.X.Y → v0.X+1.0`) — new user-visible capability even when fully backward compatible. Triggers: a new `operation_type`, a new deploy strategy, a new state file under `/opt/stacked/`, a new label contract on managed containers, a new public package, anything that pairs with a server-repo schema change. Past examples: `db_*` ops landing, log archival rollout, rolling deploy strategy.
- **Major** — N/A pre-1.0. If we ever ship a backward-incompatible payload change, coordinate the rollout with the server repo and still bump minor for now.

When in doubt, bump minor. It's cheaper to over-version than to bury a meaningful release in a patch and confuse the dashboard's update banner copy.

### REQUIRES-REINSTALL

Include `REQUIRES-REINSTALL` in the GitHub release notes body **only** when the release contains a change the self-update path cannot apply. The dashboard checks for this keyword and shows a manual reinstall banner instead of the auto-update button.

Self-update can do: swap the agent binary, restart itself via systemd, and — on the next op or startup hook — rewrite any file the `stacked` user owns under `/opt/stacked/` (compose files, Caddyfiles, state JSON) and recreate containers it manages.

Self-update cannot do: anything requiring root, anything that has to happen before the agent process exists, or anything outside `/opt/stacked/`.

**Use `REQUIRES-REINSTALL` for:**
- `install.sh` changes (new system deps, new install steps)
- New systemd unit fields or a renamed service
- New sudoers entries (the existing rule only permits `systemctl restart|stop|status stacked-agent`)
- File-layout migrations under `/opt/stacked/` that need root to perform
- Anything that must run before the agent process starts

**Do NOT use `REQUIRES-REINSTALL` for:**
- Pure Go logic changes
- Changes to embedded templates (Caddyfile, `docker-compose.yml` for the proxy, etc.) — these are rewritten by the agent and picked up by `docker compose up -d` on the next reconcile
- New `operation_type` handlers
- New state files the agent writes itself

If a release changes an embedded template and you want it to land on existing installs without waiting for an unrelated op to trigger reconcile, ensure the relevant `ensure*` function (e.g. `ensureProxy`) is invoked from agent startup, not only from op handlers. That makes the change land on the systemd restart that follows self-update. Reaching for `REQUIRES-REINSTALL` to paper over a missing startup hook is the wrong fix — it pushes manual work onto every user for something the agent can do itself.

**Historical note:** v0.8.0 was tagged `REQUIRES-REINSTALL` because the new `extra_hosts` entry in `proxyCompose()` only reconciles inside `ensureProxy()`, which isn't called at startup. Self-update swapped the binary but left the existing Caddy container on the old compose file until the next `proxy_config` op. The correct fix is a startup reconcile, not a reinstall.

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

## State Files

The agent persists a small amount of state on disk under `/opt/stacked/`:

- `active-slots.json` — owned by `internal/slots`. Maps `serviceID → "blue"|"green"|"legacy"` for services in rolling deploy mode. Read by the deploy executor (slot picking), proxy executor (Caddyfile upstream resolution), runtimelogs and heartbeat (filtering containers to the active slot during a rolling overlap). Recreate-mode services have no entry; `slots.Active(id)` returning `""` is the back-compat signal. File is flock-protected and atomically rewritten on every `slots.SetActive` / `slots.Clear`.
- `proxy/domains.json` — owned by `internal/executor/proxy.go`. Cached snapshot of the most recent `proxy_config` payload from the server, so `RegenerateCaddyfile()` (called after a rolling-deploy slot flip) can rewrite the Caddyfile without round-tripping to the server.
- `proxy/Caddyfile` and `proxy/Caddyfile.candidate` — the live Caddy config and the validate-before-swap candidate. Always validated inside the running Caddy container before being swapped into place; reload failure restores the previous bytes.

## Server Repo

The Stacked server (Next.js) lives at `../stacked`. Agent changes often require corresponding server changes (API schema, UI).
