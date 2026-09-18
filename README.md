# Stacked Agent

The Stacked agent runs on your VPS and manages deployments, containers, and reverse proxy configuration. It communicates with the [Stacked](https://stacked.rest) platform via outbound HTTPS — no inbound ports required.

## How it works

The agent is a single static binary that runs as a systemd service. It:

- **Polls** the Stacked API every 5s for pending operations (deploy, stop, restart, etc.)
- **Sends heartbeats** every 10s with CPU, memory, and disk metrics
- **Manages Docker Compose** services per deployment
- **Manages Caddy** as a reverse proxy for automatic HTTPS
- **Streams logs** back to the Stacked dashboard in real-time

All connections are initiated outbound from the agent. Works through any firewall or NAT.

## Installation

```bash
curl -fsSL https://stacked.rest/install.sh | sh -s -- --token stk_<your-token>
```

This installs Docker (if needed), the agent binary, and a systemd service. The agent runs as a dedicated `stacked` user — not root.

Get your token from the Stacked dashboard under **Machines → Add Machine**.

### Prerequisites

Docker is installed by `install.sh` when missing. **Tailscale is not.** Enabling Tailscale from the dashboard requires the official `tailscale` package already on the host (`tailscale` on `PATH`, `tailscaled` running). The agent never downloads or executes remote installers — it runs as the unprivileged `stacked` user and cannot elevate.

Install Tailscale with the [upstream package](https://tailscale.com/kb/1031/install-linux) for your distro (pinned apt/yum repo + signed packages), then enable it from the dashboard.

### Options

| Flag | Description | Default |
|---|---|---|
| `--token` | Agent token (required) | — |
| `--server` | Stacked server URL | `https://stacked.rest` |
| `--force` | Reinstall even if already present | `false` |

## What it does on your server

```
/opt/stacked/
├── agent              # Binary
├── agent.toml         # Config (token + server URL)
├── proxy/
│   ├── docker-compose.yml   # Caddy reverse proxy
│   └── Caddyfile            # Auto-generated domain routing
└── services/
    └── <service-id>/
        ├── docker-compose.yml
        ├── .env
        └── repo/            # Cloned git repo
```

## Operations

| Type | What it does |
|---|---|
| `deploy` | Git clone/pull → `docker compose up -d --build` |
| `stop` | `docker compose stop` (pause; keeps containers/volumes) |
| `restart` | `docker compose restart`, falls back to `up -d` if containers are missing |
| `setup` | Verify Docker, create network, start Caddy |
| `proxy_config` | Regenerate Caddyfile, reload Caddy |
| `self_update` | Download new binary, replace, restart |

## Managing the service

```bash
# View logs
journalctl -u stacked-agent -f

# Restart
sudo systemctl restart stacked-agent

# Stop
sudo systemctl stop stacked-agent

# Status
systemctl status stacked-agent
```

## Releasing

Tag and push — GitHub Actions builds binaries and creates a release:

```bash
git tag v0.6.5
git push origin main --tags
```

If a release adds new system dependencies or changes `install.sh`, include `REQUIRES-REINSTALL` in the release notes. The dashboard will show users a manual reinstall command instead of the auto-update button.

## Building from source

Requires Go 1.23+.

```bash
# Build for current platform
make build-local

# Cross-compile for Linux
make build
```

## License

[BSL 1.1](LICENSE) — source available, not open source.
