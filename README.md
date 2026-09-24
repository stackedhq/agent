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

This installs Docker (if needed), the agent binary, and a systemd service. The agent process runs as a dedicated `stacked` user, not as uid 0. That is **not** a host isolation boundary: `stacked` is in the `docker` group, so it can drive the rootful Docker daemon. **A compromised Stacked account, agent token, or control plane is equivalent to VPS root.**

Run the agent on a **dedicated VPS**. Do not co-locate unrelated sensitive workloads on the same machine until a narrower Docker helper exists. Full threat model, rootless evaluation, and the helper migration plan: [docs/trust-boundary.md](docs/trust-boundary.md).

Get your token from the Stacked dashboard under **Machines → Add Machine**.

### Prerequisites

Docker is installed by `install.sh` when missing. **Tailscale is not.** Enabling Tailscale from the dashboard requires the official `tailscale` package already on the host (`tailscale` on `PATH`, `tailscaled` running). The agent never downloads or executes remote installers — it runs as the unprivileged `stacked` user and cannot elevate.

Install Tailscale with the [upstream package](https://tailscale.com/kb/1031/install-linux) for your distro (pinned apt/yum repo + signed packages), then enable it from the dashboard.

### Options

| Flag | Description | Default |
|---|---|---|
| `--token` | Agent token (required) | — |
| `--server` | Stacked server origin (`https://` only; no path/userinfo/query). `http://` is accepted only for loopback with `STACKED_ALLOW_INSECURE_HTTP=1` | `https://stacked.rest` |
| `--force` | Reinstall even if already present | `false` |

## Trust boundary

| Layer | What it actually contains |
|---|---|
| systemd `User=stacked` + `ProtectSystem=strict` | The agent process. Not `dockerd`. |
| `docker` group + `/var/run/docker.sock` | Nothing. This is root-equivalent. |
| Stacked dashboard / agent token | Operators of this VPS. Treat accordingly. |

Until [the helper in the trust-boundary doc](docs/trust-boundary.md) ships, assume any code path that can make the agent run a Docker API call can take the host.

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
| `self_update` | Download signed release, verify checksum + signature, replace, restart |

## Container isolation

Every service container now starts with a reduced breakout surface. Network segmentation is opt-in so a fleet upgrade does not strand services that still talk over the historical shared `stacked` network.

**Defaults (compose and rolling are equivalent):**

- `no-new-privileges:true`
- `cap_drop: [ALL]` (add capabilities back with `capAdd`)
- `pids_limit: 1024` (databases: `4096` plus the `CHOWN`/`SETUID`/`SETGID`/`FOWNER`/`SETPCAP`/`DAC_OVERRIDE`/`SYS_NICE` set official engine images need)
- Shared `stacked` network unless the payload sets `networkIsolation: true` or sends `linkedServiceIds` / `linkedDatabaseIds`
- Isolated services use `stacked-svc-<serviceId>`; Caddy is attached so HTTP still works
- Managed databases join `stacked-db-<databaseId>`, the shared `stacked-data` plane, and `stacked`
- Isolated services without `linkedDatabaseIds` also join `stacked-data` so existing `DATABASE_URL` hostnames keep working

**Payload escape hatches**

| Field | Effect |
|---|---|
| `isolationRelaxed: true` | Historical Docker defaults: no cap drop, no `no-new-privileges`, no PID cap; shared `stacked` network |
| `networkIsolation: false` | Shared `stacked` network only (keep the capability defaults) |
| `allowPrivilegeEscalation: true` | Omit `no-new-privileges` |
| `privileged: true` | `--privileged`; skips cap drop/add |
| `capAdd` / `capDrop` | Opt-in capabilities; `capDrop` replaces the default `[ALL]` when present |
| `pidsLimit` | Override the PID cap |
| `readOnlyRoot: true` | Read-only rootfs plus tmpfs on `/tmp`, `/run`, `/var/run`. Declared volume mounts stay writable unless `:ro` |
| `tmpfs` | Extra writable tmpfs paths |
| `linkedServiceIds` | Join those services' networks |
| `linkedDatabaseIds` | Join only those DB networks (presence of the key, even empty, skips `stacked-data`) |

## Database access

Managed databases default to **internal** (reachable only on the Docker `stacked` network — no host port). A missing or unknown access mode is treated the same way. Publishing on `0.0.0.0` requires an explicit `public` access mode. The agent does not manage a host firewall; if you use public mode, restrict the port with your cloud security group or an external firewall. Tailnet mode binds only to a validated Tailscale IP.

## Custom host bind mounts

Managed volumes under `/opt/stacked/data/services/` are always allowed.

Any other `hostPath` is rejected unless this machine explicitly allowlists the host root. Dashboard settings cannot widen that set.

```toml
# /opt/stacked/agent.toml
[volumes]
allowed_host_roots = ["/srv/stacked", "/mnt/data"]
```

Or set `STACKED_ALLOWED_VOLUME_ROOTS=/srv/stacked:/mnt/data` in the systemd unit. Then restart the agent.

Critical paths (`/`, `/etc`, `/proc`, `/sys`, `/dev`, `/run`, Docker/containerd sockets and state, `/opt/stacked` control files) stay blocked even if you allowlist `/`. Allowlisting `/` is treated as root-equivalent and is logged as a warning.

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

Tag and push — GitHub Actions builds binaries, publishes `SHA256SUMS` + an Ed25519 signature + Sigstore provenance, and creates a release. See [docs/releasing.md](docs/releasing.md).

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
