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
| `self_update` | Download a signed release from GitHub, verify it, replace, restart |

## Verifying releases

Every release publishes four files:

| File | What it is |
|---|---|
| `stacked-agent-linux-amd64`, `stacked-agent-linux-arm64` | The agent binaries |
| `SHA256SUMS` | `sha256sum` output for both binaries |
| `SHA256SUMS.sig` | Raw 64-byte ed25519 signature over the exact bytes of `SHA256SUMS` |

The signing key is held in a protected GitHub Environment and only used by a
release job that needs a manual approval. `install.sh` and the agent's
`self_update` both check the signature and the checksum before installing a
binary, and self-update refuses to downgrade. The update download location is
fixed to this repository's GitHub releases; the Stacked server only chooses the
version.

Release public key (also embedded in the agent and `install.sh`):

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVG1O9W3/Uj0lnx1NnGJMiogK//sPo/5OSdHwVQ4FCbM=
-----END PUBLIC KEY-----
```

### Check the signature and checksum

Requires OpenSSL 3.0 or newer (`openssl version`).

```bash
VERSION=0.9.0   # the release you want to check
ARCH=amd64      # or arm64
BASE=https://github.com/stackedhq/agent/releases/download/v$VERSION

curl -fsSLO "$BASE/stacked-agent-linux-$ARCH"
curl -fsSLO "$BASE/SHA256SUMS"
curl -fsSLO "$BASE/SHA256SUMS.sig"

cat > stacked-release.pub <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVG1O9W3/Uj0lnx1NnGJMiogK//sPo/5OSdHwVQ4FCbM=
-----END PUBLIC KEY-----
KEY

# 1. SHA256SUMS was signed by the Stacked release key
openssl pkeyutl -verify -pubin -inkey stacked-release.pub -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
# -> Signature Verified Successfully

# 2. The binary matches its signed checksum
sha256sum --check --ignore-missing SHA256SUMS
# -> stacked-agent-linux-amd64: OK
```

### Check build provenance

Binaries carry a GitHub artifact attestation (SLSA build provenance) that ties
them to the workflow run and commit that built them. With the
[GitHub CLI](https://cli.github.com):

```bash
gh attestation verify stacked-agent-linux-amd64 --repo stackedhq/agent
```

The auth gate sidecar runs this same verified binary (mounted read-only into the
Caddy container), so there is no separate gate image to trust. The Caddy image the agent runs is pinned by digest as well (see
`internal/executor/images.go`).

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

Tag and push. GitHub Actions builds the binaries, waits for approval on the `release` Environment to sign `SHA256SUMS`, then creates the release:

```bash
git tag v0.6.5
git push origin main --tags
```

If a release adds new system dependencies or changes `install.sh`, include `REQUIRES-REINSTALL` in the release notes. The dashboard will show users a manual reinstall command instead of the auto-update button.

## Building from source

Requires the Go version in `go.mod` (the `toolchain` line is fetched automatically).

```bash
# Build for current platform
make build-local

# Cross-compile for Linux
make build
```

## License

[BSL 1.1](LICENSE) — source available, not open source.
