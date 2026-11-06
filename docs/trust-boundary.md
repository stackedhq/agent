# Docker trust boundary

The installer and README used to say the agent "runs as a dedicated
`stacked` user — not root." That is process-uid true and security-false.

The `stacked` user is a permanent member of the `docker` group. The
Docker CLI talks to a **rootful** `dockerd` over `/var/run/docker.sock`.
Anyone who can issue Docker Engine API calls can start a container that
bind-mounts the host filesystem (or the socket itself) and `chroot` /
`nsenter` to host root. systemd knobs on `stacked-agent.service`
(`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`)
constrain the agent process, not the daemon it commands.

**Stacked account or control-plane compromise is equivalent to VPS root
compromise.** A stolen agent token, a compromised `stacked.rest` (or
self-hosted) origin the agent is configured to poll, or RCE in the agent
binary can all ask `dockerd` to take the machine.

This is the intended current architecture, not a missed `chmod`. Treat
it as a hard deployment constraint until the helper below ships.

## Deployment rules (current)

Until a helper (or equivalent) is in production:

- Run the agent on a **dedicated VPS** (or dedicated VM) whose only job
  is Stacked-managed workloads.
- **Do not co-locate** unrelated sensitive workloads on the same kernel:
  other tenants' databases, CI runners, mail, identity providers, shared
  Docker Compose stacks you care about, or a workstation home directory.
- Anyone with dashboard access to the machine, or anyone who can mint
  or steal that machine's agent token, is a host administrator.
- Host firewall / fail2ban / unattended-upgrades still matter — they
  just are not a containment boundary for the agent.

The installer (`https://stacked.rest/install.sh`, not in this repo)
still creates `stacked`, adds it to `docker`, and writes the sandboxed
unit. The next installer change should print this warning at the end of
a successful install. That script is served by the control plane, so
the README is the copy that this repository can keep honest.

## Why not rootless Docker

Evaluated against the agent's actual operation surface, not a hello-world
`dockerd-rootless` smoke test.

| Requirement | What the agent does today | Rootless result |
|---|---|---|
| Ports 80/443 | Caddy publish `80:80` and `443:443` (`proxyCompose`) | Rootless cannot bind `<1024` unless the **host** sets `net.ipv4.ip_unprivileged_port_start=0` (or equivalent). That is a host-wide sysctl, not an isolation win, and it still fights some cloud images / shared kernels. |
| Compose | `docker compose up/stop/restart/down` for services, DBs, proxy, gate | CLI works if `DOCKER_HOST` points at the user socket **and** lingering user services exist. The installer would have to grow `loginctl enable-linger`, a user-unit dockerd, and a different socket path. |
| Build | nixpacks / `docker compose up --build` / `docker pull` | Possible via fuse-overlayfs or kernel overlay-in-userns (5.11+). Slower, more failure modes, extra packages. |
| Volumes | Bind mounts under `/opt/stacked/data/services/…` plus **arbitrary custom host paths**; named volumes `caddy_data` / `caddy_config` | Rootless remaps UIDs. Custom binds of paths `stacked` does not own fail. Existing rootful named volumes are not a lift-and-shift into `~/.local/share/docker`. Permission healing in `volumes.go` assumes a rootful daemon preserving host uids. |
| Networks | External bridge `stacked`; rolling `docker run --network=stacked --network-alias=…`; Caddy `extra_hosts: host.docker.internal:host-gateway`; `docker network connect` in probes | Rootless default slirp4netns/pasta is not the same parent-bridge model. `host-gateway` and hairpin-to-host (`127.0.0.1` → host services) are the exact features `proxy.go` depends on. |
| Exec / pipes | `docker exec` for DB rotate, backups, restore, query, extensions, Caddyfile validate, sslcheck; `docker exec \| docker exec` migrations | Works in rootless, but only for containers that daemon can see. Not a blocker. |
| Upgrades | `self_update` swaps `/opt/stacked/agent`; installer assumes system `docker.service` | Rootless is a different layout (`XDG_RUNTIME_DIR/docker.sock`, user storage). Migrating an existing machine means recreate-every-container plus volume rewrite. Cannot be a silent self-update. |
| Kernel | "Any systemd Linux VPS" (installer supports apt/dnf/yum/zypper/pacman/amazon) | Needs unprivileged user namespaces. OpenVZ, some LXC, older EL, locked-down images fail. That is an install-matrix regression we would own forever. |

**Decision: do not switch the default install to rootless Docker.** It
breaks the proxy ports, the `stacked` bridge + host-gateway contract,
custom bind mounts, and every existing machine's data directory. Making
it work would mean a second product (new-install-only, sysctl + linger
+ kernel checklist) without shrinking the real problem: a compromised
control plane still owns every Stacked workload on that box.

Optional later: a documented, unsupported "rootless lab" profile for
greenfield hosts that already lowered unprivileged ports. That is not
the containment strategy.

## Chosen architecture: narrow privileged helper

Keep a rootful `dockerd`. Take the `stacked` user **out** of the
`docker` group. Point the agent at a unix socket owned by a small
helper that speaks the Docker Engine API and allowlists calls.

The helper is the only process that may open `/var/run/docker.sock`.
systemd sandboxing on the agent then means something: a compromised
agent can only ask for operations the helper would have performed for
a legitimate control-plane payload.

### Shape

- Binary: `stacked-docker-helper` (same repo or a tiny sibling). Go,
  stdlib `net/http` + hijack for attach/exec/build streams.
- Unit: `stacked-docker-helper.service`, `User=root` (or a dedicated
  `stacked-dockerd` user in `docker`), `UMask=0117`.
- Socket: `/opt/stacked/run/docker.sock` (or systemd socket activation),
  `0660 stacked:stacked`.
- Agent: `Environment=DOCKER_HOST=unix:///opt/stacked/run/docker.sock`.
  The CLI already honors this; no need to wrap every `exec.Command("docker", …)`.
- Installer: stop `usermod -aG docker stacked`. `REQUIRES-REINSTALL`.

### Policy (v1)

Deny by default. Allow only what current ops need.

**Always reject** (any verb):

- Bind-mounts of the Docker socket, `/`, `/etc`, `/root`, `/home`,
  `/proc`, `/sys`, `/dev`, `/var/run`, `/var/lib/docker`, and any
  path that is not a realpath under `/opt/stacked/` **unless** it
  appears on an explicit host allowlist (issue #23).
- `Privileged`, `CapAdd`, `PidMode=host`, `NetworkMode=host`,
  `IpcMode=host`, `UsernsMode=host`, device mappings,
  `seccomp=unconfined`, `apparmor=unconfined`.
- Swarm, plugin, node, secret, config APIs.
- Image `load` of untrusted tarballs from outside `/opt/stacked/`
  (not used today; keep shut).

**Allow**, scoped to Stacked-labeled objects where an id exists:

| API family | Used by |
|---|---|
| `GET /_ping`, `/info`, `/version` | setup, heartbeat |
| Images inspect/pull/build/prune (build context under `/opt/stacked/`) | deploy, release, nixpacks |
| Containers create/start/stop/restart/kill/wait/delete/inspect/logs/stats/archive | deploy, rolling, cron, proxy, destroy |
| `POST /containers/{id}/exec` + start/hijack | rotate, backup, restore, query, extensions, sslcheck, Caddy validate |
| Networks: inspect; create only `stacked` or compose-project names; connect/disconnect | setup, probe, every compose up |
| Volumes: inspect/create/delete only for names we created (`caddy_*`, compose project) | proxy, destroy |
| `docker login` to `ghcr.io` via stdin | private image pull |

Compose is a client. If create/start/network/volume/image are allowed
with the HostConfig checks above, `docker compose` keeps working.

`docker exec` stays. It is required and it is not a host-root primitive
**if** create-time HostConfig cannot make a privileged or host-mounted
container. Combined with #23 (custom bind-mount guardrails) this is the
actual reduction: control-plane compromise can still wreck every Stacked
app and its `/opt/stacked` data; it should no longer be a one-liner to
`mount /:/host`.

### What the helper does **not** buy

- Isolation between services on the `stacked` bridge (that's #30).
- Integrity of the control plane. A malicious `deploy` can still run
  attacker images, exfil env files under `/opt/stacked`, and exec into
  app/DB containers the helper created.
- Safety of **user-approved** custom bind mounts. If the dashboard
  allowlists `/var/lib/foo`, the helper will honor it.

## Migration plan

1. **This change (docs only).** State the equivalence, dedicated-VPS
   rule, rootless no, helper yes. Lets #30 design against the helper
   rather than against a fantasy rootless daemon.
2. **#23 lands.** Machine-side bind-mount allowlist. Helper policy
   imports the same realpath rules so we do not encode them twice.
3. **Helper v0 behind `DOCKER_HOST`.** Feature-flag / drop-in unit on
   a dogfood machine. Agent code unchanged. Compare Engine API traces
   from a full op tour (setup, deploy recreate + rolling, DB + rotate +
   backup, cron, proxy reload, destroy, self-update).
4. **Installer cutover (`REQUIRES-REINSTALL`).** Install helper,
   remove `docker` group membership, set `DOCKER_HOST`. Existing
   machines keep working on the old group until they reinstall; do not
   silently drop group membership from self-update (agent cannot
   `usermod`).
5. **Only then** consider optional rootless as a lab profile. It is
   not on the critical path.

## Related issues

- #23 — custom host bind-mount guardrails (helper policy input)
- #30 — service isolation / network segmentation (after this direction)
- #32 — audit tracker (this issue is the P2 architecture fork)
