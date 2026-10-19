# Releasing the agent

Tag `vX.Y.Z` and push. GitHub Actions:

1. **Build & Vet** — `go vet`, `go test`, compile both architectures. Read-only.
2. **Signed artifacts** — rebuild with the version ldflag, write `SHA256SUMS`, sign it with Ed25519, attach Sigstore provenance. Has `id-token` + `attestations` only. Signing key: repo secret `AGENT_RELEASE_SIGNING_KEY`.
3. **Release notes** — isolated job. `contents: read` plus `COPILOT_GITHUB_TOKEN`. Never sees binaries or the signing key.
4. **Publish release** — `contents: write` only. Attaches binaries + `SHA256SUMS` + `SHA256SUMS.sig`. No signing key, no note-generation token.

## Signing key (required before the next tag)

```bash
scripts/gen-release-key.sh
```

- Put the base64 private key in GitHub secret `AGENT_RELEASE_SIGNING_KEY`.
- Paste the PEM public key into `internal/releaseverify/pubkey.go` **and** `scripts/verify-agent-binary.sh` if you generated a new pair. This PR already embeds a public key; the matching private key is not in git.

Verify a downloaded binary:

```bash
scripts/verify-agent-binary.sh 0.9.0 amd64 ./stacked-agent-linux-amd64
```

Humans can also check provenance:

```bash
gh attestation verify ./stacked-agent-linux-amd64 --repo stackedhq/agent
```

## Self-update contract

Payload:

| Field | Required | Notes |
|---|---|---|
| `targetVersion` | yes | SemVer (`0.9.0` or `v0.9.0`) |
| `allowDowngrade` | no | `true` to install an older signed release |
| `downloadUrl` | ignored unless it is exactly the official `https://github.com/stackedhq/agent/releases/download/v<ver>/stacked-agent-linux-<arch>` URL |

The agent always pulls the binary, `SHA256SUMS`, and `SHA256SUMS.sig` from that origin. It rejects non-HTTPS, redirects off GitHub, oversized assets (>64MiB), invalid SemVer, and downgrades. Verification failure leaves `/opt/stacked/agent` untouched.

## install.sh (server repo)

`packages/web/public/install.sh` still lives in `stacked`. After this release publishes checksums + signatures, that script must verify before `mv` onto `/opt/stacked/agent`. Copy `scripts/verify-agent-binary.sh` from this repo (or inline it) and replace both download blocks with:

```sh
ASSET_BASE="https://github.com/${GITHUB_REPO}/releases/latest"
# resolve latest tag, then:
curl -fsSL --proto '=https' --proto-redir '=https' --max-filesize 67108864 \
  -o "${AGENT_BIN}.tmp" "${ASSET_BASE}/download/stacked-agent-linux-${ARCH}"
# download SHA256SUMS + SHA256SUMS.sig for the resolved tag
# openssl pkeyutl -verify ... && sha256sum -c
mv "${AGENT_BIN}.tmp" "$AGENT_BIN"
```

Resolve `latest` to a concrete tag first (`curl -fsSLI` / `Location`) so checksums and the binary come from the same version. Do not install if OpenSSL cannot verify the Ed25519 signature.
