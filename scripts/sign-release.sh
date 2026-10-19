#!/bin/sh
# Sign SHA256SUMS with AGENT_RELEASE_SIGNING_KEY (base64-encoded Ed25519 PEM).
# Usage: scripts/sign-release.sh SHA256SUMS SHA256SUMS.sig
set -eu

sums="${1:?SHA256SUMS path}"
sig="${2:?signature output path}"

if [ -z "${AGENT_RELEASE_SIGNING_KEY:-}" ]; then
    echo "AGENT_RELEASE_SIGNING_KEY is not set" >&2
    echo "Generate a key with scripts/gen-release-key.sh and add it as a repo secret." >&2
    exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
printf '%s' "$AGENT_RELEASE_SIGNING_KEY" | base64 -d > "$tmpdir/priv.pem"
chmod 600 "$tmpdir/priv.pem"

openssl pkeyutl -sign -inkey "$tmpdir/priv.pem" -rawin -in "$sums" -out "$sig"
# Fail closed if the signature is the wrong size.
sz=$(wc -c < "$sig")
if [ "$sz" -ne 64 ]; then
    echo "expected 64-byte Ed25519 signature, got $sz" >&2
    exit 1
fi
