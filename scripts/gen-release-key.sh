#!/bin/sh
# Generate an Ed25519 keypair for signing SHA256SUMS on agent releases.
#
# 1. Store the base64 private key as repo secret AGENT_RELEASE_SIGNING_KEY
# 2. Paste the PEM public key into internal/releaseverify/pubkey.go
set -eu

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

openssl genpkey -algorithm ED25519 -out "$tmpdir/priv.pem" >/dev/null 2>&1
openssl pkey -in "$tmpdir/priv.pem" -pubout -out "$tmpdir/pub.pem"

echo "=== public key (internal/releaseverify/pubkey.go) ==="
cat "$tmpdir/pub.pem"
echo
echo "=== AGENT_RELEASE_SIGNING_KEY (base64 PEM, GitHub secret) ==="
base64 -w0 "$tmpdir/priv.pem"
echo
