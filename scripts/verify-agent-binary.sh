#!/bin/sh
# Verify a stacked-agent release asset: Ed25519 over SHA256SUMS, then SHA-256
# of the selected binary. Used by install.sh (server repo) and for manual checks.
#
# Usage:
#   scripts/verify-agent-binary.sh <version> <arch> <binary-path>
#   scripts/verify-agent-binary.sh 0.9.0 amd64 /tmp/stacked-agent-linux-amd64
set -eu

VERSION="${1:?version (e.g. 0.9.0)}"
ARCH="${2:?arch (amd64|arm64)}"
BIN="${3:?path to downloaded binary}"

VERSION="${VERSION#v}"
REPO="stackedhq/agent"
BASE="https://github.com/${REPO}/releases/download/v${VERSION}"
NAME="stacked-agent-linux-${ARCH}"
MAX_BYTES=67108864

# Keep in lockstep with internal/releaseverify/pubkey.go
PUB_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2Zwciqoqoeut12P+zfnTLzJQmWMtpqnLJmm7WPdHZx4=
-----END PUBLIC KEY-----'

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
printf '%s\n' "$PUB_PEM" > "$tmpdir/pub.pem"

# Refuse HTTP and follow only HTTPS (curl -L --proto-redir =https).
download() {
    dest="$1"
    url="$2"
    curl -fsSL --max-filesize "$MAX_BYTES" --proto '=https' --proto-redir '=https' \
        -o "$dest" "$url" || {
        echo "download failed: $url" >&2
        return 1
    }
}

download "$tmpdir/SHA256SUMS" "${BASE}/SHA256SUMS"
download "$tmpdir/SHA256SUMS.sig" "${BASE}/SHA256SUMS.sig"

if ! openssl pkeyutl -verify -pubin -inkey "$tmpdir/pub.pem" -rawin \
    -in "$tmpdir/SHA256SUMS" -sigfile "$tmpdir/SHA256SUMS.sig" >/dev/null; then
    echo "SHA256SUMS is not signed by the Stacked release key — refusing to install" >&2
    exit 1
fi

# Check the named binary; sha256sum -c also validates the hash format.
line=$(grep -E "[ *]${NAME}$" "$tmpdir/SHA256SUMS" || true)
if [ -z "$line" ]; then
    echo "SHA256SUMS has no entry for ${NAME}" >&2
    exit 1
fi
sum=$(printf '%s\n' "$line" | awk '{print $1}')
got=$(sha256sum "$BIN" | awk '{print $1}')
if [ "$sum" != "$got" ]; then
    echo "SHA-256 mismatch for ${NAME}: got ${got} want ${sum} — refusing to install" >&2
    exit 1
fi

echo "verified ${NAME} v${VERSION}"
