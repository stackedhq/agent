package executor

// Container images the agent runs itself. The auth gate runs from the
// agent binary inside the Caddy image (see gate_sidecar.go), so Caddy is
// the only image to pin.

// CaddyImage is the reverse proxy image, pinned by digest.
// Tag: caddy:2-alpine (Caddy v2.11.7), multi-arch index digest.
// Bump by running `docker buildx imagetools inspect caddy:2-alpine` and
// replacing the digest (and the version in this comment).
var CaddyImage = "caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f"
