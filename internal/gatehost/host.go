// Package gatehost canonicalizes hostnames for the auth-gate sidecar
// and the proxy code that writes its config.
//
// Caddy matches site hostnames case-insensitively but forwards the
// original {host} casing (and sometimes a port or trailing FQDN dot).
// Config keys, lookups, and session cookies must all use the same
// normalized form or a gated domain can be requested as ExAmPlE.com
// and miss the map.
package gatehost

import (
	"net"
	"strconv"
	"strings"
)

// CanonicalHost normalizes a request or config hostname.
//
// DNS names are lowercased, a trailing FQDN dot is stripped, and a
// trailing :port is removed when the port is a valid TCP port
// (0–65535). The empty string is returned unchanged (after trim) so
// callers can reject it.
func CanonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if h, port, err := net.SplitHostPort(host); err == nil && validPort(port) && h != "" {
		host = h
	}

	host = strings.TrimRight(host, ".")
	return strings.ToLower(host)
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
}
