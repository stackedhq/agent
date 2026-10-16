package executor

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// releaseKeyPEMs are the ed25519 public keys (PEM, SPKI) trusted to sign
// agent releases. Every release publishes SHA256SUMS plus SHA256SUMS.sig,
// a raw 64-byte ed25519 signature over the exact SHA256SUMS bytes made in
// CI from the `release` GitHub Environment. Self-update accepts a release
// if ANY key in this list verifies the signature.
//
// Rotation: add the next key to the second slot and ship a release signed
// with the current key. Once that release is widely deployed, start
// signing with the next key and drop the old one in a later release.
// Agents never need a reinstall to follow a rotation.
//
// The same public key is embedded in install.sh and published in README.md.
var releaseKeyPEMs = []string{
	// Current key.
	`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVG1O9W3/Uj0lnx1NnGJMiogK//sPo/5OSdHwVQ4FCbM=
-----END PUBLIC KEY-----`,
	// Next key (rotation slot). Intentionally empty until a rotation is planned.
}

// trustedReleaseKeys is parsed once at init. A malformed embedded key is a
// build bug, so it panics (and TestEmbeddedReleaseKeysParse catches it).
var trustedReleaseKeys = mustParseReleaseKeys(releaseKeyPEMs)

func mustParseReleaseKeys(pems []string) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(pems))
	for i, p := range pems {
		k, err := parseEd25519PublicKeyPEM(p)
		if err != nil {
			panic(fmt.Sprintf("release key %d: %v", i, err))
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		panic("no trusted release keys embedded")
	}
	return keys
}

func parseEd25519PublicKeyPEM(s string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("not a PEM PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI: %w", err)
	}
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519", pub)
	}
	return k, nil
}

// verifyReleaseSignature reports whether sig is a valid ed25519 signature
// over msg by any of keys.
func verifyReleaseSignature(keys []ed25519.PublicKey, msg, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
