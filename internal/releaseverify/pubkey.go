package releaseverify

// PublicKeyPEM is the Ed25519 public key that signs SHA256SUMS for
// every GitHub release. The matching private key lives only in the
// AGENT_RELEASE_SIGNING_KEY repository secret (base64-encoded PEM).
//
// Rotate by running scripts/gen-release-key.sh, updating this constant,
// and replacing the secret. Old agents will reject releases signed with
// a new key — ship the pubkey change in an agent release first, or
// treat the rotation as REQUIRES-REINSTALL.
const PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2Zwciqoqoeut12P+zfnTLzJQmWMtpqnLJmm7WPdHZx4=
-----END PUBLIC KEY-----`

// publicKeyPEM is the key used by VerifyChecksumSignature. Tests swap
// this for an ephemeral keypair so the production private key never
// enters the tree.
var publicKeyPEM = PublicKeyPEM

// UsePublicKeyPEM temporarily replaces the release public key. Tests only.
func UsePublicKeyPEM(pem string) func() {
	prev := publicKeyPEM
	publicKeyPEM = pem
	return func() { publicKeyPEM = prev }
}
