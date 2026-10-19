package releaseverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func marshalPubPEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func useTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prev := publicKeyPEM
	publicKeyPEM = marshalPubPEM(t, pub)
	t.Cleanup(func() { publicKeyPEM = prev })
	return priv
}

func TestVerifyChecksumSignature(t *testing.T) {
	priv := useTestKey(t)
	sums := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  stacked-agent-linux-amd64\n")
	sig := ed25519.Sign(priv, sums)
	if err := VerifyChecksumSignature(sums, sig); err != nil {
		t.Fatal(err)
	}

	if err := VerifyChecksumSignature(sums, sig[:63]); err == nil {
		t.Fatal("short sig should fail")
	}
	sig[0] ^= 0xff
	if err := VerifyChecksumSignature(sums, sig); err == nil {
		t.Fatal("tampered sig should fail")
	}
}

func TestVerifyFileHashMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stacked-agent-linux-amd64")
	if err := os.WriteFile(path, []byte("binary-v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte("binary-v2"))
	err := VerifyFileHash(path, hex.EncodeToString(want[:]))
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if got := err.Error(); !strings.Contains(got, "SHA-256 mismatch") {
		t.Fatalf("want mismatch error, got %s", got)
	}
}

func TestChecksumForName(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	hexSum := hex.EncodeToString(sum[:])
	body := hexSum + "  stacked-agent-linux-arm64\n"
	got, err := ChecksumForName([]byte(body), "stacked-agent-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got != hexSum {
		t.Fatalf("got %s", got)
	}
	if _, err := ChecksumForName([]byte(body), "stacked-agent-linux-amd64"); err == nil {
		t.Fatal("missing name should fail")
	}
}

func TestDecideUpdate(t *testing.T) {
	_, err := DecideUpdate("0.8.0", "0.7.9", false)
	if err == nil || !strings.Contains(err.Error(), "refusing downgrade") {
		t.Fatalf("downgrade: %v", err)
	}
	if _, err := DecideUpdate("0.8.0", "0.7.9", true); err != nil {
		t.Fatalf("authorized downgrade: %v", err)
	}
	if _, err := DecideUpdate("0.8.0", "0.8.0", false); err == nil {
		t.Fatal("same version should fail")
	}
	if _, err := DecideUpdate("0.8.0", "not-semver", false); err == nil {
		t.Fatal("invalid target should fail")
	}
	v, err := DecideUpdate("dev", "0.9.0", false)
	if err != nil || v.String() != "0.9.0" {
		t.Fatalf("dev -> 0.9.0: %v %+v", err, v)
	}
	if _, err := DecideUpdate("0.8.0", "0.8.1", false); err != nil {
		t.Fatal(err)
	}
}

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("v1.2.3-rc.1")
	if err != nil {
		t.Fatal(err)
	}
	if v.Major != 1 || v.Minor != 2 || v.Patch != 3 || v.Pre != "rc.1" {
		t.Fatalf("%+v", v)
	}
	for _, bad := range []string{"", "dev", "1.2", "01.2.3", "1.2.3.4", "1.2.3-"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	if Compare(mustParse(t, "1.0.0-alpha"), mustParse(t, "1.0.0")) >= 0 {
		t.Fatal("prerelease should be less than release")
	}
}

func mustParse(t *testing.T, s string) Version {
	t.Helper()
	v, err := ParseVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
