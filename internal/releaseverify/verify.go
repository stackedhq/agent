package releaseverify

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// MaxAssetBytes is the largest release asset we will accept.
	// Agent binaries are ~10–15MiB; 64MiB leaves room without allowing
	// an unbounded write to disk.
	MaxAssetBytes = 64 << 20

	ChecksumsName = "SHA256SUMS"
	SignatureName = "SHA256SUMS.sig"

	ReleaseOwner = "stackedhq"
	ReleaseRepo  = "agent"
)

// OfficialAssetURL is the only origin we download from.
func OfficialAssetURL(version, name string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	return fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s/%s", ReleaseOwner, ReleaseRepo, version, name)
}

func OfficialBinaryName(arch string) string {
	return fmt.Sprintf("stacked-agent-linux-%s", arch)
}

func ParsePublicKey(pemBytes string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, fmt.Errorf("release public key: no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release public key: not Ed25519")
	}
	if len(ed) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release public key: invalid size")
	}
	return ed, nil
}

// VerifyChecksumSignature checks that sig is an Ed25519 signature of
// the raw SHA256SUMS bytes under the embedded release public key.
func VerifyChecksumSignature(checksums, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature: want %d bytes, got %d — download SHA256SUMS.sig from the official GitHub release", ed25519.SignatureSize, len(sig))
	}
	pub, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, checksums, sig) {
		return fmt.Errorf("release signature: SHA256SUMS is not signed by the Stacked release key — refusing to install")
	}
	return nil
}

// ChecksumForName returns the hex SHA-256 for name from a sha256sum file.
func ChecksumForName(checksums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(checksums))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "hash  name" or "hash *name"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", fmt.Errorf("malformed SHA256SUMS line %q", line)
		}
		sum, file := fields[0], fields[1]
		file = strings.TrimPrefix(file, "*")
		if file != name {
			continue
		}
		if len(sum) != sha256.Size*2 {
			return "", fmt.Errorf("invalid SHA-256 for %s", name)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return "", fmt.Errorf("invalid SHA-256 for %s: %w", name, err)
		}
		return strings.ToLower(sum), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("SHA256SUMS has no entry for %s", name)
}

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func VerifyFileHash(path, wantHex string) error {
	got, err := HashFile(path)
	if err != nil {
		return fmt.Errorf("hash %s: %w", path, err)
	}
	if !strings.EqualFold(got, wantHex) {
		return fmt.Errorf("SHA-256 mismatch for %s: got %s want %s — refusing to replace the agent binary", path, got, wantHex)
	}
	return nil
}

// DecideUpdate validates target SemVer and the upgrade direction.
// current may be "dev" (local builds); that skips the downgrade check.
func DecideUpdate(current, target string, allowDowngrade bool) (Version, error) {
	tv, err := ParseVersion(target)
	if err != nil {
		return Version{}, fmt.Errorf("self_update targetVersion: %w", err)
	}
	cv, err := ParseVersion(current)
	if err != nil {
		// Unreleased / ldflag-less builds can update to any signed release.
		if strings.TrimPrefix(strings.TrimSpace(current), "v") == "dev" || strings.TrimSpace(current) == "" {
			return tv, nil
		}
		return Version{}, fmt.Errorf("current agent version %q is not SemVer: %w", current, err)
	}
	cmp := Compare(tv, cv)
	if cmp == 0 {
		return Version{}, fmt.Errorf("already running v%s", cv)
	}
	if cmp < 0 && !allowDowngrade {
		return Version{}, fmt.Errorf("refusing downgrade from v%s to v%s (pass allowDowngrade=true to authorize)", cv, tv)
	}
	return tv, nil
}
