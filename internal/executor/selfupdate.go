package executor

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
)

const (
	// maxAgentBinaryBytes caps the downloaded binary. Current builds are
	// ~15 MB; this is an abuse cap, not a size budget.
	maxAgentBinaryBytes = 200 << 20
	maxSumsBytes        = 64 << 10
	sumsFile            = "SHA256SUMS"
	sumsSigFile         = "SHA256SUMS.sig"
)

// Package vars (not consts) so tests can point self-update at an httptest
// server, a temp binary path and a test key. Production values never
// change at runtime: there is deliberately no payload field that can
// override the download location.
var (
	releaseBaseURL      = "https://github.com/stackedhq/agent/releases/download"
	agentBinaryPath     = "/opt/stacked/agent"
	releaseKeys         = trustedReleaseKeys
	releaseHTTPClient   = newReleaseHTTPClient()
	currentAgentVersion = func() string { return heartbeat.Version }
)

// semverRe accepts MAJOR.MINOR.PATCH with an optional prerelease. Build
// metadata is rejected: it isn't part of our tags and would let two
// distinct strings compare equal.
var semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

// SelfUpdate downloads a signed agent release from GitHub, verifies it,
// swaps the binary in place and exits so systemd restarts the new one.
//
// Verification chain: SHA256SUMS.sig must be a valid ed25519 signature
// over SHA256SUMS by one of the embedded release keys; the binary's
// sha256 must match its SHA256SUMS entry. Nothing is written over the
// running binary unless every check passes.
func (e *Executor) SelfUpdate(op client.Operation) error {
	targetVersion := strings.TrimPrefix(strings.TrimSpace(getStringPayload(op.Payload, "targetVersion")), "v")
	if targetVersion == "" {
		return fmt.Errorf("self_update requires targetVersion in payload")
	}

	if err := checkUpgrade(targetVersion, currentAgentVersion()); err != nil {
		return err
	}

	log.Printf("Self-updating agent to v%s", targetVersion)

	if err := installVerifiedRelease(targetVersion, runtime.GOARCH, agentBinaryPath); err != nil {
		return err
	}

	log.Printf("Agent binary replaced, exiting so systemd restarts with new binary...")

	// Report success before exiting — systemd Restart=always will start the new binary
	_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "success"})

	// Exit cleanly — systemd will restart us with the new binary
	os.Exit(0)

	// Won't reach here
	return nil
}

// checkUpgrade refuses anything that isn't a strictly newer release.
// `dev` builds (local, unversioned) may update to any valid version.
func checkUpgrade(target, current string) error {
	t, ok := parseSemver(target)
	if !ok {
		return fmt.Errorf("self_update: invalid targetVersion %q (want X.Y.Z)", target)
	}
	if current == "dev" {
		return nil
	}
	c, ok := parseSemver(strings.TrimPrefix(current, "v"))
	if !ok {
		return fmt.Errorf("self_update: running agent version %q is not a release version; refusing to update automatically, reinstall instead", current)
	}
	switch cmp := compareSemver(t, c); {
	case cmp == 0:
		return fmt.Errorf("self_update: agent is already running v%s", current)
	case cmp < 0:
		return fmt.Errorf("self_update: refusing to downgrade from v%s to v%s", current, target)
	}
	return nil
}

// installVerifiedRelease fetches and verifies release v<version> for arch
// and atomically replaces dest with it.
func installVerifiedRelease(version, arch, dest string) error {
	if _, ok := parseSemver(version); !ok {
		// Also guards URL construction below.
		return fmt.Errorf("self_update: invalid version %q", version)
	}
	base := releaseBaseURL + "/v" + version + "/"
	assetName := "stacked-agent-linux-" + arch

	sums, err := fetchSmall(base+sumsFile, maxSumsBytes)
	if err != nil {
		return fmt.Errorf("self_update: download %s for v%s: %w", sumsFile, version, err)
	}
	sig, err := fetchSmall(base+sumsSigFile, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("self_update: download %s for v%s: %w", sumsSigFile, version, err)
	}
	if !verifyReleaseSignature(releaseKeys, sums, sig) {
		return fmt.Errorf("self_update: signature check failed for v%s: %s is not signed by a trusted Stacked release key; binary not installed", version, sumsFile)
	}

	want, err := lookupChecksum(sums, assetName)
	if err != nil {
		return fmt.Errorf("self_update: v%s: %w", version, err)
	}

	tmpPath, err := downloadToTemp(base+assetName, filepath.Dir(dest), want)
	if err != nil {
		return fmt.Errorf("self_update: v%s %s: %w", version, assetName, err)
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("self_update: chmod: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("self_update: replace binary: %w", err)
	}
	return nil
}

// lookupChecksum finds name in a `sha256sum`-format file
// (`<hex>  <name>` or `<hex> *<name>` per line). Exactly one entry is
// required.
func lookupChecksum(sums []byte, name string) ([]byte, error) {
	var found []byte
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		hexSum, file, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("malformed %s line %q", sumsFile, line)
		}
		file = strings.TrimPrefix(strings.TrimPrefix(file, " "), "*")
		if file != name {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s lists %s more than once", sumsFile, name)
		}
		sum, err := hex.DecodeString(hexSum)
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("%s has an invalid checksum for %s", sumsFile, name)
		}
		found = sum
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", sumsFile, err)
	}
	if found == nil {
		return nil, fmt.Errorf("%s has no entry for %s (unsupported architecture?)", sumsFile, name)
	}
	return found, nil
}

// fetchSmall GETs url and returns the body, failing if it exceeds max bytes.
func fetchSmall(url string, max int64) ([]byte, error) {
	resp, err := releaseHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", url, max)
	}
	return body, nil
}

// downloadToTemp streams url into a new 0700 temp file in dir while
// hashing it, and returns the temp path only if the sha256 matches want.
// The temp file sits next to the final binary so the rename is atomic
// (same filesystem).
func downloadToTemp(url, dir string, want []byte) (string, error) {
	resp, err := releaseHTTPClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d from %s", resp.StatusCode, url)
	}
	if resp.ContentLength > maxAgentBinaryBytes {
		return "", fmt.Errorf("download: binary is %d bytes, over the %d byte limit", resp.ContentLength, maxAgentBinaryBytes)
	}

	f, err := os.CreateTemp(dir, ".stacked-agent-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(tmpPath)
		return "", err
	}
	if err := f.Chmod(0700); err != nil {
		return fail(fmt.Errorf("chmod temp file: %w", err))
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAgentBinaryBytes+1))
	if err != nil {
		return fail(fmt.Errorf("download: %w", err))
	}
	if n > maxAgentBinaryBytes {
		return fail(fmt.Errorf("download: binary exceeds the %d byte limit", maxAgentBinaryBytes))
	}
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		return fail(fmt.Errorf("checksum mismatch: got %x, %s says %x; binary not installed", got, sumsFile, want))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("sync temp file: %w", err))
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return tmpPath, nil
}

// newReleaseHTTPClient returns the client used for release downloads. It
// is separate from the Stacked API client: it never carries the agent
// token, and it follows GitHub's redirect to its asset CDN, but only over
// https.
func newReleaseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-https redirect to %s", req.URL.Redacted())
			}
			req.Header.Del("Authorization")
			return nil
		},
	}
}

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	var v semver
	var err error
	if v.major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return semver{}, false
	}
	if v.minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return semver{}, false
	}
	if v.patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return semver{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

// compareSemver follows SemVer 2.0 precedence: a prerelease sorts before
// its release, numeric identifiers compare numerically and sort before
// alphanumeric ones.
func compareSemver(a, b semver) int {
	for _, d := range [][2]uint64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xn, xErr := strconv.ParseUint(x, 10, 64)
		yn, yErr := strconv.ParseUint(y, 10, 64)
		switch {
		case xErr == nil && yErr == nil:
			if xn < yn {
				return -1
			}
			return 1
		case xErr == nil:
			return -1
		case yErr == nil:
			return 1
		case x < y:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}
