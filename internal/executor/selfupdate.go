package executor

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
	"github.com/stackedapp/stacked/agent/internal/releaseverify"
)

var (
	agentBinaryPath = "/opt/stacked/agent"
	releaseScheme   = "https"
	releaseHost     = "github.com"
	releasePrefix   = "/stackedhq/agent/releases/download"
	exitFunc        = os.Exit
)

const downloadTimeout = 2 * time.Minute

// SelfUpdate downloads a signed GitHub release, verifies it, replaces
// the agent binary, and exits so systemd restarts the new process.
func (e *Executor) SelfUpdate(op client.Operation) error {
	if err := e.installUpdate(op, heartbeat.Version); err != nil {
		return err
	}
	log.Printf("Agent binary replaced, exiting so systemd restarts with new binary...")
	_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "success"})
	exitFunc(0)
	return nil
}

func (e *Executor) installUpdate(op client.Operation, currentVersion string) error {
	target := getStringPayload(op.Payload, "targetVersion")
	if target == "" {
		return fmt.Errorf("self_update requires targetVersion in payload")
	}
	allowDowngrade := getBoolPayload(op.Payload, "allowDowngrade", false)

	ver, err := releaseverify.DecideUpdate(currentVersion, target, allowDowngrade)
	if err != nil {
		return err
	}

	if raw := getStringPayload(op.Payload, "downloadUrl"); raw != "" {
		if err := validateReleaseURL(raw, ver.String(), runtime.GOARCH); err != nil {
			return fmt.Errorf("downloadUrl rejected: %w", err)
		}
	}

	arch := runtime.GOARCH
	binName := releaseverify.OfficialBinaryName(arch)
	binURL := officialAssetURL(ver.String(), binName)
	sumsURL := officialAssetURL(ver.String(), releaseverify.ChecksumsName)
	sigURL := officialAssetURL(ver.String(), releaseverify.SignatureName)

	log.Printf("Self-updating agent to v%s (signed release)", ver)

	tmpPath := agentBinaryPath + ".tmp"
	sumsPath := agentBinaryPath + ".SHA256SUMS"
	sigPath := agentBinaryPath + ".SHA256SUMS.sig"
	defer func() {
		os.Remove(tmpPath)
		os.Remove(sumsPath)
		os.Remove(sigPath)
	}()

	if err := downloadReleaseFile(tmpPath, binURL); err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	if err := downloadReleaseFile(sumsPath, sumsURL); err != nil {
		return fmt.Errorf("download SHA256SUMS: %w", err)
	}
	if err := downloadReleaseFile(sigPath, sigURL); err != nil {
		return fmt.Errorf("download SHA256SUMS.sig: %w", err)
	}

	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if err := releaseverify.VerifyChecksumSignature(sums, sig); err != nil {
		return err
	}
	want, err := releaseverify.ChecksumForName(sums, binName)
	if err != nil {
		return err
	}
	if err := releaseverify.VerifyFileHash(tmpPath, want); err != nil {
		return err
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmpPath, agentBinaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}

func officialAssetURL(version, name string) string {
	return fmt.Sprintf("%s://%s%s/v%s/%s", releaseScheme, releaseHost, releasePrefix, version, name)
}

func validateReleaseURL(raw, version, arch string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS URL %q", raw)
	}
	if u.User != nil {
		return fmt.Errorf("refusing URL with userinfo")
	}
	if u.Host != "github.com" {
		return fmt.Errorf("refusing non-release host %q (only github.com/stackedhq/agent releases)", u.Host)
	}
	want := fmt.Sprintf("/stackedhq/agent/releases/download/v%s/%s", version, releaseverify.OfficialBinaryName(arch))
	if u.Path != want {
		return fmt.Errorf("URL path %q is not the official v%s %s asset", u.Path, version, arch)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("refusing URL with query or fragment")
	}
	return nil
}

func releaseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: downloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != releaseScheme {
				return fmt.Errorf("refusing HTTPS downgrade to %s", req.URL)
			}
			if req.URL.Host != releaseHost {
				return fmt.Errorf("refusing redirect off release host to %s", req.URL.Host)
			}
			if !strings.HasPrefix(req.URL.Path, releasePrefix) {
				return fmt.Errorf("refusing redirect off release path to %s", req.URL.Path)
			}
			return nil
		},
	}
}

func downloadReleaseFile(dest, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != releaseScheme {
		return fmt.Errorf("refusing non-%s download %q", strings.ToUpper(releaseScheme), rawURL)
	}
	if u.Host != releaseHost {
		return fmt.Errorf("refusing non-release host %q", u.Host)
	}

	resp, err := releaseHTTPClient().Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	if resp.ContentLength > releaseverify.MaxAssetBytes {
		return fmt.Errorf("download %s is %d bytes, over the %d byte limit", rawURL, resp.ContentLength, releaseverify.MaxAssetBytes)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := io.Copy(f, io.LimitReader(resp.Body, releaseverify.MaxAssetBytes+1))
	if err != nil {
		return err
	}
	if n > releaseverify.MaxAssetBytes {
		return fmt.Errorf("download exceeded %d byte limit", releaseverify.MaxAssetBytes)
	}
	return nil
}

