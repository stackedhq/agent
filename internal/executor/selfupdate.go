package executor

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const agentBinaryPath = "/opt/stacked/agent"

// SelfUpdate downloads the latest agent binary and restarts the service.
func (e *Executor) SelfUpdate(op client.Operation) error {
	targetVersion := getStringPayload(op.Payload, "targetVersion")
	if targetVersion == "" {
		return fmt.Errorf("self_update requires targetVersion in payload")
	}

	downloadURL := getStringPayload(op.Payload, "downloadUrl")
	if downloadURL == "" {
		arch := runtime.GOARCH
		downloadURL = fmt.Sprintf(
			"https://github.com/stackedhq/agent/releases/download/v%s/stacked-agent-linux-%s",
			targetVersion, arch,
		)
	}

	log.Printf("Self-updating agent to v%s from %s", targetVersion, downloadURL)

	// Download to temp file
	tmpPath := agentBinaryPath + ".tmp"
	if err := downloadFile(tmpPath, downloadURL); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download binary: %w", err)
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod: %w", err)
	}

	// Replace current binary
	if err := os.Rename(tmpPath, agentBinaryPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	log.Printf("Agent binary replaced, restarting via systemd...")

	// Report success before restarting — the restart will kill this process
	_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "success"})

	// Restart the service — systemd will start the new binary
	if out, err := runCommandSilent("", "sudo", "systemctl", "restart", "stacked-agent"); err != nil {
		return fmt.Errorf("restart service: %s: %w", out, err)
	}

	// Won't reach here if restart succeeds (process gets killed)
	return nil
}

func downloadFile(dest, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}
