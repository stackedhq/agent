package executor

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

const (
	stackedDir  = "/opt/stacked"
	servicesDir = "/opt/stacked/services"
	proxyDir    = "/opt/stacked/proxy"
)

// Executor handles running operations dispatched by the poller.
type Executor struct {
	Client *client.Client
}

func New(c *client.Client) *Executor {
	return &Executor{Client: c}
}

// Execute dispatches an operation to the correct handler based on type.
func (e *Executor) Execute(op client.Operation) {
	// Report running
	if err := e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "running"}); err != nil {
		log.Printf("Failed to report running status for %s: %v", op.ID, err)
	}

	var err error
	switch op.Type {
	case "deploy":
		err = e.Deploy(op)
	case "stop":
		err = e.Stop(op)
	case "restart":
		err = e.Restart(op)
	case "setup":
		err = e.Setup(op)
	case "proxy_config":
		err = e.ProxyConfig(op)
	case "self_update":
		err = e.SelfUpdate(op)
	default:
		err = fmt.Errorf("unknown operation type: %s", op.Type)
	}

	if err != nil {
		log.Printf("Operation %s (%s) failed: %v", op.ID, op.Type, err)
		_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{
			Status: "failed",
			Result: map[string]interface{}{"error": err.Error()},
		})
		return
	}

	_ = e.Client.UpdateStatus(op.ID, &client.StatusUpdate{Status: "success"})
}

// serviceDir returns the working directory for a service.
func serviceDir(serviceID string) string {
	return filepath.Join(servicesDir, serviceID)
}

// runCommand executes a command, streaming stdout/stderr to the Stacked API.
func (e *Executor) runCommand(operationID, dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	// Combine stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	streamer := logs.NewStreamer(e.Client, operationID)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	streamer.Stream(stdout)
	streamer.Flush()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s exited with error: %w", name, err)
	}
	return nil
}

// runCommandWithStreamer executes a command using an existing streamer,
// so all commands in a deploy share the same log stream and progress state.
func (e *Executor) runCommandWithStreamer(streamer *logs.Streamer, dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}

	streamer.Stream(stdout)
	streamer.Flush()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s exited with error: %w", name, err)
	}
	return nil
}

// runCommandSilent executes a command and returns its combined output.
func runCommandSilent(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ensureDir creates a directory if it doesn't exist.
func ensureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// writeFile writes content to a file, creating parent dirs as needed.
func writeFile(path, content string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// getStringPayload extracts a string from the operation payload.
func getStringPayload(payload map[string]interface{}, key string) string {
	v, ok := payload[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// mergedReader returns an io.Reader that reads from both r1 and r2.
func mergedReader(r1, r2 io.Reader) io.Reader {
	return io.MultiReader(r1, r2)
}
