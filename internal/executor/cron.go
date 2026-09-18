package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// RunJob handles the `cron_run` op type — a scheduled job. Runs the user's
// command in a one-shot container (`docker run --rm`) built from the
// service's *already-deployed* local image, before any traffic concerns.
//
// Unlike `release_command`, a cron run never rebuilds or re-pulls: it runs
// the image left on the host by the last successful deploy
// (`stacked-<serviceID>` for git services, or the pinned `dockerImage`).
// This keeps runs cheap and guarantees a job runs the same code that's
// currently serving, not freshly-fetched source. If no image exists yet
// (the service was never deployed) the run fails with a clear message.
//
// Env vars are fetched on-demand via the same credentials endpoint the
// deploy/release paths use, so the op payload holds no secrets.
//
// On success the result carries `{exitCode: 0}` so the server records the
// run's exit code. A non-zero exit returns an error (the exit status is in
// the message); the server marks the run failed.
func (e *Executor) RunJob(op client.Operation) (map[string]interface{}, error) {
	mode := getStringPayload(op.Payload, "mode")
	if mode == "http" {
		return e.runHTTPJob(op)
	}
	return e.runCommandJob(op)
}

// runHTTPJob makes an HTTP request from the agent host. Runs on the same
// network as the user's containers, so internal URLs (e.g.
// http://my-service:3000/api/cron) work.
func (e *Executor) runHTTPJob(op client.Operation) (map[string]interface{}, error) {
	url := getStringPayload(op.Payload, "httpUrl")
	if url == "" {
		return nil, fmt.Errorf("cron_run http mode requires httpUrl")
	}
	method := getStringPayload(op.Payload, "httpMethod")
	if method == "" {
		method = "GET"
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) (map[string]interface{}, error) {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return nil, err
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("HTTP job: %s %s", method, url))
	streamer.Flush()

	var bodyReader io.Reader
	if body := getStringPayload(op.Payload, "httpBody"); body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return fail(fmt.Errorf("build request: %w", err))
	}

	// Parse JSON headers from payload if present.
	if hdrs := getStringPayload(op.Payload, "httpHeaders"); hdrs != "" {
		parsed := parseJSONHeaders(hdrs)
		for k, v := range parsed {
			req.Header.Set(k, v)
		}
	}

	httpClient := &http.Client{Timeout: 5 * time.Minute}
	streamer.SetProgress(50)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fail(fmt.Errorf("request failed: %w", err))
	}
	defer resp.Body.Close()

	// Read a snippet of the body for logs (cap at 4KB).
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	snippet := string(bodyBytes)

	streamer.AddLine(fmt.Sprintf("Response: %d %s", resp.StatusCode, resp.Status))
	if snippet != "" {
		streamer.AddLine(snippet)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		streamer.SetProgress(100)
		streamer.AddLine("HTTP job completed successfully.")
		streamer.Flush()
		return map[string]interface{}{"exitCode": 0}, nil
	}

	streamer.Flush()
	return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(snippet))
}

func (e *Executor) runCommandJob(op client.Operation) (map[string]interface{}, error) {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return nil, fmt.Errorf("cron_run requires serviceId in payload")
	}

	command := getStringPayload(op.Payload, "command")
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("cron_run requires a command")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) (map[string]interface{}, error) {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return nil, err
	}

	streamer.SetProgress(0)
	streamer.AddLine("Scheduled job: resolving image...")
	streamer.Flush()

	// Resolve the image without rebuilding. Pinned dockerImage wins; else
	// the git-build image name the deploy path produced.
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	imageName := dockerImage
	if imageName == "" {
		imageName = "stacked-" + serviceID
	}

	// Verify the image exists locally — a never-deployed service has none,
	// and `docker run` would otherwise try (and fail) to pull a non-image.
	if out, err := runCommandSilent("", "docker", "image", "inspect", imageName); err != nil {
		_ = out
		return fail(fmt.Errorf(
			"image %s not found on host; deploy the service before running jobs",
			imageName,
		))
	}

	dir := serviceDir(serviceID)
	if err := ensureSecretDir(dir); err != nil {
		return fail(fmt.Errorf("create service dir: %w", err))
	}

	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		var credErr *client.CredentialsError
		if errors.As(err, &credErr) {
			return fail(fmt.Errorf("%s", credErr.Message))
		}
		return fail(fmt.Errorf("get credentials: %w", err))
	}

	if creds.EnvVars == nil {
		creds.EnvVars = map[string]string{}
	}
	if _, ok := creds.EnvVars["HOST"]; !ok {
		creds.EnvVars["HOST"] = "0.0.0.0"
	}
	envPath := filepath.Join(dir, ".env")
	if err := writeSecretFile(envPath, buildEnvFile(creds.EnvVars)); err != nil {
		return fail(fmt.Errorf("write .env: %w", err))
	}

	// Make sure the stacked network exists — the job may need to reach the
	// user's database container, which sits on it.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	streamer.SetProgress(50)
	streamer.AddLine("Running job: " + command)
	streamer.Flush()

	runID := getStringPayload(op.Payload, "runId")
	containerName := serviceID + "-cron"
	if runID != "" {
		// Short suffix keeps concurrent manual + scheduled runs from
		// colliding on the container name.
		suffix := runID
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		containerName = serviceID + "-cron-" + suffix
	}

	args := []string{
		"run", "--rm",
		"--network=stacked",
		"--env-file=" + envPath,
		"--name", containerName,
		imageName,
		"sh", "-lc", command,
	}
	if err := e.runCommandWithStreamer(streamer, dir, "docker", args...); err != nil {
		return fail(fmt.Errorf("job command failed: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Job completed successfully.")
	streamer.Flush()
	return map[string]interface{}{"exitCode": 0}, nil
}

// parseJSONHeaders parses a JSON object string into a flat string map.
// Returns empty map on any parse error — headers are best-effort.
func parseJSONHeaders(raw string) map[string]string {
	out := map[string]string{}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return out
	}
	for k, v := range parsed {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
