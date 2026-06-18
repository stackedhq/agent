package executor

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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
	if err := ensureDir(dir); err != nil {
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
	if err := writeFile(envPath, buildEnvFile(creds.EnvVars)); err != nil {
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
