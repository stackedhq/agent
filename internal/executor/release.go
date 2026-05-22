package executor

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// ReleaseCommand handles the `release_command` op type — Heroku-style
// release phase. Runs the user's command (e.g. `bun db:migrate`) inside
// a one-shot container built from the new image, before any traffic
// flips to the new code. A non-zero exit aborts the deploy bundle: the
// server, on receiving the failure status, never enqueues the follow-up
// `deploy` op, so the live container is never disturbed.
//
// We deliberately use `docker run --rm` rather than `docker exec` against
// a pre-started slot, for two reasons:
//
//   1. The new slot doesn't need to be running yet — saves time and
//      avoids the "container started but migrations failed, now what?"
//      cleanup path.
//   2. The semantics are identical to Heroku's release-phase dyno and
//      Fly's release_command (which spins up a temporary VM): one image
//      version, one process, exit code is the gate.
//
// The handler reuses the deploy payload shape verbatim — the server
// duplicates the deploy op's payload onto the release op so this code
// path can resolve image, env, network, etc. exactly the same way as
// the deploy executor.
func (e *Executor) ReleaseCommand(op client.Operation) error {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return fmt.Errorf("release_command requires serviceId in payload")
	}

	releaseCmd := getStringPayload(op.Payload, "releaseCommand")
	if strings.TrimSpace(releaseCmd) == "" {
		// Server should never enqueue a release op without a command,
		// but defend against it: a no-op release is correct behavior.
		log.Printf("release_command for %s has empty command; skipping", serviceID)
		return nil
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(0)
	streamer.AddLine("Release phase: fetching credentials...")
	streamer.Flush()

	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		var credErr *client.CredentialsError
		if errors.As(err, &credErr) {
			return fail(fmt.Errorf("%s", credErr.Message))
		}
		return fail(fmt.Errorf("get credentials: %w", err))
	}

	// Resolve the image. For docker-image services this is the user's
	// pushed image and we just `docker pull` it. For git-based services
	// we have to clone + nixpacks-build before we can run the command —
	// the build is identical to what the deploy op will do, and docker's
	// layer cache makes the second build (in the deploy op) ~instant.
	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return fail(fmt.Errorf("create service dir: %w", err))
	}

	dockerImage := getStringPayload(op.Payload, "dockerImage")
	var imageName string

	if dockerImage != "" {
		imageName = dockerImage
		streamer.SetProgress(10)
		streamer.AddLine("Pulling image " + imageName + "...")
		streamer.Flush()

		if creds.RegistryToken != "" {
			cmd := exec.Command("docker", "login", "ghcr.io", "-u", "x-access-token", "--password-stdin")
			cmd.Stdin = strings.NewReader(creds.RegistryToken)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("ghcr login (release) failed (non-fatal): %s", string(out))
			}
		}

		if err := e.runCommandWithStreamer(streamer, dir, "docker", "pull", imageName); err != nil {
			return fail(fmt.Errorf("docker pull %s: %w", imageName, err))
		}
	} else {
		// Git-based: clone + build. Reuses the same buildFromSource
		// helper deploy.go uses, so the image name is identical
		// (`stacked-<serviceID>`) and the deploy op will hit cache.
		built, err := e.buildFromSource(op, serviceID, dir, creds, streamer)
		if err != nil {
			return fail(err)
		}
		imageName = built
	}

	// Write the env file the one-shot container will read. Same shape
	// the deploy executor writes for the running container.
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

	// Make sure the stacked network exists — the migration command may
	// need to reach the user's database container, which sits on it.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	streamer.SetProgress(70)
	streamer.AddLine("Running release command: " + releaseCmd)
	streamer.Flush()

	// `--rm` so the container doesn't pile up. `--network=stacked` lets
	// the command reach managed databases. `sh -lc` so users can write
	// shell pipelines / && chains naturally.
	args := []string{
		"run", "--rm",
		"--network=stacked",
		"--env-file=" + envPath,
		"--name", serviceID + "-release",
		imageName,
		"sh", "-lc", releaseCmd,
	}
	if err := e.runCommandWithStreamer(streamer, dir, "docker", args...); err != nil {
		return fail(fmt.Errorf("release command failed: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Release command completed successfully.")
	streamer.Flush()
	return nil
}


