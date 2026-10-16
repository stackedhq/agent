package executor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/logs"
)

// One-shot job containers (`cron_run` command jobs and `release_command`).
//
// They run the user's image with `docker run --rm`, so three things are
// enforced here rather than trusted to the image:
//
//   - labels: an image can carry its own `com.stacked.*` /
//     `com.docker.compose.*` labels, which `docker run` inherits. The log
//     forwarders and heartbeat use those to map containers to services and
//     build on-disk paths, so job containers are stamped
//     `com.stacked.kind=job` and the compose/slot labels are cleared;
//   - resources: the service's CPU/memory caps, or a default so a runaway
//     job can't starve the host;
//   - time: a deadline, after which the container is `docker kill`ed
//     (killing the docker CLI alone would leave the container running).

const (
	// ReleaseCommandTimeout bounds the release command itself (the build
	// before it is covered by the op deadline).
	ReleaseCommandTimeout = 30 * time.Minute

	defaultCronJobTimeout = time.Hour
	maxCronJobTimeout     = 24 * time.Hour

	defaultJobMemoryMB      = 512
	defaultJobCPUMillicores = 1000

	jobKillTimeout = 30 * time.Second
)

// CronJobTimeout returns how long a cron_run command may run: the payload's
// `timeoutSeconds` when present and positive (capped at 24h), else 1h.
func CronJobTimeout(payload map[string]interface{}) time.Duration {
	secs := getIntPayload(payload, "timeoutSeconds")
	if secs <= 0 {
		return defaultCronJobTimeout
	}
	d := time.Duration(secs) * time.Second
	if d > maxCronJobTimeout {
		return maxCronJobTimeout
	}
	return d
}

// jobLabelArgs marks a job container and clears labels inherited from the
// image that would make it look like a managed service or database.
func jobLabelArgs(job string) []string {
	return []string{
		"--label", "com.stacked.kind=job",
		"--label", "com.stacked.job=" + job,
		"--label", "com.stacked.slot=",
		"--label", "com.docker.compose.project=",
		"--label", "com.docker.compose.service=",
		"--label", "com.docker.compose.oneoff=",
	}
}

// jobResourceArgs applies the service's limits from the payload
// (`cpuLimit` millicores, `memoryLimitMb`), defaulting each unset one to
// 1 CPU / 512 MB.
func jobResourceArgs(payload map[string]interface{}) []string {
	limits := resourceLimitsFromPayload(payload)
	if limits.memoryMB <= 0 {
		limits.memoryMB = defaultJobMemoryMB
	}
	if limits.cpuMillicores <= 0 {
		limits.cpuMillicores = defaultJobCPUMillicores
	}
	return []string{
		fmt.Sprintf("--memory=%dm", limits.memoryMB),
		"--cpus=" + limits.cpus(),
	}
}

// errJobTimedOut is wrapped into the error returned when a job hits its
// deadline.
var errJobTimedOut = errors.New("job timed out")

// runJobContainer runs `docker <args>` (a `docker run --name containerName
// ...`) with output streamed, and stops the container if timeout or the op
// deadline expires first.
func runJobContainer(streamer *logs.Streamer, dir string, env []string, containerName string, timeout time.Duration, args []string) error {
	ctx, cancel := context.WithTimeout(currentOpContext(), timeout)
	defer cancel()

	cmd := opCommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	cmd.Env = env
	killCLI := cmd.Cancel
	cmd.Cancel = func() error {
		// Stop the container first: that ends `docker run` cleanly and
		// `--rm` removes it. Then kill the CLI's process group as a
		// backstop in case the daemon call hung.
		killJobContainer(containerName)
		if killCLI != nil {
			return killCLI()
		}
		return cmd.Process.Kill()
	}

	err := runStreamedCmd(streamer, cmd, "docker")
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && currentOpContext().Err() == nil {
			return fmt.Errorf("%w after %s; container %s was stopped", errJobTimedOut, timeout, containerName)
		}
		return fmt.Errorf("%w: operation deadline reached; container %s was stopped", errJobTimedOut, containerName)
	}
	return err
}

// killJobContainer stops a job container. Uses its own short deadline
// because the op context is already done when this runs.
func killJobContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), jobKillTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "kill", name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such container") && !strings.Contains(string(out), "is not running") {
		log.Printf("docker kill %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
}
