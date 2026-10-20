package executor

import (
	"context"
	"errors"
	"fmt"
	"log"
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
//   - resources: the service's CPU/memory caps from the payload
//     (`cpuLimit` millicores, `memoryLimitMb`; the deploy payload for
//     release commands, the `cron_run` payload for cron jobs). Each unset
//     cap falls back to a default (1 CPU; 512 MB for cron, 1 GB for
//     release commands, which often run migrations or asset builds) so a
//     runaway job can't starve the host;
//   - time: a deadline, after which the container is `docker kill`ed
//     (killing the docker CLI alone would leave the container running)
//     and runJobContainer waits for it to be removed before returning.
//
// volume_migrate's copy helper also runs through runJobContainer (see
// VolumeMigrate) for the deadline handling.

const (
	// ReleaseCommandTimeout bounds the release command itself (the build
	// before it is covered by the op deadline).
	ReleaseCommandTimeout = 30 * time.Minute

	defaultCronJobTimeout = time.Hour
	maxCronJobTimeout     = 24 * time.Hour

	defaultCronMemoryMB     = 512
	defaultReleaseMemoryMB  = 1024
	defaultJobCPUMillicores = 1000
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
// (`cpuLimit` millicores, `memoryLimitMb`; only values > 0 count),
// defaulting an unset CPU cap to 1 CPU and an unset memory cap to
// defaultMemoryMB.
func jobResourceArgs(payload map[string]interface{}, defaultMemoryMB int) []string {
	limits := resourceLimitsFromPayload(payload)
	if limits.memoryMB <= 0 {
		limits.memoryMB = defaultMemoryMB
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
	// A job that exited successfully right at the deadline succeeded;
	// only a failed run is attributed to the timeout.
	if err != nil && ctx.Err() != nil {
		// Don't return while the container may still be running (a
		// volume copy could keep writing into its target): wait for
		// `--rm` to remove it, force-removing it if it lingers.
		stopped := "was stopped"
		if gone := waitJobContainerGone(containerName); gone != nil {
			stopped = "may still be running: " + gone.Error()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && currentOpContext().Err() == nil {
			return fmt.Errorf("%w after %s; container %s %s", errJobTimedOut, timeout, containerName, stopped)
		}
		return fmt.Errorf("%w: operation deadline reached; container %s %s", errJobTimedOut, containerName, stopped)
	}
	return err
}

// jobRemoveWait bounds how long a stopped job container is given to be
// auto-removed (`--rm`) before it is force-removed; jobRemovePoll is the
// polling interval. Variables so tests can shorten them.
var (
	jobRemoveWait = cleanupTimeout
	jobRemovePoll = 250 * time.Millisecond
)

// waitJobContainerGone waits until the named container no longer exists,
// then returns nil. If it is still present after jobRemoveWait it is
// force-removed (`docker rm -f` kills it first). Every docker call uses
// cleanupCommand, so this works after the op deadline has expired.
func waitJobContainerGone(name string) error {
	deadline := time.Now().Add(jobRemoveWait)
	for {
		if jobContainerGone(name) {
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(jobRemovePoll)
	}
	out, err := cleanupCommand(cleanupTimeout, "docker", "rm", "-f", name)
	if jobContainerGone(name) {
		return nil
	}
	if err == nil {
		err = errors.New("container still present after docker rm -f")
	}
	log.Printf("docker rm -f %s: %v: %s", name, err, strings.TrimSpace(out))
	return fmt.Errorf("remove %s: %w", name, err)
}

// jobContainerGone reports whether the daemon says no such container
// exists. Any other inspect failure (daemon unreachable) is "not gone".
func jobContainerGone(name string) bool {
	out, err := cleanupCommand(cleanupTimeout, "docker", "container", "inspect", "--format", "{{.Id}}", name)
	return err != nil && strings.Contains(out, "No such container")
}

// killJobContainer stops a job container. Uses its own short deadline
// because the op context is already done when this runs.
func killJobContainer(name string) {
	out, err := cleanupCommand(cleanupTimeout, "docker", "kill", name)
	if err != nil && !strings.Contains(out, "No such container") && !strings.Contains(out, "is not running") {
		log.Printf("docker kill %s: %v: %s", name, err, strings.TrimSpace(out))
	}
}
