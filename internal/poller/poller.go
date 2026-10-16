package poller

import (
	"log"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/executor"
)

// Per-operation deadlines. When one expires the op is reported failed and
// its commands are killed; ops still run one at a time.
const (
	// deployOpTimeout covers clone + build + rollout.
	deployOpTimeout = 45 * time.Minute
	// dbDataOpTimeout covers ops that move a whole database or volume.
	dbDataOpTimeout = 2 * time.Hour
	// imagePullOpTimeout covers ops that may pull a large image first.
	imagePullOpTimeout = 30 * time.Minute
	// defaultOpTimeout is everything else (config, start/stop, probes).
	defaultOpTimeout = 10 * time.Minute
	// jobSetupSlack is added to a job's own run timeout for the image
	// check and credential fetch around it.
	jobSetupSlack = 10 * time.Minute
)

// opTimeout returns the deadline for one operation.
func opTimeout(op client.Operation) time.Duration {
	switch op.Type {
	case "deploy":
		return deployOpTimeout
	case "release_command":
		// The release op builds the image (like a deploy) and then runs
		// the command under its own timeout.
		return deployOpTimeout + executor.ReleaseCommandTimeout
	case "cron_run":
		return executor.CronJobTimeout(op.Payload) + jobSetupSlack
	case "db_backup", "db_restore", "db_migrate", "volume_migrate":
		return dbDataOpTimeout
	case "db_provision", "setup":
		return imagePullOpTimeout
	default:
		return defaultOpTimeout
	}
}

// Loop polls for operations at the given interval until the stop channel is closed.
func Loop(c *client.Client, exec *executor.Executor, interval time.Duration, stop <-chan struct{}) {
	// Poll once immediately on startup
	poll(c, exec)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			poll(c, exec)
		case <-stop:
			return
		}
	}
}

func poll(c *client.Client, exec *executor.Executor) {
	ops, err := c.PollOperations()
	if err != nil {
		log.Printf("Poll failed: %v", err)
		return
	}

	if len(ops) == 0 {
		return
	}

	log.Printf("Claimed %d operation(s)", len(ops))

	// Deduplicate proxy_config — only execute the latest one
	ops = dedupeProxyConfig(ops)

	// Execute sequentially
	for _, op := range ops {
		timeout := opTimeout(op)
		log.Printf("Executing operation %s (type=%s, timeout=%s)", op.ID, op.Type, timeout)
		exec.ExecuteWithTimeout(op, timeout)
	}
}

// dedupeProxyConfig keeps only the last proxy_config operation,
// since each one contains the full desired state.
func dedupeProxyConfig(ops []client.Operation) []client.Operation {
	lastProxyIdx := -1
	for i, op := range ops {
		if op.Type == "proxy_config" {
			lastProxyIdx = i
		}
	}

	if lastProxyIdx < 0 {
		return ops
	}

	var result []client.Operation
	for i, op := range ops {
		if op.Type == "proxy_config" && i != lastProxyIdx {
			// Skip older proxy_config ops — mark them as success since they're superseded
			log.Printf("Skipping superseded proxy_config operation %s", op.ID)
			continue
		}
		result = append(result, op)
	}
	return result
}
