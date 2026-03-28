package poller

import (
	"log"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/executor"
)

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
		log.Printf("Executing operation %s (type=%s)", op.ID, op.Type)
		exec.Execute(op)
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
