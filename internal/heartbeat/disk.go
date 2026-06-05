package heartbeat

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// duTimeout bounds how long we'll wait for `du -sh` on a Stacked path.
// A box with a multi-GB Postgres volume can take several seconds and
// spike I/O; if we exceed the budget we drop the section rather than
// blocking the heartbeat. The heartbeat handler is the single critical
// path for op delivery (see agent.ts comments) and must not stall.
const duTimeout = 5 * time.Second

// dockerDfTimeout bounds `docker system df`. On a host with hundreds
// of images / build-cache layers, `df` walks the full graph and can
// take 1–3 seconds; if Docker itself is wedged it can hang indefinitely.
// Same defensive posture as `du`: drop the section, preserve the
// previous snapshot, never block the heartbeat.
const dockerDfTimeout = 5 * time.Second

// collectDiskBreakdown returns a best-effort disk-usage snapshot for
// the host. Both sub-sections are independent: a failure in one (or a
// timeout) doesn't prevent the other from being reported. Returns nil
// only when *both* halves failed \u2014 in which case the server preserves
// whatever the previous heartbeat wrote.
func collectDiskBreakdown() *client.DiskBreakdown {
	docker := collectDockerDiskUsage()
	stacked := collectStackedDiskUsage()
	if docker == nil && stacked == nil {
		return nil
	}
	return &client.DiskBreakdown{
		Docker:  docker,
		Stacked: stacked,
	}
}

// dockerSystemDfRow matches the JSON shape emitted by
// `docker system df --format '{{json .}}'`. Docker emits one line per
// resource type ("Images", "Containers", "Local Volumes", "Build Cache")
// with these four fields.
type dockerSystemDfRow struct {
	Type        string `json:"Type"`
	Size        string `json:"Size"`        // e.g. "1.234GB"
	Reclaimable string `json:"Reclaimable"` // e.g. "500MB (40%)"
}

func collectDockerDiskUsage() *client.DockerDiskUsage {
	ctx, cancel := context.WithTimeout(context.Background(), dockerDfTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "system", "df", "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("docker system df timed out after %s", dockerDfTimeout)
		} else {
			log.Printf("docker system df failed: %v", err)
		}
		return nil
	}

	var usage client.DockerDiskUsage
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var row dockerSystemDfRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		size := parseSize(row.Size)
		// `Reclaimable` is "<size> (<percent>%)"; we only want the size.
		// Guard against an empty Reclaimable field (older Docker, build
		// cache rows on some versions) which would panic on `[0]`.
		var reclaim uint64
		if fields := strings.Fields(row.Reclaimable); len(fields) > 0 {
			reclaim = parseSize(fields[0])
		}
		usage.ReclaimableBytes += reclaim
		switch row.Type {
		case "Images":
			usage.ImagesBytes = size
		case "Containers":
			usage.ContainersBytes = size
		case "Local Volumes":
			usage.VolumesBytes = size
		case "Build Cache":
			usage.BuildCacheBytes = size
		}
	}
	return &usage
}

func collectStackedDiskUsage() *client.StackedDiskUsage {
	services, sOk := duBytes("/opt/stacked/services")
	volumes, vOk := duBytes("/opt/stacked/volumes")
	if !sOk && !vOk {
		return nil
	}
	return &client.StackedDiskUsage{
		ServicesBytes: services,
		VolumesBytes:  volumes,
	}
}

// duBytes runs `du -sb <path>` (bytes, summary) under a timeout and
// returns (bytes, ok). `ok=false` if the timeout fired, the path
// doesn't exist, or the parse failed. Caller decides whether to omit
// the field or report 0 \u2014 we report 0 only when both halves of
// stacked failed (see collectStackedDiskUsage).
//
// `-b` returns apparent size in bytes (not block-aligned). For
// "what's eating my disk" the apparent size is the more useful number:
// a sparse file looks small under `-b` but takes a fraction of a block
// of real space; on the other hand a tiny file uses a whole 4 KiB
// block on disk. We accept the apparent-size approximation here in
// exchange for consistent units across all rows.
func duBytes(path string) (uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), duTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "du", "-sb", path)
	out, err := cmd.Output()
	if err != nil {
		// ENOENT and timeouts both end up here. Logging the path
		// avoids spamming the journal on first-run boxes that don't
		// have these directories yet.
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("du %s timed out after %s", path, duTimeout)
		}
		return 0, false
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
