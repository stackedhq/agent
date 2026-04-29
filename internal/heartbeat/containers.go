package heartbeat

import (
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// collectContainers enumerates Stacked-managed Docker containers (those with a
// com.docker.compose.project label, since every deploy generates a compose
// project keyed by the serviceID) and pulls per-container CPU/memory stats.
//
// The mapping container -> serviceID comes from the compose project label,
// which the deploy executor sets to the serviceID via the working directory
// name (/opt/stacked/services/<serviceID>) — compose's default project name is
// the basename of that directory.
//
// Errors are logged but never fatal: a partial or empty result is always OK.
//
// NOTE on multi-container services: today every service maps to exactly one
// container. If horizontal scaling is ever added (e.g. `deploy.replicas` or
// `docker compose up --scale`), multiple containers will share the same
// compose-project label and we'll emit duplicate ContainerStatus rows for one
// serviceID. The server will then race UPDATEs and the UI will flicker. When
// scaling lands, aggregate (sum CPU%, sum memBytes) per serviceID here before
// returning.
func collectContainers() []client.ContainerStatus {
	rows := listStackedContainers()
	if len(rows) == 0 {
		return nil
	}

	statsByID := dockerStats(containerIDs(rows))

	// When a container has no memory limit set, Docker reports the host's
	// total memory as the "limit". That's technically true but useless for the
	// UI — it makes every unlimited service look like it's using 1% of a giant
	// pool. Detect this and zero the field so the UI drops the "/ 16 GB"
	// suffix and just shows absolute bytes used.
	hostMemBytes := uint64(sysInfo.MemoryMb) * 1024 * 1024

	out := make([]client.ContainerStatus, 0, len(rows))
	for _, r := range rows {
		c := client.ContainerStatus{
			ServiceID: r.serviceID,
			Status:    r.state,
		}
		if s, ok := statsByID[r.id]; ok {
			// Clamp percent fields to [0, 100] so a malformed `docker stats`
			// row can't poison the heartbeat payload.
			c.CPUPercent = clampPercent(s.cpuPercent)
			c.MemoryPercent = clampPercent(s.memPercent)
			c.MemoryBytes = s.memBytes
			c.MemoryLimitBytes = s.memLimitBytes
			// Treat "limit within 5% of host memory" as unlimited. The 5%
			// fudge handles rounding between docker's MiB conversion and our
			// /proc/meminfo MB conversion.
			if hostMemBytes > 0 && c.MemoryLimitBytes >= hostMemBytes*95/100 {
				c.MemoryLimitBytes = 0
			}
		}
		out = append(out, c)
	}
	return out
}

type containerRow struct {
	id        string
	serviceID string
	state     string
}

func listStackedContainers() []containerRow {
	// Tab-separated to avoid issues with image names containing spaces.
	// We only want containers that belong to a Stacked-managed compose project.
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--filter", "label=com.docker.compose.project",
		"--format", `{{.ID}}	{{.Label "com.docker.compose.project"}}	{{.State}}`,
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("docker ps failed: %v", err)
		return nil
	}

	var rows []containerRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		rows = append(rows, containerRow{
			id:        parts[0],
			serviceID: parts[1],
			state:     parts[2],
		})
	}
	return rows
}

func containerIDs(rows []containerRow) []string {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.id)
	}
	return ids
}

type containerStats struct {
	cpuPercent    float64
	memPercent    float64
	memBytes      uint64
	memLimitBytes uint64
}

// dockerStatsRow matches the JSON shape emitted by `docker stats --format '{{json .}}'`.
type dockerStatsRow struct {
	ID       string `json:"ID"`
	CPUPerc  string `json:"CPUPerc"`
	MemPerc  string `json:"MemPerc"`
	MemUsage string `json:"MemUsage"`
}

// dockerStats runs a single `docker stats --no-stream` for the given container
// IDs and returns a map keyed by short ID (12 chars, matching `docker ps`).
//
// `docker stats` only reports stats for *running* containers; stopped ones are
// silently omitted. That's fine — for a stopped container we just leave the
// resource fields zero.
func dockerStats(ids []string) map[string]containerStats {
	if len(ids) == 0 {
		return nil
	}

	args := append([]string{"stats", "--no-stream", "--format", "{{json .}}"}, ids...)
	cmd := exec.Command("docker", args...)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("docker stats failed: %v", err)
		return nil
	}

	result := make(map[string]containerStats, len(ids))
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var row dockerStatsRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		used, limit := parseMemUsage(row.MemUsage)
		result[shortID(row.ID)] = containerStats{
			cpuPercent:    parsePercent(row.CPUPerc),
			memPercent:    parsePercent(row.MemPerc),
			memBytes:      used,
			memLimitBytes: limit,
		}
	}
	return result
}

// shortID truncates a container ID to the 12-char form `docker ps` returns.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// parsePercent strips a trailing "%" and parses the float. Returns 0 on error.
func parsePercent(s string) float64 {
	s = strings.TrimSuffix(strings.TrimSpace(s), "%")
	if s == "" || s == "--" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseMemUsage parses strings like "243MiB / 512MiB" or "1.2GiB / 7.7GiB"
// into (used, limit) byte counts. Returns (0, 0) on any error.
func parseMemUsage(s string) (uint64, uint64) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0
	}
	return parseSize(parts[0]), parseSize(parts[1])
}

// parseSize parses a docker-formatted size like "243MiB", "1.2GiB", "512kB".
// docker uses both binary (KiB/MiB/GiB) and decimal (kB/MB/GB) units depending
// on context; we handle both.
func parseSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// Find boundary between number and unit.
	var i int
	for i < len(s) {
		c := s[i]
		if (c >= '0' && c <= '9') || c == '.' {
			i++
			continue
		}
		break
	}
	if i == 0 {
		return 0
	}

	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0
	}
	unit := strings.TrimSpace(s[i:])

	var mult float64 = 1
	switch unit {
	case "B", "":
		mult = 1
	case "kB":
		mult = 1e3
	case "KB", "KiB":
		mult = 1024
	case "MB":
		mult = 1e6
	case "MiB":
		mult = 1024 * 1024
	case "GB":
		mult = 1e9
	case "GiB":
		mult = 1024 * 1024 * 1024
	case "TB":
		mult = 1e12
	case "TiB":
		mult = 1024 * 1024 * 1024 * 1024
	default:
		return 0
	}
	return uint64(num * mult)
}
