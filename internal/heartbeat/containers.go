package heartbeat

import (
	"encoding/json"
	"log"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/slots"
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
	slot      string
}

func listStackedContainers() []containerRow {
	// We only want Stacked-managed service containers, identified by
	// the `com.stacked.kind=service` label that the deploy executor
	// writes on every container it creates (both recreate-mode
	// compose templates and rolling-mode `docker run`). The
	// historical "no kind label = treat as service" back-compat path
	// was removed because it swept up unrelated docker-compose
	// projects the user runs on the same host (e.g. their own side
	// projects) and the Caddy proxy itself, polluting heartbeat
	// payloads with bogus serviceIds.
	//
	// Tab-separated to avoid issues with image names containing
	// spaces. The docker-side label filter shortcuts the common case;
	// the parser-side check below is defence in depth.
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--filter", "label=com.stacked.kind=service",
		"--format", `{{.ID}}	{{.Label "com.docker.compose.project"}}	{{.State}}	{{.Label "com.stacked.kind"}}	{{.Label "com.stacked.slot"}}`,
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
		if len(parts) < 4 {
			continue
		}
		if parts[3] != "service" {
			// Should be redundant given the docker-side filter,
			// but cheap to verify and avoids reporting bogus rows
			// if docker ever loosens label-filter semantics.
			continue
		}
		slot := ""
		if len(parts) >= 5 {
			slot = parts[4]
		}
		rows = append(rows, containerRow{
			id:        parts[0],
			serviceID: parts[1],
			state:     parts[2],
			slot:      slot,
		})
	}
	return filterActiveSlot(rows)
}

// filterActiveSlot mirrors the same-named helper in runtimelogs/manager.go.
// Kept package-local to avoid pulling a shared dependency just for this
// 20-line filter; the duplication is small and the rule is unlikely to
// drift since both consumers must agree on which slot's metrics / logs
// to surface.
func filterActiveSlot(rows []containerRow) []containerRow {
	if len(rows) == 0 {
		return rows
	}
	state := slots.All()
	if len(state) == 0 {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		active, ok := state[r.serviceID]
		if !ok {
			out = append(out, r)
			continue
		}
		if r.slot == "" {
			if string(active) == "legacy" {
				out = append(out, r)
			}
			continue
		}
		if r.slot == string(active) {
			out = append(out, r)
		}
	}
	return out
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

// collectOtherContainers enumerates Docker containers on this host that
// are *not* managed by Stacked, and returns their current `docker stats`
// snapshot.
//
// "Not managed by Stacked" means: no `com.stacked.kind=service` label.
// That's the same label `listStackedContainers` filters *in* on, so the
// two collectors are complementary by construction — every container
// the host runs is either reported under `containers` (Stacked
// services) or `otherContainers` (everything else), never both.
//
// The list is capped (sorted by CPU desc, truncated to TOP_N) so a box
// running 200 random containers can't push an arbitrarily large JSONB
// blob through the heartbeat.
func collectOtherContainers() []client.OtherContainer {
	const topN = 10
	rows := listOtherContainers()
	if len(rows) == 0 {
		return nil
	}

	statsByID := dockerStats(otherContainerIDs(rows))
	out := make([]client.OtherContainer, 0, len(rows))
	for _, r := range rows {
		c := client.OtherContainer{
			ID:    r.id,
			Name:  r.name,
			Image: r.image,
			State: r.state,
		}
		if s, ok := statsByID[r.id]; ok {
			c.CPUPercent = clampPercent(s.cpuPercent)
			c.MemoryPercent = clampPercent(s.memPercent)
			c.MemoryBytes = s.memBytes
		}
		out = append(out, c)
	}

	// Sort by CPU desc so the top-N truncation keeps the most
	// interesting rows. Memory-heavy idle containers still surface
	// further down because we cap at 10, which is comfortably above
	// the active-container count on a typical solo-founder VPS.
	sort.Slice(out, func(i, j int) bool {
		return out[i].CPUPercent > out[j].CPUPercent
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

type otherContainerRow struct {
	id    string
	name  string
	image string
	state string
}

func listOtherContainers() []otherContainerRow {
	// Tab-separated to avoid issues with image names containing
	// spaces. We can't use a docker-side `label!=` filter for an
	// arbitrary key, so we pull every container and filter
	// agent-side. Cheap on the typical 10–20 container host.
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--format", `{{.ID}}	{{.Names}}	{{.Image}}	{{.State}}	{{.Label "com.stacked.kind"}}`,
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("docker ps (other) failed: %v", err)
		return nil
	}

	var rows []otherContainerRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		// Skip Stacked-managed service containers — they're already
		// reported under `containers` and serve as the basis for
		// per-service metrics in the UI. Anything without the
		// `com.stacked.kind=service` label is considered "other":
		// the user's own compose projects, the Caddy proxy
		// container itself, ad-hoc `docker run` invocations.
		kind := ""
		if len(parts) >= 5 {
			kind = parts[4]
		}
		if kind == "service" {
			continue
		}
		rows = append(rows, otherContainerRow{
			id:    shortID(parts[0]),
			name:  parts[1],
			image: parts[2],
			state: parts[3],
		})
	}
	return rows
}

func otherContainerIDs(rows []otherContainerRow) []string {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.id)
	}
	return ids
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
