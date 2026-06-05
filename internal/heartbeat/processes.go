package heartbeat

import (
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const topProcessesN = 5

// collectTopProcessesByCPU returns the top-N processes on the host
// sorted by %CPU, as reported by `ps -eo`. PIDs are deliberately
// omitted from the wire payload \u2014 we surface the command name only.
// See client.ProcessStat for why.
//
// Errors degrade to a nil slice (which the JSON encoder omits): a host
// without `ps` is unusual but legal on minimal containers, and a
// missing section is better than a failed heartbeat.
func collectTopProcessesByCPU() []client.ProcessStat {
	return collectTopProcesses("-%cpu")
}

// collectTopProcessesByMemory mirrors the above but sorts by %MEM. Two
// separate `ps` calls is the simplest correct shape; merging into one
// call and sorting in Go would also work but invites accidental
// double-counting if `ps` emits the same row in both lists. Cheap
// either way \u2014 `ps` is microseconds.
func collectTopProcessesByMemory() []client.ProcessStat {
	return collectTopProcesses("-%mem")
}

func collectTopProcesses(sortKey string) []client.ProcessStat {
	// `ps -eo comm,%cpu,%mem --sort=<key>` lists every process on the
	// host sorted by the given key. We post-filter to top-N rather
	// than rely on `ps`'s implementation-specific limit flags.
	//
	// `comm` (not `cmd`) is the kernel-truncated 15-char process name;
	// it's the right field for "what's running" without dragging in
	// the full argv (which can leak secrets passed on the command
	// line, e.g. `node app.js --token=<secret>`).
	cmd := exec.Command(
		"ps", "-eo", "comm:64,%cpu,%mem", "--sort", sortKey,
		"--no-headers",
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("ps failed (%s): %v", sortKey, err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return nil
	}

	rows := make([]client.ProcessStat, 0, topProcessesN)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// `comm:64` gives us up to a 64-char left-padded column, then
		// the two percentages. `strings.Fields` collapses runs of
		// whitespace, so a command name with embedded spaces would
		// break the parse. `comm` is the kernel-supplied basename and
		// cannot contain spaces, so this is safe in practice.
		cpu, err1 := strconv.ParseFloat(fields[len(fields)-2], 64)
		mem, err2 := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		command := strings.Join(fields[:len(fields)-2], " ")
		// Skip kernel threads in square brackets like `[kworker/0:1]`.
		// They never explain user-visible CPU/memory issues and they
		// dominate the sorted output on idle hosts, pushing the
		// actually-interesting workload off the top-N list.
		if strings.HasPrefix(command, "[") &&
			strings.HasSuffix(command, "]") {
			continue
		}
		// Skip the row representing `ps` itself, which is always near
		// the top of a sort-by-CPU since it just woke up.
		if command == "ps" {
			continue
		}
		rows = append(rows, client.ProcessStat{
			Command:       command,
			CPUPercent:    clampPercent(cpu),
			MemoryPercent: clampPercent(mem),
		})
		if len(rows) >= topProcessesN {
			break
		}
	}
	return rows
}
