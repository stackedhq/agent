package heartbeat

import (
	"bufio"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// diskBreakdownInterval is the minimum gap between disk-breakdown
// collections. `du -sb` on a multi-GB Postgres volume spikes I/O, and
// `docker system df` walks the full image graph; running both every
// heartbeat (30s) is wasteful because disk usage changes on the order
// of minutes, not seconds. We refresh on a 5-minute cadence and reuse
// the cached snapshot in between — the SSE update on the next true
// refresh still keeps the UI live, just less frequently.
const diskBreakdownInterval = 5 * time.Minute

var (
	diskBreakdownMu       sync.Mutex
	diskBreakdownLastAtNs atomic.Int64 // unix nanos
	diskBreakdownCache    *client.DiskBreakdown
)

// cachedDiskBreakdown returns the last disk breakdown if it's still
// within the refresh window, otherwise runs a fresh collection. Safe
// to call from the heartbeat goroutine — the mutex ensures only one
// collection runs at a time even if heartbeats overlap (they don't
// today, but future cadence changes shouldn't introduce a data race).
func cachedDiskBreakdown() *client.DiskBreakdown {
	now := time.Now().UnixNano()
	last := diskBreakdownLastAtNs.Load()
	if last != 0 && now-last < int64(diskBreakdownInterval) {
		diskBreakdownMu.Lock()
		defer diskBreakdownMu.Unlock()
		return diskBreakdownCache
	}
	diskBreakdownMu.Lock()
	defer diskBreakdownMu.Unlock()
	// Re-check inside the lock: a sibling caller may have refreshed
	// while we were waiting for the mutex.
	last = diskBreakdownLastAtNs.Load()
	if last != 0 && time.Now().UnixNano()-last < int64(diskBreakdownInterval) {
		return diskBreakdownCache
	}
	diskBreakdownCache = collectDiskBreakdown()
	diskBreakdownLastAtNs.Store(time.Now().UnixNano())
	return diskBreakdownCache
}

// Version is set at build time via ldflags. Defaults to "dev" for local builds.
var Version = "dev"

// systemInfo holds static machine info collected once at startup.
type systemInfo struct {
	CPUCores int
	MemoryMb int
	DiskGb   int
	OS       string
	Arch     string
	Hostname string
}

var sysInfo systemInfo

func init() {
	sysInfo = collectSystemInfo()
}

// Loop sends heartbeats at the given interval until the stop channel is closed.
func Loop(c *client.Client, interval time.Duration, stop <-chan struct{}) {
	// Send one immediately on startup
	send(c)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			send(c)
		case <-stop:
			return
		}
	}
}

func send(c *client.Client) {
	cpu := cpuUsage()
	mem := memoryUsage()
	disk := diskUsage()

	req := &client.HeartbeatRequest{
		AgentVersion: Version,
		CPUUsage:     cpu,
		MemoryUsage:  mem,
		DiskUsage:    disk,
		CPUCores:     sysInfo.CPUCores,
		MemoryMb:     sysInfo.MemoryMb,
		DiskGb:       sysInfo.DiskGb,
		OS:           sysInfo.OS,
		Arch:         sysInfo.Arch,
		Hostname:     sysInfo.Hostname,
		Containers:   collectContainers(),
		// Optional. Returns nil if the tailscale binary isn't
		// installed or the daemon errored — the field is then
		// omitted from the JSON wire payload (omitempty) so the
		// server treats this machine as "no tailscale activity to
		// report" and leaves its tailscale_* columns alone.
		Tailscale: collectTailscaleStatus(),
		// "What's eating my box" sections. Each collector returns
		// nil on any error / missing tool, and `omitempty` then drops
		// the field from the wire payload — the server preserves
		// whatever the last good heartbeat wrote for that section.
		OtherContainers:      collectOtherContainers(),
		TopProcessesByCPU:    collectTopProcessesByCPU(),
		TopProcessesByMemory: collectTopProcessesByMemory(),
		DiskBreakdown:        cachedDiskBreakdown(),
	}

	if err := c.Heartbeat(req); err != nil {
		log.Printf("Heartbeat failed: %v", err)
	}
}

func collectSystemInfo() systemInfo {
	info := systemInfo{
		CPUCores: runtime.NumCPU(),
		Arch:     runtime.GOARCH,
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// Total memory from /proc/meminfo (MemTotal in kB)
	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				kB := parseMemInfoValue(line)
				info.MemoryMb = int(kB / 1024)
				break
			}
		}
		f.Close()
	}

	// Total disk from statfs
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		totalBytes := stat.Blocks * uint64(stat.Bsize)
		info.DiskGb = int(totalBytes / (1024 * 1024 * 1024))
	}

	// OS from /etc/os-release
	if f, err := os.Open("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.TrimPrefix(line, "PRETTY_NAME=")
				val = strings.Trim(val, "\"")
				info.OS = val
				break
			}
		}
		f.Close()
	}

	return info
}

// cpuUsage reads /proc/stat and computes a rough CPU usage percentage.
// It takes two samples 500ms apart to calculate the delta.
func cpuUsage() float64 {
	idle1, total1 := readCPUStat()
	time.Sleep(500 * time.Millisecond)
	idle2, total2 := readCPUStat()

	// Guard against unsigned underflow. /proc/stat counters are normally
	// monotonic, but a CPU going offline / hotplug / kernel quirk could
	// theoretically reset them between samples. Cheap to defend against.
	if idle2 < idle1 || total2 < total1 {
		return 0
	}
	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)
	if totalDelta == 0 {
		return 0
	}
	return clampPercent((1.0 - idleDelta/totalDelta) * 100.0)
}

func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, 0
		}
		for i := 1; i < len(fields); i++ {
			val, _ := strconv.ParseUint(fields[i], 10, 64)
			total += val
			if i == 4 { // idle is the 4th value (index 4)
				idle = val
			}
		}
		break
	}
	return
}

// AvailableMemoryMB reads MemAvailable from /proc/meminfo and returns it
// in megabytes. Returns 0 if the file is unreadable or the field is
// missing (non-Linux hosts, exotic kernels). Used by the rolling-deploy
// executor for the pre-flight memory-headroom check: starting a second
// container alongside the live one needs roughly 2× the service's
// memory limit to fit, and a 1 GB VPS should fail the deploy fast
// rather than OOM-killing the host.
func AvailableMemoryMB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			// parseMemInfoValue returns kB; convert to MB.
			return parseMemInfoValue(line) / 1024
		}
	}
	return 0
}

// memoryUsage reads /proc/meminfo and returns used memory as a percentage.
func memoryUsage() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseMemInfoValue(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable = parseMemInfoValue(line)
		}
		if memTotal > 0 && memAvailable > 0 {
			break
		}
	}

	if memTotal == 0 {
		return 0
	}
	// Guard against unsigned underflow. MemAvailable is a kernel estimate
	// that can rarely exceed MemTotal under memory-pressure / accounting
	// quirks (observed on Oracle Linux 9.6 / arm64). Without this check the
	// uint64 subtraction wraps to ~2^64, producing percentages on the order
	// of 1e13 which overflowed the server's numeric(5,2) column and 500'd
	// every heartbeat.
	if memAvailable >= memTotal {
		return 0
	}
	used := memTotal - memAvailable
	return clampPercent(float64(used) / float64(memTotal) * 100.0)
}

func parseMemInfoValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	val, _ := strconv.ParseUint(fields[1], 10, 64)
	return val
}

// diskUsage uses syscall.Statfs to get disk usage for /.
func diskUsage() float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0
	}
	// Guard against unsigned underflow. Bfree should never exceed Blocks on
	// a real filesystem; defend symmetrically with the other percent fns.
	if free >= total {
		return 0
	}
	used := total - free
	return clampPercent(float64(used) / float64(total) * 100.0)
}
