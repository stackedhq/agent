package heartbeat

import (
	"bufio"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const Version = "0.3.0"

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

	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)
	if totalDelta == 0 {
		return 0
	}
	return (1.0 - idleDelta/totalDelta) * 100.0
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
	used := memTotal - memAvailable
	return float64(used) / float64(memTotal) * 100.0
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
	used := total - free
	return float64(used) / float64(total) * 100.0
}
