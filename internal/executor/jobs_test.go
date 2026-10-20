package executor

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/logs"
)

func TestCronJobTimeout(t *testing.T) {
	cases := []struct {
		payload map[string]interface{}
		want    time.Duration
	}{
		{map[string]interface{}{}, time.Hour},
		{map[string]interface{}{"timeoutSeconds": float64(0)}, time.Hour},
		{map[string]interface{}{"timeoutSeconds": float64(-5)}, time.Hour},
		{map[string]interface{}{"timeoutSeconds": "600"}, time.Hour},
		{map[string]interface{}{"timeoutSeconds": float64(600)}, 10 * time.Minute},
		{map[string]interface{}{"timeoutSeconds": float64(7 * 24 * 3600)}, 24 * time.Hour},
	}
	for _, c := range cases {
		if got := CronJobTimeout(c.payload); got != c.want {
			t.Fatalf("CronJobTimeout(%v) = %s, want %s", c.payload, got, c.want)
		}
	}
}

func TestJobLabelArgsOverrideInheritedLabels(t *testing.T) {
	got := strings.Join(jobLabelArgs("cron"), " ")
	for _, want := range []string{
		"--label com.stacked.kind=job",
		"--label com.stacked.job=cron",
		"--label com.docker.compose.project=",
		"--label com.docker.compose.service=",
		"--label com.stacked.slot=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}

func TestJobResourceArgs(t *testing.T) {
	if got := strings.Join(jobResourceArgs(map[string]interface{}{}, defaultCronMemoryMB), " "); got != "--memory=512m --cpus=1" {
		t.Fatalf("cron defaults = %q", got)
	}
	if got := strings.Join(jobResourceArgs(map[string]interface{}{}, defaultReleaseMemoryMB), " "); got != "--memory=1024m --cpus=1" {
		t.Fatalf("release defaults = %q", got)
	}
	got := strings.Join(jobResourceArgs(map[string]interface{}{"cpuLimit": float64(2500), "memoryLimitMb": float64(2048)}, defaultCronMemoryMB), " ")
	if got != "--memory=2048m --cpus=2.5" {
		t.Fatalf("service limits = %q", got)
	}
	got = strings.Join(jobResourceArgs(map[string]interface{}{"memoryLimitMb": float64(256)}, defaultReleaseMemoryMB), " ")
	if got != "--memory=256m --cpus=1" {
		t.Fatalf("partial limits = %q", got)
	}
	// Zero / negative values mean "unset" and fall back to the default.
	got = strings.Join(jobResourceArgs(map[string]interface{}{"cpuLimit": float64(0), "memoryLimitMb": float64(-1)}, defaultCronMemoryMB), " ")
	if got != "--memory=512m --cpus=1" {
		t.Fatalf("non-positive limits = %q", got)
	}
}

// A job that outlives its timeout is stopped with `docker kill` (killing
// the CLI alone would leave the container running).
func TestDockerJobContainerTimeoutKillsContainer(t *testing.T) {
	requireDocker(t)
	name := "stk-test-job-" + randSuffix(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() })
	args := []string{"run", "--rm", "--name", name}
	args = append(args, jobLabelArgs("cron")...)
	args = append(args, jobResourceArgs(nil, defaultCronMemoryMB)...)
	args = append(args, "alpine:3", "sh", "-c", "echo started; sleep 120")

	start := time.Now()
	err := runJobContainer(logs.NewStreamer(nil, "op"), "", nil, name, 3*time.Second, args)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 40*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := exec.Command("docker", "ps", "-a", "-q", "--filter", "name=^"+name+"$").Output()
		if strings.TrimSpace(string(out)) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job container still present after timeout")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func TestDockerJobContainerLabels(t *testing.T) {
	requireDocker(t)
	name := "stk-test-job-" + randSuffix(t)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() })
	// An image (here: run-time labels standing in for image LABELs) that
	// claims to be a Stacked service must end up labelled as a job.
	args := []string{"run", "--rm", "--name", name,
		"--label", "com.stacked.kind=service", "--label", "com.docker.compose.project=../../etc"}
	args = append(args, jobLabelArgs("release")...)
	args = append(args, "alpine:3", "sleep", "20")
	go func() { _ = runJobContainer(logs.NewStreamer(nil, "op"), "", nil, name, 30*time.Second, args) }()
	var out []byte
	for i := 0; i < 40; i++ {
		var err error
		out, err = exec.Command("docker", "inspect", "-f", `{{index .Config.Labels "com.stacked.kind"}}|{{index .Config.Labels "com.docker.compose.project"}}`, name).Output()
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if strings.TrimSpace(string(out)) != "job|" {
		t.Fatalf("labels = %q", out)
	}
}
