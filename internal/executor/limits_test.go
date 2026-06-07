package executor

import (
	"strings"
	"testing"
)

func TestResourceLimitsFromPayload(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		want    resourceLimits
	}{
		{
			name:    "empty payload defaults to unless-stopped, no caps",
			payload: map[string]interface{}{},
			want:    resourceLimits{cpuMillicores: 0, memoryMB: 0, restartPolicy: "unless-stopped"},
		},
		{
			// JSON numbers decode as float64 — mirror the real payload.
			name: "full payload",
			payload: map[string]interface{}{
				"cpuLimit":      float64(1500),
				"memoryLimitMb": float64(512),
				"restartPolicy": "on-failure",
			},
			want: resourceLimits{cpuMillicores: 1500, memoryMB: 512, restartPolicy: "on-failure"},
		},
		{
			name:    "blank restart policy falls back",
			payload: map[string]interface{}{"restartPolicy": ""},
			want:    resourceLimits{cpuMillicores: 0, memoryMB: 0, restartPolicy: "unless-stopped"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resourceLimitsFromPayload(c.payload)
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestResourceLimitsCPUs(t *testing.T) {
	cases := []struct {
		milli int
		want  string
	}{
		{0, ""},
		{-100, ""},
		{1000, "1"},
		{1500, "1.5"},
		{250, "0.25"},
		{100, "0.1"},
	}
	for _, c := range cases {
		if got := (resourceLimits{cpuMillicores: c.milli}).cpus(); got != c.want {
			t.Errorf("cpus(%d) = %q, want %q", c.milli, got, c.want)
		}
	}
}

func TestGenerateCompose_AppliesLimits(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", nil, resourceLimits{
		cpuMillicores: 1500,
		memoryMB:      512,
		restartPolicy: "always",
	})
	for _, want := range []string{
		"restart: always",
		"mem_limit: 512m",
		"cpus: 1.5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

func TestGenerateCompose_OmitsUnsetLimits(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", nil, resourceLimits{
		restartPolicy: "unless-stopped",
	})
	if strings.Contains(out, "mem_limit") {
		t.Errorf("expected no mem_limit when unset:\n%s", out)
	}
	if strings.Contains(out, "cpus:") {
		t.Errorf("expected no cpus when unset:\n%s", out)
	}
	if !strings.Contains(out, "restart: unless-stopped") {
		t.Errorf("expected restart policy line:\n%s", out)
	}
}
