package executor

import (
	"strings"
	"testing"
)

func TestParseVolumes_EmptyOrMissing(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
	}{
		{"nil payload field", map[string]interface{}{}},
		{"explicit nil", map[string]interface{}{"volumes": nil}},
		{"empty slice", map[string]interface{}{"volumes": []interface{}{}}},
		{"wrong type (string)", map[string]interface{}{"volumes": "nope"}},
		{"wrong type (map)", map[string]interface{}{"volumes": map[string]interface{}{"a": 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseVolumes(c.payload)
			if len(got) != 0 {
				t.Fatalf("expected empty mounts, got %d", len(got))
			}
		})
	}
}

func TestParseVolumes_HappyPath(t *testing.T) {
	payload := map[string]interface{}{
		"volumes": []interface{}{
			map[string]interface{}{
				"hostPath":      "/data/b",
				"containerPath": "/b",
				"readOnly":      true,
			},
			map[string]interface{}{
				"hostPath":      "/data/a",
				"containerPath": "/a",
			},
		},
	}
	got := parseVolumes(payload)
	if len(got) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(got))
	}
	// Sorted by container path: /a before /b.
	if got[0].ContainerPath != "/a" || got[1].ContainerPath != "/b" {
		t.Fatalf("mounts not sorted by container path: %+v", got)
	}
	if got[0].ReadOnly || !got[1].ReadOnly {
		t.Fatalf("readOnly not preserved: %+v", got)
	}
}

func TestParseVolumes_SkipsMalformedEntries(t *testing.T) {
	payload := map[string]interface{}{
		"volumes": []interface{}{
			map[string]interface{}{
				"hostPath":      "/ok",
				"containerPath": "/ok",
			},
			"not an object",
			map[string]interface{}{
				"hostPath": "/missing-container",
			},
			map[string]interface{}{
				"containerPath": "/missing-host",
			},
			map[string]interface{}{
				"hostPath":      "",
				"containerPath": "/empty-host",
			},
		},
	}
	got := parseVolumes(payload)
	if len(got) != 1 {
		t.Fatalf("expected 1 valid mount, got %d: %+v", len(got), got)
	}
	if got[0].HostPath != "/ok" || got[0].ContainerPath != "/ok" {
		t.Fatalf("wrong surviving mount: %+v", got[0])
	}
}

func TestRenderComposeVolumes_Empty(t *testing.T) {
	if out := renderComposeVolumes(nil); out != "" {
		t.Fatalf("expected empty string for nil, got %q", out)
	}
	if out := renderComposeVolumes([]volumeMount{}); out != "" {
		t.Fatalf("expected empty string for empty slice, got %q", out)
	}
}

func TestRenderComposeVolumes_RW(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/host/a", ContainerPath: "/c/a"},
	})
	want := "    volumes:\n      - /host/a:/c/a\n"
	if out != want {
		t.Fatalf("mismatch:\ngot:  %q\nwant: %q", out, want)
	}
}

func TestRenderComposeVolumes_RO(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/host/a", ContainerPath: "/c/a", ReadOnly: true},
	})
	if !strings.Contains(out, ":/c/a:ro\n") {
		t.Fatalf("expected :ro suffix in output, got %q", out)
	}
}

func TestRenderComposeVolumes_Multiple(t *testing.T) {
	out := renderComposeVolumes([]volumeMount{
		{HostPath: "/h1", ContainerPath: "/c1"},
		{HostPath: "/h2", ContainerPath: "/c2", ReadOnly: true},
	})
	want := "    volumes:\n      - /h1:/c1\n      - /h2:/c2:ro\n"
	if out != want {
		t.Fatalf("mismatch:\ngot:  %q\nwant: %q", out, want)
	}
}

func TestGenerateCompose_NoVolumes_OmitsBlock(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", nil)
	if strings.Contains(out, "volumes:") {
		t.Fatalf("expected no volumes: block when mounts is nil, got:\n%s", out)
	}
	// Sanity-check the structural bits we rely on.
	if !strings.Contains(out, "container_name: svc-1") {
		t.Fatalf("missing container_name in compose:\n%s", out)
	}
	if !strings.Contains(out, "image: img:latest") {
		t.Fatalf("missing image line in compose:\n%s", out)
	}
}

func TestGenerateCompose_WithVolumes_IncludesBlock(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", []volumeMount{
		{HostPath: "/host", ContainerPath: "/container"},
	})
	if !strings.Contains(out, "    volumes:\n      - /host:/container\n") {
		t.Fatalf("expected volumes block in compose, got:\n%s", out)
	}
}
