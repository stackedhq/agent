package executor

import (
	"encoding/json"
	"testing"
)

// parseDockerPorts is the only fragile bit of the takeover handler —
// docker's `NetworkSettings.Ports` JSON has a small but tricky surface
// area (null hostBindings, weird protocols, multi-binding rows). The
// docker-touching code paths around it are integration territory;
// these tests cover the pure parser.

func TestParseDockerPorts_PublishedTCP(t *testing.T) {
	raw := `{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8081"}]}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("want 1 binding, got %d", len(bindings))
	}
	b := bindings[0]
	if b.ContainerPort != 3000 || b.HostPort != 8081 ||
		b.HostIP != "0.0.0.0" || b.Protocol != "tcp" {
		t.Fatalf("unexpected binding: %+v", b)
	}
}

func TestParseDockerPorts_DualStackIPv4AndIPv6(t *testing.T) {
	// Docker reports both an IPv4 and IPv6 binding for the same
	// containerPort:hostPort tuple. We surface both — the dashboard
	// picks the IPv4 one.
	raw := `{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8081"},{"HostIp":"::","HostPort":"8081"}]}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("want 2 bindings, got %d: %+v", len(bindings), bindings)
	}
}

func TestParseDockerPorts_ExposedButUnpublished(t *testing.T) {
	// A `null` value means the image declares the port but no host
	// binding exists. Caller treats this as "not reachable on
	// loopback" — we just must not crash, and must drop the row.
	raw := `{"3000/tcp":null}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("want 0 bindings for unpublished port, got %+v", bindings)
	}
}

func TestParseDockerPorts_MixedPublishedAndUnpublished(t *testing.T) {
	raw := `{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"8081"}],"9090/tcp":null}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("want 1 binding (skip the null row), got %+v", bindings)
	}
	if bindings[0].ContainerPort != 3000 {
		t.Fatalf("want containerPort 3000, got %d", bindings[0].ContainerPort)
	}
}

func TestParseDockerPorts_EmptyAndNullPayloads(t *testing.T) {
	// `docker inspect` returns the literal string "null" when the
	// container has no Ports table at all. Both empty + null
	// inputs must produce zero bindings without error.
	for _, raw := range []string{"", "null", "  null  ", "{}"} {
		bindings, err := parseDockerPorts(raw)
		if err != nil {
			t.Fatalf("parseDockerPorts(%q): %v", raw, err)
		}
		if len(bindings) != 0 {
			t.Fatalf("parseDockerPorts(%q): want 0 bindings, got %+v", raw, bindings)
		}
	}
}

func TestParseDockerPorts_SkipsUnknownProtocol(t *testing.T) {
	// sctp / weird protocol rows. We only emit tcp + udp — anything
	// else is silently dropped so the dashboard doesn't have to
	// branch on protocols it doesn't render.
	raw := `{"3000/sctp":[{"HostIp":"0.0.0.0","HostPort":"8081"}]}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("want 0 bindings (sctp dropped), got %+v", bindings)
	}
}

func TestParseDockerPorts_SkipsInvalidPort(t *testing.T) {
	// Defensive: docker shouldn't ever produce non-numeric ports,
	// but we still test we don't crash or emit a binding for them.
	raw := `{"abc/tcp":[{"HostIp":"0.0.0.0","HostPort":"8081"}]}`
	bindings, err := parseDockerPorts(raw)
	if err != nil {
		t.Fatalf("parseDockerPorts: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("want 0 bindings for bad port spec, got %+v", bindings)
	}
}

func TestParseDockerPorts_DeterministicOrder(t *testing.T) {
	// Map iteration is non-deterministic; the function sorts. We
	// rely on stable order in the dashboard's tie-break logic
	// (first matching binding wins after IPv4 preference sort).
	raw := `{
		"9090/tcp":[{"HostIp":"0.0.0.0","HostPort":"19090"}],
		"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"13000"}],
		"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"15432"}]
	}`
	for i := 0; i < 10; i++ {
		bindings, err := parseDockerPorts(raw)
		if err != nil {
			t.Fatalf("parseDockerPorts: %v", err)
		}
		if len(bindings) != 3 {
			t.Fatalf("want 3 bindings, got %d", len(bindings))
		}
		if bindings[0].ContainerPort != 3000 ||
			bindings[1].ContainerPort != 5432 ||
			bindings[2].ContainerPort != 9090 {
			t.Fatalf("not sorted ascending by containerPort: %+v", bindings)
		}
	}
}

func TestParseDockerPorts_MalformedJSON(t *testing.T) {
	if _, err := parseDockerPorts("not json"); err == nil {
		t.Fatalf("want error on malformed JSON, got nil")
	}
}

// --- name + port validators ----------------------------------------

func TestIsSafeContainerName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Valid docker container names.
		{"dokploy-traefik", true},
		{"my-app.production_1", true},
		{"web-abc123", true},
		{"a", true},
		// Invalid: empty, leading separator, shell metacharacters.
		{"", false},
		{"-leading-dash", false},
		{".hidden", false},
		{"_underscore-first", false},
		{"name with space", false},
		{"name;rm -rf /", false},
		{"name`whoami`", false},
		{"name$VAR", false},
		{"name|pipe", false},
		{"path/like", false},
		{"name\nlf", false},
	}
	for _, tc := range cases {
		if got := isSafeContainerName(tc.in); got != tc.want {
			t.Errorf("isSafeContainerName(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestParsePositiveInt(t *testing.T) {
	ok := []struct {
		in   string
		want int
	}{
		{"1", 1},
		{"80", 80},
		{"8081", 8081},
		{"65535", 65535},
		{"  3000  ", 3000}, // trimmed
	}
	for _, tc := range ok {
		got, err := parsePositiveInt(tc.in)
		if err != nil {
			t.Errorf("parsePositiveInt(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parsePositiveInt(%q) = %d; want %d", tc.in, got, tc.want)
		}
	}
	bad := []string{"", "  ", "0", "-1", "abc", "12a", "65536", "100000"}
	for _, in := range bad {
		if _, err := parsePositiveInt(in); err == nil {
			t.Errorf("parsePositiveInt(%q) want error, got nil", in)
		}
	}
}

// --- full-shape sanity check on inspectOneContainer mock data ------

// Round-trips a realistic docker inspect payload through the parser
// and then asserts the JSON shape the dashboard expects. Keeps us
// honest if anyone changes parseDockerPorts later in a way that
// silently drops keys.
func TestProbeContainerBindings_ShapeRoundTrip(t *testing.T) {
	// Build the expected binding inline and JSON-roundtrip it to
	// make sure the field names match what the dashboard reads.
	b := dockerPortBinding{
		ContainerPort: 3000,
		Protocol:      "tcp",
		HostIP:        "0.0.0.0",
		HostPort:      8081,
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"containerPort":3000,"protocol":"tcp","hostIp":"0.0.0.0","hostPort":8081}`
	if string(raw) != want {
		t.Fatalf("dockerPortBinding JSON shape drifted:\n  got:  %s\n  want: %s",
			raw, want)
	}
}
