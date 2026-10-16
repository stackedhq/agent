package executor

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/compose_golden from the current renderer")

const goldenServiceID = "11111111-2222-4333-8444-555555555555"

// goldenEnv mirrors testdata/compose_legacy/service.env (what the old
// template loaded through `env_file: .env`).
var goldenEnv = map[string]string{
	"HOST":      "0.0.0.0",
	"NODE_ENV":  "production",
	"SMTP_FROM": "Riffado <noreply@riffado.com>",
	"HAS_HASH":  "a#b",
	"HAS_QUOTE": `has "quotes" inside`,
}

type goldenCase struct {
	name   string
	render func() (string, error)
	// legacy is the fixture rendered by the pre-YAML-emitter templates
	// (testdata/compose_legacy), for the docker-backed equivalence test.
	legacy string
	// ignore lists service keys that intentionally changed.
	ignore []string
}

func goldenCases() []goldenCase {
	svc := func(mounts []volumeMount, limits resourceLimits, aliases []string, cmd string) func() (string, error) {
		return func() (string, error) {
			return generateCompose(goldenServiceID, imageFor(limits), mounts, limits, aliases, cmd, goldenEnv), nil
		}
	}
	return []goldenCase{
		{
			name:   "service-min",
			render: svc(nil, resourceLimits{restartPolicy: "unless-stopped"}, nil, ""),
			legacy: "service-min.yml",
		},
		{
			name: "service-full",
			render: svc([]volumeMount{
				{HostPath: "/opt/stacked/data/services/" + goldenServiceID + "/data-abc123", ContainerPath: "/data"},
				{HostPath: "/srv/config", ContainerPath: "/etc/app", ReadOnly: true},
			}, resourceLimits{restartPolicy: "always", memoryMB: 512, cpuMillicores: 1500}, []string{"acme-api", "api"}, `node server.js --port 3000 && echo "done"`),
			legacy: "service-full.yml",
		},
		{
			name:   "service-restart-no",
			render: svc(nil, resourceLimits{restartPolicy: "no"}, nil, ""),
			legacy: "service-restart-no.yml",
		},
		{
			name: "db-postgres",
			render: func() (string, error) {
				return generateDatabaseCompose("postgres", 15432, "stk-db-pg", "postgres:16", map[string]string{"user": "app", "password": "pa ss:word", "dbName": "appdb"}, "public", "")
			},
			legacy: "db-postgres.yml",
		},
		{
			name: "db-mysql",
			render: func() (string, error) {
				return generateDatabaseCompose("mysql", 13306, "stk-db-my", "mysql:8", map[string]string{"user": "app", "password": "Xyz-123_abc", "dbName": "appdb", "rootPassword": "true"}, "tailnet", "100.64.0.5")
			},
			legacy: "db-mysql.yml",
		},
		{
			name: "db-mongo",
			render: func() (string, error) {
				return generateDatabaseCompose("mongo", 27018, "stk-db-mo", "mongo:7", map[string]string{"user": "app", "password": "p#w", "dbName": "appdb"}, "internal", "")
			},
			legacy: "db-mongo.yml",
		},
		{
			name: "db-redis",
			render: func() (string, error) {
				return generateDatabaseCompose("redis", 16379, "stk-db-rd", "redis:7-alpine", map[string]string{"password": "Xyz-123_abc"}, "public", "")
			},
			legacy: "db-redis.yml",
			// The password moved from `--requirepass` argv to env + a
			// config file written inside the container.
			ignore: []string{"command", "environment"},
		},
	}
}

func imageFor(limits resourceLimits) string {
	switch limits.restartPolicy {
	case "always":
		return "nginx:1.27-alpine"
	case "no":
		return "img:latest"
	}
	return "ghcr.io/acme/api:1.2.3"
}

// TestComposeGolden pins the exact rendered output for representative
// payloads. Run `go test ./internal/executor -run TestComposeGolden
// -update-golden` after an intentional template change and review the diff.
func TestComposeGolden(t *testing.T) {
	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			path := filepath.Join("testdata", "compose_golden", c.name+".yml")
			if *updateGolden {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got != string(want) {
				t.Fatalf("compose output changed for %s:\n--- got\n%s\n--- want\n%s", c.name, got, want)
			}
		})
	}
}

// TestComposeScalarsAreAlwaysQuoted checks the structural guarantee: every
// value line in the rendered compose is a quoted scalar, a known agent
// literal, or a bare key, whatever the payload contains.
func TestComposeScalarsAreAlwaysQuoted(t *testing.T) {
	hostile := "x\n  privileged: true\nlabels: {a: b} # ${HOME} $(id) `id` \\ \" '"
	out := generateCompose(goldenServiceID, "img:latest",
		[]volumeMount{{HostPath: "/srv/a", ContainerPath: "/data"}},
		resourceLimits{restartPolicy: "unless-stopped", memoryMB: 64, cpuMillicores: 250},
		[]string{"api"}, hostile, map[string]string{"EVIL": hostile, "HOST": "0.0.0.0"})
	if strings.Contains(out, "\n  privileged") || strings.Contains(out, "privileged: true\n") {
		t.Fatalf("hostile value escaped its scalar:\n%s", out)
	}
	if strings.Contains(strings.ReplaceAll(out, "$$", ""), "$") {
		t.Fatalf("`$` must be escaped as `$$`:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasSuffix(trimmed, ":") {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			if !strings.HasPrefix(trimmed, `- "`) {
				t.Errorf("unquoted list item: %q", line)
			}
			continue
		}
		_, value, ok := strings.Cut(trimmed, ": ")
		if !ok {
			t.Errorf("unexpected line: %q", line)
			continue
		}
		switch value {
		case "true", "0.25":
			continue
		}
		if !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
			t.Errorf("unquoted scalar: %q", line)
		}
	}
}

func TestComposeQuote(t *testing.T) {
	cases := map[string]string{
		"plain":        `"plain"`,
		"a$b":          `"a$$b"`,
		"$$":           `"$$$$"`,
		"${X:-y}":      `"$${X:-y}"`,
		"line1\nline2": `"line1\nline2"`,
		`q"b\`:         `"q\"b\\"`,
		"<&>":          `"<&>"`,
		"tab\there":    `"tab\there"`,
	}
	for in, want := range cases {
		if got := composeQuote(in); got != want {
			t.Errorf("composeQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRenderYAMLKeysAndNull(t *testing.T) {
	out := renderYAML(yMap{
		{Key: "volumes", Value: yMap{{Key: "data", Value: yNull{}}}},
		{Key: "weird key", Value: yMap{}},
		{Key: "list", Value: yList{}},
	})
	want := "volumes:\n  data:\n\n\"weird key\": {}\n\nlist: []\n"
	if out != want {
		t.Fatalf("renderYAML =\n%q\nwant\n%q", out, want)
	}
}
