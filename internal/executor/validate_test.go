package executor

import (
	"strings"
	"testing"
)

func TestValidateOpIdentifiers(t *testing.T) {
	const id = "11111111-2222-4333-8444-555555555555"
	ok := []map[string]interface{}{
		{},
		{"serviceId": id},
		{"databaseId": id},
		{"serviceId": id, "databaseId": id},
		{"serviceId": ""}, // handlers report "requires serviceId"
		{"serviceId": nil},
		{"other": "../../etc"},
	}
	for _, p := range ok {
		if err := validateOpIdentifiers(p); err != nil {
			t.Errorf("validateOpIdentifiers(%v) = %v, want nil", p, err)
		}
	}
	bad := []map[string]interface{}{
		{"serviceId": "../../etc"},
		{"serviceId": "/"},
		{"serviceId": "."},
		{"serviceId": "svc-1"},
		{"serviceId": "AAAAAAAA-2222-4333-8444-555555555555"},
		{"serviceId": id + "/../x"},
		{"serviceId": " " + id},
		{"databaseId": "../services"},
		{"databaseId": 42.0},
		{"serviceId": id, "databaseId": "x"},
	}
	for _, p := range bad {
		if err := validateOpIdentifiers(p); err == nil {
			t.Errorf("validateOpIdentifiers(%v) = nil, want error", p)
		}
	}
}

func TestValidImageReference(t *testing.T) {
	good := []string{
		"nginx",
		"nginx:1.27-alpine",
		"library/nginx:latest",
		"ghcr.io/acme/api:1.2.3",
		"ghcr.io/acme/my_app__x.y-z:v1",
		"localhost:5000/app",
		"registry.example.com:443/team/app:tag_1.0",
		"redis:7-alpine",
		"postgres:16",
		"[::1]:5000/app:dev",
		"nginx@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/acme/api:1.2.3@sha256:" + strings.Repeat("0", 64),
		"stacked-11111111-2222-4333-8444-555555555555",
	}
	for _, s := range good {
		if !validImageReference(s) {
			t.Errorf("validImageReference(%q) = false, want true", s)
		}
	}
	bad := []string{
		"",
		"-v",
		"--privileged",
		"nginx latest",
		"nginx:latest\nservices:",
		"Nginx",
		"nginx:",
		"nginx:-tag",
		":tag",
		"nginx:" + strings.Repeat("a", 129),
		"nginx@sha256:short",
		"a//b",
		"a/b/",
		"$IMAGE",
		"nginx:${TAG}",
		"\"nginx\"",
		strings.Repeat("a", 256),
	}
	for _, s := range bad {
		if validImageReference(s) {
			t.Errorf("validImageReference(%q) = true, want false", s)
		}
	}
}

func TestValidateRestartPolicy(t *testing.T) {
	for _, s := range []string{"no", "always", "unless-stopped", "on-failure", "on-failure:5"} {
		if err := validateRestartPolicy(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "never", "always\n", "on-failure:", "on-failure:-1", "unless-stopped # x", "\"no\""} {
		if err := validateRestartPolicy(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidateContainerName(t *testing.T) {
	for _, s := range []string{"stk-db-pg", "postgres-x", "a", "A_b.c-1"} {
		if err := validateContainerName(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "-x", ".x", "a b", "a/b", "a:b", "a\nb", strings.Repeat("a", 129)} {
		if err := validateContainerName(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidDBVersion(t *testing.T) {
	for _, s := range []string{"16", "8.0", "7-alpine", "7.2.4", "latest"} {
		if !validDBVersion(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "16 ", "16\nx", "a:b", "../x", strings.Repeat("1", 65)} {
		if validDBVersion(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestNormalizeCommitSha(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"abc1234":               "abc1234",
		"ABC1234":               "abc1234",
		" deadbeefcafe ":        "deadbeefcafe",
		strings.Repeat("f", 40): strings.Repeat("f", 40),
	} {
		got, err := normalizeCommitSha(in)
		if err != nil || got != want {
			t.Errorf("normalizeCommitSha(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"abc123", "--orphan", "-b", "HEAD", "main", "abc1234^", "abc1234 --", strings.Repeat("a", 41), "g123456"} {
		if _, err := normalizeCommitSha(in); err == nil {
			t.Errorf("normalizeCommitSha(%q) accepted", in)
		}
	}
}

func TestValidGitBranch(t *testing.T) {
	for _, b := range []string{"main", "feature/x", "release-1.2", "user/name/topic", "v1.0_x"} {
		if !validGitBranch(b) {
			t.Errorf("%q rejected", b)
		}
	}
	for _, b := range []string{"", "-x", "--upload-pack=x", "a..b", "a b", "a~1", "a^", "a:b", "a?", "a*", "a[", `a\b`,
		"/a", "a/", "a//b", "a.lock", "a/.hidden", "@", "a@{1}", "a.", "a\nb", strings.Repeat("a", 256)} {
		if validGitBranch(b) {
			t.Errorf("%q accepted", b)
		}
	}
}

func TestValidEnvKey(t *testing.T) {
	for _, k := range []string{"A", "_A", "node_env", "DATABASE_URL", "A1"} {
		if !validEnvKey(k) {
			t.Errorf("%q rejected", k)
		}
	}
	for _, k := range []string{"", "1A", "A-B", "A B", "A=B", "A$", "A\n", "É"} {
		if validEnvKey(k) {
			t.Errorf("%q accepted", k)
		}
	}
}

func TestValidateDeployPayload(t *testing.T) {
	const id = "11111111-2222-4333-8444-555555555555"
	if err := validateDeployPayload(id, map[string]interface{}{
		"dockerImage":   "ghcr.io/acme/api:1",
		"restartPolicy": "always",
		"commitSha":     "abc1234",
		"gitBranch":     "main",
		"volumes": []interface{}{
			map[string]interface{}{"hostPath": "/opt/stacked/data/services/" + id + "/data-abc", "containerPath": "/data"},
		},
	}); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if err := validateDeployPayload(id, map[string]interface{}{}); err != nil {
		t.Fatalf("empty payload rejected: %v", err)
	}
	bad := []map[string]interface{}{
		{"dockerImage": "--privileged"},
		{"restartPolicy": "always\nprivileged: true"},
		{"commitSha": "--orphan"},
		{"gitBranch": "-x"},
		{"volumes": []interface{}{map[string]interface{}{"hostPath": "/etc", "containerPath": "/x"}}},
	}
	for _, p := range bad {
		if err := validateDeployPayload(id, p); err == nil {
			t.Errorf("payload %v accepted", p)
		}
	}
	if err := validateDeployPayload("../x", map[string]interface{}{}); err == nil {
		t.Error("non-UUID serviceId accepted")
	}
}
