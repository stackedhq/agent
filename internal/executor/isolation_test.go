package executor

import (
	"strings"
	"testing"
)

func TestIsolationFromPayloadDefaults(t *testing.T) {
	got := isolationFromPayload(nil)
	if !got.NoNewPrivileges || got.PidsLimit != defaultAppPidsLimit {
		t.Fatalf("defaults = %+v", got)
	}
	if len(got.CapDrop) != 1 || got.CapDrop[0] != "ALL" {
		t.Fatalf("cap_drop = %v", got.CapDrop)
	}
	if got.ReadOnly || got.Relaxed || got.Privileged {
		t.Fatalf("unexpected flags: %+v", got)
	}
}

func TestIsolationRelaxedEscapeHatch(t *testing.T) {
	got := isolationFromPayload(map[string]interface{}{"isolationRelaxed": true})
	if !got.Relaxed || got.NoNewPrivileges || len(got.CapDrop) != 0 || got.PidsLimit != 0 {
		t.Fatalf("relaxed = %+v", got)
	}
	if block := renderComposeIsolation(got); block != "" {
		t.Fatalf("relaxed compose must omit isolation block, got %q", block)
	}
	if args := isolationDockerArgs(got); len(args) != 0 {
		t.Fatalf("relaxed docker args = %v", args)
	}
}

func TestIsolationOptIns(t *testing.T) {
	got := isolationFromPayload(map[string]interface{}{
		"allowPrivilegeEscalation": true,
		"capAdd":                   []interface{}{"NET_BIND_SERVICE", "SYS_PTRACE"},
		"pidsLimit":                float64(256),
		"readOnlyRoot":             true,
		"tmpfs":                    []interface{}{"/var/cache"},
	})
	if got.NoNewPrivileges {
		t.Fatal("allowPrivilegeEscalation must omit no-new-privileges")
	}
	if got.PidsLimit != 256 || !got.ReadOnly {
		t.Fatalf("opt-ins = %+v", got)
	}
	joined := strings.Join(got.CapAdd, ",")
	if !strings.Contains(joined, "NET_BIND_SERVICE") || !strings.Contains(joined, "SYS_PTRACE") {
		t.Fatalf("capAdd = %v", got.CapAdd)
	}
	tmp := strings.Join(got.Tmpfs, ",")
	for _, want := range []string{"/tmp", "/run", "/var/run", "/var/cache"} {
		if !strings.Contains(tmp, want) {
			t.Fatalf("tmpfs missing %s: %v", want, got.Tmpfs)
		}
	}

	yml := renderComposeIsolation(got)
	for _, want := range []string{
		"cap_drop:",
		`- "ALL"`,
		"cap_add:",
		`- "NET_BIND_SERVICE"`,
		"pids_limit: 256",
		"read_only: true",
		`- "/tmp"`,
	} {
		if !strings.Contains(yml, want) {
			t.Errorf("compose missing %q:\n%s", want, yml)
		}
	}
	if strings.Contains(yml, "no-new-privileges") {
		t.Errorf("nnp must be omitted:\n%s", yml)
	}

	args := isolationDockerArgs(got)
	for _, want := range []string{"--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE", "--pids-limit=256", "--read-only", "--tmpfs=/tmp"} {
		if !containsFlag(args, want) {
			t.Errorf("missing %s in %v", want, args)
		}
	}
	if containsFlag(args, "--security-opt=no-new-privileges:true") {
		t.Errorf("nnp flag must be omitted: %v", args)
	}
}

func TestIsolationDropsYAMLInjectedCapsAndTmpfs(t *testing.T) {
	got := isolationFromPayload(map[string]interface{}{
		"capAdd": []interface{}{"SYS_ADMIN\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock"},
		"tmpfs":  []interface{}{"/var/run/docker.sock:/var/run/docker.sock"},
	})
	yml := renderComposeIsolation(got)
	if strings.Contains(yml, "docker.sock") || strings.Contains(yml, "volumes:") {
		t.Fatalf("injected compose escaped isolation:\n%s", yml)
	}
}

func TestIsolationPrivilegedSkipsCapDrop(t *testing.T) {
	got := isolationFromPayload(map[string]interface{}{
		"privileged": true,
		"capAdd":     []interface{}{"SYS_ADMIN"},
	})
	if !got.Privileged || len(got.CapDrop) != 0 || len(got.CapAdd) != 0 {
		t.Fatalf("privileged = %+v", got)
	}
	yml := renderComposeIsolation(got)
	if !strings.Contains(yml, "privileged: true") || strings.Contains(yml, "cap_drop") {
		t.Fatalf("privileged compose:\n%s", yml)
	}
}

func TestGenerateCompose_DefaultIsolation(t *testing.T) {
	out := generateCompose("svc-1", "img:latest", nil,
		resourceLimits{restartPolicy: "unless-stopped"},
		isolationFromPayload(nil), networkPlanFromPayload("svc-1", nil, nil), "")
	for _, want := range []string{
		"security_opt:",
		"no-new-privileges:true",
		"cap_drop:",
		`- "ALL"`,
		"pids_limit: 1024",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

func TestDatabaseIsolation_OfficialImages(t *testing.T) {
	iso := databaseIsolation()
	if !iso.NoNewPrivileges || iso.PidsLimit != defaultDatabasePidsLimit {
		t.Fatalf("db isolation = %+v", iso)
	}
	have := strings.Join(iso.CapAdd, ",")
	for _, want := range []string{"CHOWN", "SETUID", "SETGID", "FOWNER"} {
		if !strings.Contains(have, want) {
			t.Errorf("official DB images need %s, got %v", want, iso.CapAdd)
		}
	}

	creds := map[string]string{"user": "u", "password": "p", "dbName": "d", "rootPassword": "r"}
	for _, dbType := range []string{"postgres", "mysql", "mongo", "redis"} {
		out, err := generateDatabaseCompose(dbType, 1234, dbType+"-x", dbType+":latest", creds, "internal", "", "db-"+dbType)
		if err != nil {
			t.Fatalf("%s: %v", dbType, err)
		}
		for _, want := range []string{
			"no-new-privileges:true",
			"cap_drop:",
			`- "ALL"`,
			"cap_add:",
			`- "SETUID"`,
			"pids_limit: 4096",
			"stacked-data",
			"stacked-db-db-" + dbType,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s compose missing %q:\n%s", dbType, want, out)
			}
		}
		if strings.Contains(out, "read_only:") {
			t.Errorf("%s must keep a writable rootfs:\n%s", dbType, out)
		}
	}
}
