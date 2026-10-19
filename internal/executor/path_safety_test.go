package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const pathSafetyID = "ebe83b46-8e71-4bec-b21e-8ec9812c8af6"

func malformedIDs() []string {
	return []string{
		"",
		".",
		"..",
		"/",
		"/etc/passwd",
		"/opt/stacked/services/" + pathSafetyID,
		"foo/bar",
		`foo\bar`,
		"../" + pathSafetyID,
		pathSafetyID + "/..",
		"not-a-uuid",
		"svc-1",
	}
}

func withRedirectedRoots(t *testing.T) (root string) {
	t.Helper()
	root = t.TempDir()
	prevSvc, prevDB, prevVol := servicesDir, databasesDir, managedVolumeDataDir
	servicesDir = filepath.Join(root, "services")
	databasesDir = filepath.Join(root, "databases")
	managedVolumeDataDir = filepath.Join(root, "data")
	if err := os.MkdirAll(servicesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(databasesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(managedVolumeDataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		servicesDir, databasesDir, managedVolumeDataDir = prevSvc, prevDB, prevVol
	})
	return root
}

func TestServiceAndDatabaseDirRejectMalformed(t *testing.T) {
	root := withRedirectedRoots(t)
	for _, id := range malformedIDs() {
		if path, err := serviceDir(id); err == nil {
			t.Errorf("serviceDir(%q) = %q, want error", id, path)
		}
		if path, err := databaseDir(id); err == nil {
			t.Errorf("databaseDir(%q) = %q, want error", id, path)
		}
	}
	got, err := serviceDir(pathSafetyID)
	if err != nil {
		t.Fatalf("serviceDir(valid): %v", err)
	}
	if got != filepath.Join(root, "services", pathSafetyID) {
		t.Fatalf("serviceDir = %q", got)
	}
}

func TestMalformedIDsHaveNoFilesystemOrComposeSideEffects(t *testing.T) {
	root := withRedirectedRoots(t)
	sentinel := filepath.Join(root, "SENTINEL")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideCompose := filepath.Join(root, "docker-compose.yml")

	e := &Executor{}
	op := func(id string) client.Operation {
		return client.Operation{
			ID: "op-1",
			Payload: map[string]interface{}{
				"serviceId":  id,
				"databaseId": id,
			},
		}
	}

	assertUntouched := func(t *testing.T, id string) {
		t.Helper()
		if _, err := os.Stat(sentinel); err != nil {
			t.Fatalf("id %q deleted sentinel: %v", id, err)
		}
		if _, err := os.Stat(outsideCompose); !os.IsNotExist(err) {
			t.Fatalf("id %q wrote compose outside child: %v", id, err)
		}
		if entries, err := os.ReadDir(servicesDir); err != nil {
			t.Fatal(err)
		} else if len(entries) != 0 {
			t.Fatalf("id %q wrote under servicesDir: %v", id, entries)
		}
		if entries, err := os.ReadDir(databasesDir); err != nil {
			t.Fatal(err)
		} else if len(entries) != 0 {
			t.Fatalf("id %q wrote under databasesDir: %v", id, entries)
		}
		if _, err := exec.LookPath("docker"); err == nil {
			// Handlers must return before compose; a leftover project named
			// after the malformed id would mean we exec'd. Best-effort.
			if out, err := exec.Command("docker", "compose", "ls", "-q").CombinedOutput(); err == nil {
				if strings.Contains(string(out), id) && id != "" {
					t.Fatalf("id %q appeared in compose ls: %s", id, out)
				}
			}
		}
	}

	for _, id := range malformedIDs() {
		t.Run("id="+id, func(t *testing.T) {
			o := op(id)
			if _, err := e.Deploy(o); err == nil {
				t.Fatal("Deploy: want error")
			}
			if err := e.ReleaseCommand(o); err == nil {
				t.Fatal("ReleaseCommand: want error")
			}
			if _, err := e.RunJob(o); err == nil {
				t.Fatal("RunJob: want error")
			}
			if err := e.Stop(o); err == nil {
				t.Fatal("Stop: want error")
			}
			if err := e.Restart(o); err == nil {
				t.Fatal("Restart: want error")
			}
			if err := e.ServiceDestroy(o); err == nil {
				t.Fatal("ServiceDestroy: want error")
			}
			if _, err := e.Provision(o); err == nil {
				t.Fatal("Provision: want error")
			}
			if err := e.StartDB(o); err == nil {
				t.Fatal("StartDB: want error")
			}
			if err := e.StopDB(o); err == nil {
				t.Fatal("StopDB: want error")
			}
			if err := e.DestroyDB(o); err == nil {
				t.Fatal("DestroyDB: want error")
			}
			assertUntouched(t, id)
		})
	}
}

func TestDestroyDoesNotDeleteRootOnTraversal(t *testing.T) {
	root := withRedirectedRoots(t)
	keep := filepath.Join(root, "services", "keep-me")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Executor{}
	err := e.ServiceDestroy(client.Operation{
		Payload: map[string]interface{}{"serviceId": ".."},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("traversal destroy deleted sibling: %v", err)
	}
	err = e.DestroyDB(client.Operation{
		Payload: map[string]interface{}{"databaseId": ".."},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("db traversal destroy deleted sibling: %v", err)
	}
}
