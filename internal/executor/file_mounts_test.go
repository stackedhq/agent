package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

const testFileMountID = "11111111-1111-4111-8111-111111111111"

func TestHasFileMounts(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  interface{}
		want bool
	}{
		{"absent", nil, false},
		{"empty list", []interface{}{}, false},
		{"metadata list", []interface{}{map[string]interface{}{"id": "encrypted"}}, true},
		{"non-empty malformed metadata", "present", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := map[string]interface{}{}
			if test.name != "absent" {
				payload["fileMounts"] = test.raw
			}
			if got := hasFileMounts(payload); got != test.want {
				t.Fatalf("hasFileMounts() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMaterializeFileMountsAtWritesPrivateRegularFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "files")
	mounts, err := materializeFileMountsAt(root, []client.FileMount{{
		ID:            testFileMountID,
		ContainerPath: "/etc/app/config.toml",
		Content:       "secret = true\n",
	}})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if len(mounts) != 1 || !mounts[0].ReadOnly || mounts[0].ContainerPath != "/etc/app/config.toml" {
		t.Fatalf("unexpected rendered mounts: %+v", mounts)
	}
	content, err := os.ReadFile(filepath.Join(root, testFileMountID))
	if err != nil || string(content) != "secret = true\n" {
		t.Fatalf("materialized content = %q, err = %v", content, err)
	}
	info, err := os.Stat(filepath.Join(root, testFileMountID))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("source mode = %v, err = %v", info.Mode(), err)
	}
	dir, err := os.Stat(root)
	if err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("source directory mode = %v, err = %v", dir.Mode(), err)
	}
}

func TestMaterializeFileMountsAtRejectsUnsafeData(t *testing.T) {
	cases := []client.FileMount{
		{ID: "not-a-uuid", ContainerPath: "/config", Content: "x"},
		{ID: testFileMountID, ContainerPath: "relative", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/../escape", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/app/./config", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/app/config/", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/app/config#bad", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/app/config\nbad", Content: "x"},
		{ID: testFileMountID, ContainerPath: "/config", Content: strings.Repeat("x", maxFileMountContent+1)},
	}
	for _, mount := range cases {
		if _, err := materializeFileMountsAt(t.TempDir(), []client.FileMount{mount}); err == nil {
			t.Fatalf("expected unsafe mount %#v to fail", mount)
		}
	}
}

func TestMaterializeFileMountsAtRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, testFileMountID)); err != nil {
		t.Fatal(err)
	}
	_, err := materializeFileMountsAt(root, []client.FileMount{{
		ID: testFileMountID, ContainerPath: "/config", Content: "new",
	}})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	content, _ := os.ReadFile(target)
	if string(content) != "do not replace" {
		t.Fatal("symlink target was changed")
	}
}

func TestFileMountDockerArgsAreReadOnly(t *testing.T) {
	args := fileMountDockerArgs([]volumeMount{{HostPath: "/host/file", ContainerPath: "/config", ReadOnly: true}})
	if len(args) != 1 || args[0] != "--volume=/host/file:/config:ro" {
		t.Fatalf("unexpected docker args: %v", args)
	}
}

func TestMergeFileMountsRejectsContainerPathConflict(t *testing.T) {
	_, err := mergeFileMounts([]volumeMount{{ContainerPath: "/config"}}, []volumeMount{{ContainerPath: "/config", ReadOnly: true}})
	if err == nil {
		t.Fatal("expected mount conflict")
	}
}
