package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/ids"
)

const (
	maxFileMountContent  = 64 * 1024
	maxFileMountTotal    = 512 * 1024
	maxManagedFileMounts = 20
)

type managedFileMount struct {
	ID            string
	ContainerPath string
	Content       string
}

// hasFileMounts deliberately checks metadata only. Plaintext content is
// fetched immediately before it is materialized and is never placed in an op
// payload or a log line.
func hasFileMounts(payload map[string]interface{}) bool {
	raw, ok := payload["fileMounts"]
	if !ok || raw == nil {
		return false
	}
	value := reflect.ValueOf(raw)
	switch value.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return value.Len() > 0
	default:
		return true
	}
}

func (e *Executor) prepareFileMounts(op client.Operation, serviceID string) ([]volumeMount, error) {
	if !hasFileMounts(op.Payload) {
		return nil, nil
	}
	mounts, err := e.Client.GetFileMounts(op.ID)
	if err != nil {
		return nil, fmt.Errorf("get file mounts: %w", err)
	}
	if len(mounts) == 0 {
		return nil, fmt.Errorf("managed file mount metadata was present but no files were returned")
	}
	return materializeFileMounts(serviceID, mounts)
}

func materializeFileMounts(serviceID string, mounts []client.FileMount) ([]volumeMount, error) {
	svcRoot, err := ids.Child(managedServiceDataRoot, serviceID)
	if err != nil {
		return nil, fmt.Errorf("invalid service ID for managed file mounts: %w", err)
	}
	root := filepath.Join(svcRoot, "files")
	if err := rejectSymlinkPathComponents(managedServiceDataRoot, root); err != nil {
		return nil, err
	}
	result, err := materializeFileMountsAt(root, mounts)
	if err != nil {
		return nil, err
	}
	parent := filepath.Join(managedServiceDataRoot, serviceID)
	if err := chmodDirNoFollow(parent, 0o700); err != nil {
		return nil, fmt.Errorf("lock service parent %s: %w", parent, err)
	}
	return result, nil
}

// materializeFileMountsAt validates every response before writing it, then
// atomically replaces only the requested source files. Stale files are
// intentionally retained: they can aid recovery, and are never mounted unless
// the current response references them.
func materializeFileMountsAt(root string, mounts []client.FileMount) ([]volumeMount, error) {
	validated, err := validateFileMounts(mounts)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateFileMountDir(root); err != nil {
		return nil, err
	}

	result := make([]volumeMount, 0, len(validated))
	for _, mount := range validated {
		target := filepath.Join(root, mount.ID)
		if err := writePrivateFileAtomically(target, mount.Content); err != nil {
			return nil, fmt.Errorf("materialize managed file mount %s: %w", mount.ID, err)
		}
		result = append(result, volumeMount{
			HostPath:      target,
			ContainerPath: mount.ContainerPath,
			ReadOnly:      true,
		})
	}
	return result, nil
}

func validateFileMounts(mounts []client.FileMount) ([]managedFileMount, error) {
	if len(mounts) > maxManagedFileMounts {
		return nil, fmt.Errorf("too many managed file mounts")
	}
	validated := make([]managedFileMount, 0, len(mounts))
	seenIDs := make(map[string]struct{}, len(mounts))
	paths := make(map[string]struct{}, len(mounts))
	totalBytes := 0
	for _, mount := range mounts {
		if err := ids.Validate(mount.ID); err != nil {
			return nil, fmt.Errorf("managed file mount has invalid ID")
		}
		if !validContainerFilePath(mount.ContainerPath) {
			return nil, fmt.Errorf("managed file mount %s has invalid container path", mount.ID)
		}
		containerPath := filepath.Clean(mount.ContainerPath)
		if !utf8.ValidString(mount.Content) || len(mount.Content) > maxFileMountContent {
			return nil, fmt.Errorf("managed file mount %s has invalid content", mount.ID)
		}
		totalBytes += len(mount.Content)
		if totalBytes > maxFileMountTotal {
			return nil, fmt.Errorf("managed file mounts exceed total content limit")
		}
		if _, exists := seenIDs[mount.ID]; exists {
			return nil, fmt.Errorf("managed file mounts contain duplicate ID")
		}
		for existingPath := range paths {
			if containerPathsOverlap(containerPath, existingPath) {
				return nil, fmt.Errorf("managed file mounts contain conflicting container paths")
			}
		}
		seenIDs[mount.ID] = struct{}{}
		paths[containerPath] = struct{}{}
		validated = append(validated, managedFileMount{
			ID:            mount.ID,
			ContainerPath: containerPath,
			Content:       mount.Content,
		})
	}
	sort.Slice(validated, func(i, j int) bool {
		return validated[i].ContainerPath < validated[j].ContainerPath
	})
	return validated, nil
}

func validContainerFilePath(path string) bool {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || strings.HasSuffix(path, "/") {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`:#"'\\`, r) {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return filepath.Clean(path) != "/"
}

// rejectSymlinkPathComponents verifies existing path components under base
// before MkdirAll can follow one outside Stacked's managed namespace.
func rejectSymlinkPathComponents(base, target string) error {
	if info, err := os.Lstat(base); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("managed file mount root is not a directory")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	relative, err := filepath.Rel(base, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("managed file mount path escapes its root")
	}
	current := base
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("managed file mount path contains a non-directory")
		}
	}
	return nil
}

func ensurePrivateFileMountDir(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create managed file mount directory: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect managed file mount directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("managed file mount directory is not a directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("chmod managed file mount directory: %w", err)
	}
	return nil
}

func writePrivateFileAtomically(path, content string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace symlink")
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("existing path is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".stacked-file-mount-")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	// The private 0700 parent protects the host copy. The file itself is
	// world-readable so non-root UIDs inside arbitrary prebuilt images can
	// read the bind mount; Docker preserves the source mode in the container.
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
}

func fileMountDockerArgs(mounts []volumeMount) []string {
	args := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		args = append(args, "--volume="+mount.HostPath+":"+mount.ContainerPath+":ro")
	}
	return args
}

func containerPathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func mergeFileMounts(mounts, fileMounts []volumeMount) ([]volumeMount, error) {
	paths := make(map[string]struct{}, len(mounts)+len(fileMounts))
	for _, mount := range mounts {
		paths[mount.ContainerPath] = struct{}{}
	}
	for _, mount := range fileMounts {
		for existingPath := range paths {
			if containerPathsOverlap(mount.ContainerPath, existingPath) {
				return nil, fmt.Errorf("managed file mount conflicts with another mount at %s", mount.ContainerPath)
			}
		}
		paths[mount.ContainerPath] = struct{}{}
	}
	return append(mounts, fileMounts...), nil
}
