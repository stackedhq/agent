package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// STACKED_ALLOWED_VOLUME_ROOTS is a machine-local, comma/colon-separated
// extra allowlist for custom host bind mounts. Dashboard state cannot set
// this; it is env or /opt/stacked/agent.toml only.
const allowedVolumeRootsEnv = "STACKED_ALLOWED_VOLUME_ROOTS"

var (
	allowedRootsMu         sync.RWMutex
	configuredAllowedRoots []string
	deniedHostPathPrefixes = []string{
		"/etc",
		"/proc",
		"/sys",
		"/dev",
		"/run",
		"/var/run",
		"/var/lib/docker",
		"/var/lib/containerd",
		"/var/lib/containers",
		"/opt/stacked",
	}
)

// SetAllowedHostRoots records machine-local custom bind roots from agent.toml.
// Call at process start; dashboard payloads must not reach this.
func SetAllowedHostRoots(roots []string) error {
	normalized, err := NormalizeAllowedHostRoots(roots)
	if err != nil {
		return err
	}
	allowedRootsMu.Lock()
	defer allowedRootsMu.Unlock()
	configuredAllowedRoots = normalized
	return nil
}

// NormalizeAllowedHostRoots cleans operator-supplied roots. "/" is allowed
// as an explicit root-equivalent grant. Critical paths cannot be allowlisted.
func NormalizeAllowedHostRoots(roots []string) ([]string, error) {
	out := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))
	for _, raw := range roots {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.ContainsRune(raw, 0) || hasDotDotSegment(raw) {
			return nil, fmt.Errorf("allowed host root %q is invalid", raw)
		}
		if !filepath.IsAbs(raw) {
			return nil, fmt.Errorf("allowed host root %q must be an absolute path", raw)
		}
		clean := filepath.Clean(raw)
		if clean != "/" {
			if denied, reason := deniedHostPath(clean); denied {
				return nil, fmt.Errorf("allowed host root %q is blocked (%s)", clean, reason)
			}
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	return out, nil
}

func allowedHostRoots() []string {
	allowedRootsMu.RLock()
	configured := append([]string(nil), configuredAllowedRoots...)
	allowedRootsMu.RUnlock()
	envRoots, err := NormalizeAllowedHostRoots(splitVolumeRoots(os.Getenv(allowedVolumeRootsEnv)))
	if err != nil {
		log.Printf("volume-guard: %s is invalid: %v", allowedVolumeRootsEnv, err)
		return configured
	}
	if len(envRoots) == 0 {
		return configured
	}
	seen := make(map[string]struct{}, len(configured)+len(envRoots))
	out := make([]string, 0, len(configured)+len(envRoots))
	for _, root := range append(configured, envRoots...) {
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	return out
}

func splitVolumeRoots(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ':' || r == ';' || r == '\n'
	})
}

func prepareHostVolumeMounts(payload map[string]interface{}, logLine func(string)) ([]volumeMount, error) {
	mounts := parseVolumes(payload)
	if err := authorizeVolumeMounts(mounts, logLine); err != nil {
		return nil, err
	}
	if err := ensureVolumeHostDirs(mounts); err != nil {
		return nil, err
	}
	return mounts, nil
}

func authorizeVolumeMounts(mounts []volumeMount, logLine func(string)) error {
	for i := range mounts {
		resolved, notes, err := authorizeHostPath(mounts[i].HostPath)
		for _, note := range notes {
			logVolumeGuard(logLine, note)
		}
		if err != nil {
			return err
		}
		mounts[i].HostPath = resolved
	}
	return nil
}

func logVolumeGuard(logLine func(string), msg string) {
	log.Print(msg)
	if logLine != nil {
		logLine(msg)
	}
}

func authorizeHostPath(hostPath string) (string, []string, error) {
	var notes []string
	clean, err := cleanHostBindPath(hostPath)
	if err != nil {
		return "", nil, err
	}
	resolved, err := resolveExistingPathPrefix(clean)
	if err != nil {
		return "", nil, fmt.Errorf("resolve host bind %q: %w", clean, err)
	}

	if clean != resolved {
		notes = append(notes, fmt.Sprintf("volume-guard: host path %q resolved to %q", clean, resolved))
	} else {
		notes = append(notes, fmt.Sprintf("volume-guard: host path %q (resolved %q)", clean, resolved))
	}

	if denied, reason := deniedHostPath(clean); denied {
		return "", notes, deniedHostBindError(clean, resolved, reason)
	}
	if denied, reason := deniedHostPath(resolved); denied {
		return "", notes, deniedHostBindError(clean, resolved, reason)
	}

	managedClean := isManagedVolumePath(clean)
	managedResolved := isManagedVolumePath(resolved)
	if managedClean && managedResolved {
		notes = append(notes, fmt.Sprintf("volume-guard: allowing managed volume %q", resolved))
		return resolved, notes, nil
	}
	if managedClean != managedResolved {
		return "", notes, fmt.Errorf("host bind %q escapes the managed volume root via symlink (resolved %q)", clean, resolved)
	}

	roots := allowedHostRoots()
	matchedResolved, resolvedRoot := matchingAllowedRoot(resolved, roots)
	if !matchedResolved {
		return "", notes, fmt.Errorf("custom host bind %q is not allowlisted on this machine (resolved %q); add a machine-local root to [volumes].allowed_host_roots in /opt/stacked/agent.toml or %s", clean, resolved, allowedVolumeRootsEnv)
	}

	if resolvedRoot == "/" || resolved == "/" {
		notes = append(notes, fmt.Sprintf("WARNING: volume-guard: custom bind %q is root-equivalent (resolved %q, allowlisted under %q)", clean, resolved, resolvedRoot))
	} else {
		notes = append(notes, fmt.Sprintf("volume-guard: allowing custom volume %q under %q", resolved, resolvedRoot))
	}
	return resolved, notes, nil
}

func deniedHostBindError(clean, resolved, reason string) error {
	equiv := ""
	if clean == "/" || resolved == "/" || reason == "container runtime socket" {
		equiv = " (root-equivalent)"
	}
	return fmt.Errorf("host bind %q is blocked%s: %s (resolved %q)", clean, equiv, reason, resolved)
}

func cleanHostBindPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("host bind path is empty")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("host bind path contains a NUL byte")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("host bind path %q must be absolute", path)
	}
	if hasDotDotSegment(path) {
		return "", fmt.Errorf("host bind path %q must not contain '..' segments", path)
	}
	return filepath.Clean(path), nil
}

func isManagedVolumePath(path string) bool {
	if strings.HasPrefix(path, managedVolumeRoot) {
		return true
	}
	root := strings.TrimSuffix(managedVolumeRoot, "/")
	clean := filepath.Clean(path)
	return strings.HasPrefix(clean, root+string(os.PathSeparator))
}

func deniedHostPath(path string) (bool, string) {
	clean := filepath.Clean(path)
	if clean == "/" {
		return true, "refusing to mount the host root"
	}
	base := filepath.Base(clean)
	if base == "docker.sock" || base == "containerd.sock" {
		return true, "container runtime socket"
	}
	if isManagedVolumePath(clean) {
		return false, ""
	}
	for _, prefix := range deniedHostPathPrefixes {
		if pathEqualsOrUnder(clean, prefix) {
			return true, "critical path " + prefix
		}
	}
	return false, ""
}

func matchingAllowedRoot(path string, roots []string) (bool, string) {
	for _, root := range roots {
		for _, candidate := range expandAllowedRoot(root) {
			if pathEqualsOrUnder(path, candidate) {
				return true, candidate
			}
		}
	}
	return false, ""
}

func expandAllowedRoot(root string) []string {
	out := []string{root}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved == root {
		return out
	}
	if denied, _ := deniedHostPath(resolved); denied {
		return out
	}
	return append(out, resolved)
}

func pathEqualsOrUnder(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if root == "/" {
		return filepath.IsAbs(path)
	}
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}
