package executor

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// managedVolumeRoot is the host-side namespace that the dashboard
// materializes for `mode: "managed"` volume entries. Anything under
// this prefix is server-owned and the agent is allowed to relax its
// permissions (see healManagedVolumePerms). Custom user-supplied host
// paths are deliberately left untouched.
//
// keep in sync with packages/web/src/lib/volume-paths.ts MANAGED_VOLUME_ROOT
const (
	managedServiceDataRoot = "/opt/stacked/data/services"
	managedVolumeRoot      = managedServiceDataRoot + "/"
)

// stackedUUIDPattern is the dashboard's service / file-mount ID shape.
// Healing and parent lockdown only run when this component is present so a
// look-alike path cannot talk us into chmoding arbitrary host dirs.
var stackedUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isStackedUUID(s string) bool {
	return stackedUUIDPattern.MatchString(s)
}

// permsHealSentinel is the empty file dropped at the root of a healed
// managed volume so subsequent deploys skip the recursive walk. The
// version suffix lets us re-run the heal in the future without having
// to detect the old state — bump the suffix and every volume re-heals
// exactly once. Hidden so it doesn't clutter `ls` for users SSHing in.
const permsHealSentinel = ".stacked-perms-v1"

// permsHealDisableEnv is the kill-switch. Set to "1" on the agent
// (systemd unit drop-in or env file) to skip the heal entirely if it
// ever misbehaves on a particular host. Newly-created managed dirs
// still get 0o777 on their leaf via the explicit Chmod below — the
// kill-switch only disables the recursive sweep of existing contents.
const permsHealDisableEnv = "STACKED_DISABLE_VOLUME_PERMS_HEAL"

// volumeMount is the agent-side view of a single host-volume entry
// arriving in the `deploy` / `release_command` op payload. It mirrors
// the dashboard's `services.volumes` jsonb shape:
//
//	{ hostPath: string, containerPath: string, readOnly?: bool, mode?: string }
//
// `mode` is a UX hint from the dashboard ("managed" vs "custom").
// The agent does not trust that field. It classifies mounts from the
// resolved host path: managed volumes under managedVolumeRoot are
// always allowed; every other host bind needs a machine-local allowlist.
type volumeMount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// parseVolumes pulls the `volumes` field out of an op payload and
// returns a normalized, deterministically-ordered list of mounts.
// Returns an empty slice when the field is absent, null, empty, or any
// shape we don't recognize — older servers (or services with no
// volumes configured) follow that path. Malformed individual entries
// are skipped with a log line rather than failing the deploy, since
// the server validates the same shape and a single bad entry getting
// through indicates a server bug we want visible but not fatal at the
// agent layer.
//
// The returned slice is sorted by container path so docker compose
// doesn't see spurious diffs between two payloads that contained the
// same mounts in different orders, which would otherwise trigger
// needless container recreates.
func parseVolumes(payload map[string]interface{}) []volumeMount {
	raw, ok := payload["volumes"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]volumeMount, 0, len(raw))
	for _, entry := range raw {
		obj, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		host, _ := obj["hostPath"].(string)
		container, _ := obj["containerPath"].(string)
		if host == "" || container == "" {
			continue
		}
		ro, _ := obj["readOnly"].(bool)
		out = append(out, volumeMount{
			HostPath:      host,
			ContainerPath: container,
			ReadOnly:      ro,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ContainerPath < out[j].ContainerPath
	})
	return out
}

// renderComposeVolumes produces the indented YAML fragment that goes
// under a service's `volumes:` key. Returns an empty string when there
// are no mounts so the caller can splice it into the compose template
// without an empty `volumes:` block (which docker compose tolerates
// but reads as "remove any previously configured volumes" on some
// versions — cleaner to just omit the key).
//
// Output shape:
//
//	volumes:
//	  - /host/path:/container/path
//	  - /host/path:/container/path:ro
//
// Leading whitespace is 6 spaces because the service block in
// generateCompose is indented under `services:` at depth 2 (4 spaces),
// and `volumes:` items go one more level in (6 spaces).
func renderComposeVolumes(mounts []volumeMount) string {
	if len(mounts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("    volumes:\n")
	for _, m := range mounts {
		value := m.HostPath + ":" + m.ContainerPath
		if m.ReadOnly {
			value += ":ro"
		}
		// A JSON string is a YAML scalar. Quote the complete short-form
		// mount so paths supplied by the server cannot add YAML structure.
		encoded, _ := json.Marshal(value)
		fmt.Fprintf(&b, "      - %s\n", encoded)
	}
	return b.String()
}

// ensureVolumeHostDirs creates each host-path directory before
// `docker compose up`. Without this, Docker auto-creates missing bind
// source paths as root with 0755 — which works, but is non-obvious
// and conflicts with the "self-heal a stale dir" pattern documented
// elsewhere in setup.go. Doing it explicitly gives us a known mode and
// a clean error path if creation fails (e.g. permission denied on a
// user-supplied custom path that lives somewhere the agent can't
// write).
//
// For paths inside the managed namespace we additionally relax perms
// to 0o777 (dirs) / 0o666 (files). Background: the agent runs as the
// unprivileged `stacked` user, so any host dir it creates is owned by
// that uid. Docker bind mounts preserve host uid/gid inside the
// container, so a 0o755 dir owned by `stacked` (~uid 1001) is read-
// only to a container running as any other non-root user — which is
// every modern app-image default (`oven/bun` uid 1000, `node:*` uid
// 1000, distroless/nonroot uid 65532, Chainguard 65532, ...). The
// observable symptom is `EACCES` / `SQLITE_CANTOPEN` the moment the
// app tries to write to its own data dir.
//
// We can't `chown` to the right uid because we don't know it at
// deploy time — `USER` in the image can be a name (`bun`), can be
// overridden by compose `user:`, can be empty for distroless images,
// and changes across image rebuilds. 0o777 is a per-service-siloed
// blanket fix that matches what Dokploy and Coolify do for the same
// reason. Custom (user-supplied) host paths are intentionally left
// alone — that's the user's filesystem and their perms story to own.
func ensureVolumeHostDirs(mounts []volumeMount) error {
	for _, m := range mounts {
		parent, managed := managedServiceParent(m.HostPath)
		if managed {
			if err := rejectSymlinkPathComponents(managedServiceDataRoot, filepath.Clean(m.HostPath)); err != nil {
				return fmt.Errorf("managed volume path %s: %w", m.HostPath, err)
			}
		}
		if err := os.MkdirAll(m.HostPath, 0o755); err != nil {
			return fmt.Errorf("create host volume dir %s: %w", m.HostPath, err)
		}
		if !managed {
			continue
		}
		if err := protectManagedVolumeLayout(m.HostPath, parent); err != nil {
			return err
		}
	}
	return nil
}

// protectManagedVolumeLayout locks the per-service parent to 0700 so
// unrelated local UIDs cannot traverse into 0777 leaves, then heals the
// bind-mount leaf for arbitrary container UIDs. Docker resolves bind
// sources as root, so the private parent does not block the mount.
func protectManagedVolumeLayout(hostPath, parent string) error {
	if err := chmodDirNoFollow(parent, 0o700); err != nil {
		return fmt.Errorf("lock service parent %s: %w", parent, err)
	}
	leaf := filepath.Clean(hostPath)
	if leaf == parent {
		return nil
	}
	if err := healManagedVolumePerms(leaf); err != nil {
		return fmt.Errorf("heal managed volume perms %s: %w", leaf, err)
	}
	return nil
}

// ReconcileManagedVolumeParents tightens existing
// /opt/stacked/data/services/<uuid> directories to 0700. Called from
// agent startup and Setup so hosts that already have 0755 parents pick
// up the lockdown without waiting for a redeploy. Missing root is a
// no-op (fresh box before the first managed volume).
func ReconcileManagedVolumeParents() error {
	return reconcileManagedServiceParentsAt(managedServiceDataRoot)
}

func reconcileManagedServiceParentsAt(root string) error {
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("managed volume root %s is not a directory", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !isStackedUUID(entry.Name()) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			log.Printf("volume-perms: skip symlink service parent %s", path)
			continue
		}
		if !entry.IsDir() {
			continue
		}
		if err := chmodDirNoFollow(path, 0o700); err != nil {
			log.Printf("volume-perms: lock service parent %s: %v (continuing)", path, err)
		}
	}
	return nil
}

// chmodDirNoFollow sets mode on a real directory. Lstat + O_NOFOLLOW so
// a symlink planted as a service parent cannot redirect the chmod onto
// its target.
func chmodDirNoFollow(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to chmod symlink %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(mode)
}

func lockManagedParentIfAny(hostPath string) {
	parent, ok := managedServiceParent(hostPath)
	if !ok {
		return
	}
	if err := chmodDirNoFollow(parent, 0o700); err != nil {
		log.Printf("volume-perms: lock service parent %s: %v", parent, err)
	}
}

// isManagedHostPath reports whether a host path lives inside the
// agent-managed namespace under a canonical UUID service component.
// Anchored on the services root so a sibling like
// `/opt/stacked/data/services-backup/...` cannot match. Paths are
// Clean'd before the UUID check so `..` segments cannot sneak a chmod
// outside the expected silo.
func isManagedHostPath(hostPath string) bool {
	_, ok := managedServiceParent(hostPath)
	return ok
}

// managedServiceParent returns the /opt/stacked/data/services/<uuid>
// directory for a host path, if the cleaned path is inside the managed
// root and the first component is a UUID. Does not resolve symlinks —
// callers that will chmod must use Lstat / O_NOFOLLOW separately.
func managedServiceParent(hostPath string) (string, bool) {
	if hostPath == "" || strings.ContainsRune(hostPath, 0) {
		return "", false
	}
	if !filepath.IsAbs(hostPath) {
		return "", false
	}
	cleaned := filepath.Clean(hostPath)
	root := filepath.Clean(managedServiceDataRoot)
	rel, err := filepath.Rel(root, cleaned)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	serviceID, _, _ := strings.Cut(rel, string(filepath.Separator))
	if !isStackedUUID(serviceID) {
		return "", false
	}
	return filepath.Join(root, serviceID), true
}

// healManagedVolumePerms makes a managed-volume host dir writable by
// any container uid. Idempotent: a sentinel file short-circuits the
// recursive walk on subsequent deploys, so a 100k-file Postgres data
// dir doesn't pay the I/O cost on every redeploy. The leaf dir itself
// is always chmoded (cheap, and guarantees a freshly-created dir gets
// 0o777 even though MkdirAll respects umask).
//
// Walk semantics:
//   - Symlinks are skipped. Following them would let a malicious or
//     buggy container place a symlink to `/etc/shadow` inside its own
//     volume and trick the next deploy into chmoding the link target.
//   - Directories get 0o777, files get 0o666. We don't try to be
//     clever about executables — apps that need +x set it themselves
//     when they write the file, and managed volumes are for data, not
//     code.
//   - Walk errors on individual entries log and continue rather than
//     fail the deploy. A single unreadable file inside a user's data
//     dir shouldn't brick their deploy; the leaf-dir chmod is what
//     actually fixes the SQLITE_CANTOPEN class of bug.
//
// The recursive sweep can be disabled fleet-wide via the
// STACKED_DISABLE_VOLUME_PERMS_HEAL env var as an emergency brake;
// the leaf-dir chmod still runs because that's the part that fixes
// newly-created volumes.
func healManagedVolumePerms(root string) error {
	if err := chmodDirNoFollow(root, 0o777); err != nil {
		return fmt.Errorf("chmod leaf %s: %w", root, err)
	}

	if os.Getenv(permsHealDisableEnv) == "1" {
		log.Printf("volume-perms: recursive heal disabled via %s, leaf-only chmod applied to %s", permsHealDisableEnv, root)
		return nil
	}

	sentinel := filepath.Join(root, permsHealSentinel)
	if _, err := os.Stat(sentinel); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat sentinel %s: %w", sentinel, err)
	}

	var (
		healedDirs  int
		healedFiles int
		skipped     int
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Printf("volume-perms: walk error at %s: %v (continuing)", path, walkErr)
			skipped++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == root {
			return nil // already chmoded above
		}
		// Skip symlinks entirely — don't follow, don't chmod. lchmod
		// isn't portable in Go's stdlib and chmod-on-symlink would
		// follow the link on Linux, which is the unsafe behavior.
		if d.Type()&fs.ModeSymlink != 0 {
			skipped++
			return nil
		}
		// Also skip anything that isn't a regular file or directory
		// (sockets, fifos, devices). Containers can create these and
		// they don't need our perm adjustments.
		if !d.IsDir() && !d.Type().IsRegular() {
			skipped++
			return nil
		}
		var mode os.FileMode = 0o666
		if d.IsDir() {
			mode = 0o777
		}
		if err := os.Chmod(path, mode); err != nil {
			log.Printf("volume-perms: chmod %s failed: %v (continuing)", path, err)
			skipped++
			return nil
		}
		if d.IsDir() {
			healedDirs++
		} else {
			healedFiles++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk %s: %w", root, err)
	}

	// Drop the sentinel last so a crash mid-walk leaves us in a
	// retry-friendly state (next deploy re-walks). Sentinel is 0o666
	// so a container running as a different uid than the next deploy
	// can still stat/read it; we only ever care about its existence.
	if err := os.WriteFile(sentinel, nil, 0o666); err != nil {
		return fmt.Errorf("write sentinel %s: %w", sentinel, err)
	}
	// Best-effort chmod in case umask stripped bits; ignore errors,
	// the file existing is what matters for short-circuiting.
	_ = os.Chmod(sentinel, 0o666)

	log.Printf("volume-perms: healed %s (dirs=%d files=%d skipped=%d)", root, healedDirs, healedFiles, skipped)
	return nil
}
