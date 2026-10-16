package executor

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// managedVolumeRoot is the host-side namespace that the dashboard
// materializes for `mode: "managed"` volume entries. Anything under
// this prefix is server-owned and the agent is allowed to relax its
// permissions (see healManagedVolumePerms). Custom user-supplied host
// paths are deliberately left untouched.
//
// keep in sync with packages/web/src/lib/volume-paths.ts MANAGED_VOLUME_ROOT
const managedVolumeRoot = "/opt/stacked/data/services/"

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
// `mode` is a UX hint from the dashboard ("managed" vs "custom") and
// the agent does not branch on it — both modes resolve to a bind mount
// at the supplied hostPath. We deliberately keep the agent oblivious
// to managed-vs-custom because the path is fully materialized server-
// side; the only correct behavior is "mount what you're told".
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

// composeVolumeSpecs renders mounts as compose short-syntax volume
// strings (`host:container[:ro]`). Each becomes a yStr, so it is quoted and
// `$`-escaped when the compose file is rendered.
func composeVolumeSpecs(mounts []volumeMount) yList {
	out := make(yList, 0, len(mounts))
	for _, m := range mounts {
		value := m.HostPath + ":" + m.ContainerPath
		if m.ReadOnly {
			value += ":ro"
		}
		out = append(out, yStr(value))
	}
	return out
}

// --- Host path policy (cross-branch contract 7) ---------------------------

// deniedHostPathRoots: a custom volume may not be at or under any of these.
// Keep in sync with the server's host path policy (services.ts).
var deniedHostPathRoots = []string{
	"/etc", "/root", "/home", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/var/run", "/run", "/proc", "/sys", "/dev", "/var/lib/docker", "/opt/stacked",
	"/var/spool", "/var/lib/containerd", "/var/snap", "/snap", "/var/lib/kubelet",
}

// hostPathHint is appended to every policy rejection so the deploy log
// tells the user where a custom volume can go.
const hostPathHint = "Choose a path under /srv, /mnt or /data."

// hostPathPolicyError is a host path rejected by the volume policy. Its
// message names the path and the rule, plus where to put it instead; it
// ends up verbatim in the deploy log and the op error.
type hostPathPolicyError struct {
	Path  string // as cleaned (or quoted as given, for unparseable paths)
	Rule  string // e.g. "system path, inside /home"
	Mount string // container path, when known
}

func (e *hostPathPolicyError) Error() string {
	at := ""
	if e.Mount != "" {
		at = " (mounted at " + e.Mount + ")"
	}
	return fmt.Sprintf("volume host path %s%s is not allowed (%s). %s", e.Path, at, e.Rule, hostPathHint)
}

func denyHostPath(path, rule string) error {
	return &hostPathPolicyError{Path: path, Rule: rule}
}

// legacyCatalogDataRoot is the pre-managed-volume app catalog convention
// (`/opt/stacked/data/<serviceName>`). Existing catalog installs store host
// paths there, so they stay mountable even though they're under
// /opt/stacked; the managed `services/` subtree is excluded.
const legacyCatalogDataRoot = "/opt/stacked/data"

// cleanHostPath normalises a host path the way the server does (collapse
// `//`, drop a trailing `/`) and rejects anything that could be
// reinterpreted: relative paths, `..` segments, `$` (compose interpolation),
// `:` (volume-spec separator) and control characters.
func cleanHostPath(p string) (string, error) {
	if p == "" || len(p) > 4096 {
		return "", denyHostPath(fmt.Sprintf("%q", truncateForError(p)), "empty or longer than 4096 characters")
	}
	if !strings.HasPrefix(p, "/") {
		return "", denyHostPath(fmt.Sprintf("%q", truncateForError(p)), "must be an absolute path")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '$' || r == ':' {
			return "", denyHostPath(fmt.Sprintf("%q", truncateForError(p)), "contains $, : or a control character")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", denyHostPath(fmt.Sprintf("%q", truncateForError(p)), "contains a '..' segment")
		}
	}
	return filepath.Clean(p), nil
}

func pathAtOrUnder(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+"/")
}

// managedServiceDir is `/opt/stacked/data/services/<serviceID>`.
func managedServiceDir(serviceID string) string {
	return managedServiceDataRoot + "/" + serviceID
}

// checkHostPathPolicy validates a (cleaned) host path for serviceID's
// volumes. Returns the cleaned path. A managed path must be strictly inside
// this service's own managed dir and outside its `files/` area (managed file
// mounts are read-only and must stay that way).
func checkHostPathPolicy(serviceID, hostPath string) (string, error) {
	clean, err := cleanHostPath(hostPath)
	if err != nil {
		return "", err
	}
	if clean == "/" {
		return "", denyHostPath(clean, "the filesystem root")
	}
	if isUUID(serviceID) {
		own := managedServiceDir(serviceID)
		if strings.HasPrefix(clean, own+"/") {
			if pathAtOrUnder(clean, own+"/files") {
				return "", denyHostPath(clean, "reserved for managed file mounts")
			}
			return clean, nil
		}
	}
	if strings.HasPrefix(clean, legacyCatalogDataRoot+"/") && !pathAtOrUnder(clean, managedServiceDataRoot) {
		return clean, nil
	}
	if pathAtOrUnder(clean, managedServiceDataRoot) {
		return "", denyHostPath(clean, "Stacked-managed storage; only the service's own managed volumes may use it")
	}
	if denied := deniedHostRoot(clean); denied != "" {
		if denied == stackedDir {
			return "", denyHostPath(clean, "Stacked's own directory "+stackedDir)
		}
		return "", denyHostPath(clean, "system path, inside "+denied)
	}
	if contained := deniedRootUnder(clean); contained != "" {
		// A parent of a denied root (e.g. /var, /opt) would expose it
		// through the mount just the same.
		return "", denyHostPath(clean, "contains the system path "+contained)
	}
	return clean, nil
}

// deniedRootUnder returns a denied root that lies strictly inside clean,
// or "".
func deniedRootUnder(clean string) string {
	for _, root := range deniedHostPathRoots {
		if strings.HasPrefix(root, clean+"/") {
			return root
		}
	}
	return ""
}

func deniedHostRoot(clean string) string {
	for _, root := range deniedHostPathRoots {
		if pathAtOrUnder(clean, root) {
			return root
		}
	}
	return ""
}

// validateContainerMountPath rejects container paths that could break the
// `host:container[:ro]` spec or escape compose quoting.
func validateContainerMountPath(p string) error {
	if p == "" || len(p) > 4096 || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("container path %q must be absolute", truncateForError(p))
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '$' || r == ':' {
			return fmt.Errorf("container path %q contains a forbidden character", truncateForError(p))
		}
	}
	return nil
}

// validateVolumes applies the host path policy to every mount, rejects
// nested or duplicate host paths within the service (one mount must not be
// able to plant a symlink that redirects another), and returns the mounts
// with cleaned host paths. Pure: no filesystem access.
func validateVolumes(serviceID string, mounts []volumeMount) ([]volumeMount, error) {
	out := make([]volumeMount, 0, len(mounts))
	for _, m := range mounts {
		clean, err := checkHostPathPolicy(serviceID, m.HostPath)
		if err != nil {
			var pe *hostPathPolicyError
			if errors.As(err, &pe) {
				pe.Mount = truncateForError(m.ContainerPath)
			}
			return nil, err
		}
		if err := validateContainerMountPath(m.ContainerPath); err != nil {
			return nil, fmt.Errorf("volume %s: %w", clean, err)
		}
		for _, prev := range out {
			if containerPathsOverlap(clean, prev.HostPath) {
				return nil, fmt.Errorf("volume host paths %s and %s overlap; use separate directories", prev.HostPath, clean)
			}
		}
		m.HostPath = clean
		out = append(out, m)
	}
	return out, nil
}

// prepareVolumeHostDirs validates mounts (validateVolumes), then creates
// each host directory without following symlinks planted along the way, and
// relaxes permissions inside managed volumes. Returns the cleaned mounts to
// render into the compose file. Must run before `docker compose up` so the
// bind sources exist with predictable ownership (otherwise dockerd creates
// them as root:root 0755).
//
// Managed volumes (`/opt/stacked/data/services/<id>/<slug>`):
//
//   - `/opt/stacked/data` and `/opt/stacked/data/services` are tightened to
//     0711 and the per-service dir `<id>` to 0700 (owned by `stacked`). Other
//     local users can't list or enter any service's data; containers are
//     unaffected because a bind mount is resolved by dockerd, and the
//     container only ever sees the mounted leaf. (Managed file mounts have
//     shipped with a 0700 `<id>/files` dir since they landed.)
//   - The leaf and its contents stay 0777/0666 (healManagedVolumePerms).
//     The agent runs unprivileged and can't chown to the container's uid,
//     and the image's USER is often a name, empty, or overridden at runtime,
//     so a narrower mode (0750/0770 with the stacked group) would break
//     every image that runs as non-root (node uid 1000, postgres 999,
//     distroless 65532). The private parent is what keeps other host users
//     out.
//
// Custom paths are created 0755 and their permissions are otherwise left to
// the user.
func prepareVolumeHostDirs(serviceID string, mounts []volumeMount) ([]volumeMount, error) {
	validated, err := validateVolumes(serviceID, mounts)
	if err != nil {
		return nil, err
	}
	for _, m := range validated {
		if isManagedHostPath(m.HostPath) {
			tightenManagedDataParents()
			rel := strings.TrimPrefix(m.HostPath, managedServiceDataRoot+"/")
			if err := ensureManagedVolumeDir(managedServiceDataRoot, rel); err != nil {
				return nil, fmt.Errorf("prepare managed volume %s: %w", m.HostPath, err)
			}
			continue
		}
		if err := ensureCustomVolumeDir(m.HostPath); err != nil {
			return nil, fmt.Errorf("prepare host volume dir %s: %w", m.HostPath, err)
		}
	}
	return validated, nil
}

// tightenManagedDataParents makes /opt/stacked/data and
// /opt/stacked/data/services 0711 (traverse-only). Best effort: an
// install where root owns these dirs keeps its modes.
func tightenManagedDataParents() {
	for _, dir := range []string{legacyCatalogDataRoot, managedServiceDataRoot} {
		if err := os.MkdirAll(dir, 0o711); err != nil {
			log.Printf("volume-perms: create %s: %v", dir, err)
			continue
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() == 0o711 {
			continue
		}
		if err := os.Chmod(dir, 0o711); err != nil {
			log.Printf("volume-perms: chmod %s 0711: %v", dir, err)
		}
	}
}

// ensureManagedVolumeDir creates base/rel (rel = "<serviceID>/<slug>")
// through an os.Root anchored at base, so a symlink anywhere below base
// can't redirect the mkdir/chmod outside it, then heals the leaf's perms.
func ensureManagedVolumeDir(base, rel string) error {
	rel = filepath.Clean(rel)
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 2 || filepath.IsAbs(rel) || parts[0] == ".." {
		return fmt.Errorf("managed volume path must be <serviceId>/<name>")
	}
	if err := os.MkdirAll(base, 0o711); err != nil {
		return err
	}
	if err := rejectSymlinkPathComponents(base, filepath.Join(base, rel)); err != nil {
		return err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll(rel, 0o700); err != nil {
		return err
	}
	// <serviceID>: private to the stacked user.
	if err := root.Chmod(parts[0], 0o700); err != nil {
		return err
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("managed volume path is not a directory")
	}
	leaf, err := root.OpenRoot(rel)
	if err != nil {
		return err
	}
	defer leaf.Close()
	return healManagedVolumePermsIn(leaf, filepath.Join(base, rel))
}

// ensureCustomVolumeDir creates a custom (user-chosen) host directory after
// checking that no existing component below the top level is a symlink and
// that the real location isn't a denied path. A top-level symlink
// (`/mnt -> /var/mnt` on ostree systems) can only be created by host root
// and is allowed.
func ensureCustomVolumeDir(clean string) error {
	if err := rejectCustomPathSymlinks(clean); err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("host path %s is not a directory", clean)
	}
	return nil
}

func rejectCustomPathSymlinks(clean string) error {
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	current := "/"
	existing := "/"
	for depth, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if depth > 0 {
				return fmt.Errorf("host path %s contains a symlink at %s", clean, current)
			}
		} else if !info.IsDir() {
			return fmt.Errorf("host path %s: %s is not a directory", clean, current)
		}
		existing = current
	}
	// Policy applies to where the path really lands, not just its spelling.
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return err
	}
	if resolved == "/" && existing != "/" {
		return fmt.Errorf("host path %s resolves to /", clean)
	}
	if denied := deniedHostRoot(resolved); denied != "" && !pathAtOrUnder(clean, legacyCatalogDataRoot) {
		return fmt.Errorf("host path %s resolves inside %s", clean, denied)
	}
	return nil
}

// isManagedHostPath reports whether a host path lives inside the
// agent-managed namespace. Anchored on the trailing slash to avoid
// matching a sibling-named directory like
// `/opt/stacked/data/services-backup/...` that a user might create
// manually on disk.
func isManagedHostPath(hostPath string) bool {
	return strings.HasPrefix(hostPath, managedVolumeRoot)
}

// healManagedVolumePerms makes a managed-volume host dir writable by
// any container uid. See healManagedVolumePermsIn.
func healManagedVolumePerms(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("managed volume %s is not a directory", root)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	return healManagedVolumePermsIn(r, root)
}

// healManagedVolumePermsIn does the work through an os.Root anchored at the
// volume leaf. Idempotent: a sentinel file short-circuits the recursive
// walk on subsequent deploys, so a 100k-file Postgres data dir doesn't pay
// the I/O cost on every redeploy. The leaf dir itself is always chmoded
// (cheap, and guarantees a freshly-created dir gets 0o777 even though
// MkdirAll respects umask).
//
// Walk semantics:
//   - Everything goes through the os.Root, so no path, symlink or rename
//     race inside the volume can make a chmod or the sentinel write land
//     outside it.
//   - Symlinks are skipped (never followed or chmodded). Following them
//     would let a container place a symlink to `/etc/shadow` inside its
//     own volume and trick the next deploy into chmoding the target.
//   - Directories get 0o777, files get 0o666. Managed volumes are for
//     data, not code; apps that need +x set it themselves.
//   - Walk errors on individual entries log and continue rather than
//     fail the deploy.
//
// The recursive sweep can be disabled via STACKED_DISABLE_VOLUME_PERMS_HEAL
// as an emergency brake; the leaf-dir chmod still runs.
func healManagedVolumePermsIn(r *os.Root, display string) error {
	if err := r.Chmod(".", 0o777); err != nil {
		return fmt.Errorf("chmod leaf %s: %w", display, err)
	}

	if os.Getenv(permsHealDisableEnv) == "1" {
		log.Printf("volume-perms: recursive heal disabled via %s, leaf-only chmod applied to %s", permsHealDisableEnv, display)
		return nil
	}

	if _, err := r.Lstat(permsHealSentinel); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat sentinel in %s: %w", display, err)
	}

	var (
		healedDirs  int
		healedFiles int
		skipped     int
	)
	err := fs.WalkDir(r.FS(), ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Printf("volume-perms: walk error at %s/%s: %v (continuing)", display, path, walkErr)
			skipped++
			if d != nil && d.IsDir() && path != "." {
				return fs.SkipDir
			}
			return nil
		}
		if path == "." {
			return nil // already chmoded above
		}
		if d.Type()&fs.ModeSymlink != 0 {
			skipped++
			return nil
		}
		// Sockets, fifos and devices don't need our perm adjustments.
		if !d.IsDir() && !d.Type().IsRegular() {
			skipped++
			return nil
		}
		var mode os.FileMode = 0o666
		if d.IsDir() {
			mode = 0o777
		}
		if err := r.Chmod(path, mode); err != nil {
			log.Printf("volume-perms: chmod %s/%s failed: %v (continuing)", display, path, err)
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
		return fmt.Errorf("walk %s: %w", display, err)
	}

	// Drop the sentinel last so a crash mid-walk leaves us in a
	// retry-friendly state (next deploy re-walks). O_EXCL + the Root mean a
	// symlink planted under the sentinel name is never followed.
	f, err := r.OpenFile(permsHealSentinel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("write sentinel in %s: %w", display, err)
	}
	if f != nil {
		_ = f.Close()
		_ = r.Chmod(permsHealSentinel, 0o666)
	}

	log.Printf("volume-perms: healed %s (dirs=%d files=%d skipped=%d)", display, healedDirs, healedFiles, skipped)
	return nil
}
