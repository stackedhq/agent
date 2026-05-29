package executor

import (
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

// renderComposeVolumes produces the indented YAML fragment that goes
// under a service's `volumes:` key. Returns an empty string when there
// are no mounts so the caller can splice it into the compose template
// without an empty `volumes:` block (which docker compose tolerates
// but reads as "remove any previously configured volumes" on some
// versions — cleaner to just omit the key).
//
// Output shape:
//
//	    volumes:
//	      - /host/path:/container/path
//	      - /host/path:/container/path:ro
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
		if m.ReadOnly {
			fmt.Fprintf(&b, "      - %s:%s:ro\n", m.HostPath, m.ContainerPath)
		} else {
			fmt.Fprintf(&b, "      - %s:%s\n", m.HostPath, m.ContainerPath)
		}
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
		if err := os.MkdirAll(m.HostPath, 0o755); err != nil {
			return fmt.Errorf("create host volume dir %s: %w", m.HostPath, err)
		}
		if !isManagedHostPath(m.HostPath) {
			continue
		}
		if err := healManagedVolumePerms(m.HostPath); err != nil {
			return fmt.Errorf("heal managed volume perms %s: %w", m.HostPath, err)
		}
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
	if err := os.Chmod(root, 0o777); err != nil {
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
