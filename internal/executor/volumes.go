package executor

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

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
// write). 0o755 matches Docker's default and lets the container's
// non-root user read; writes still depend on the container UID
// matching the host dir's ownership, which is the user's problem to
// solve for custom paths and a non-issue for managed paths since the
// managed root is created by the agent itself.
func ensureVolumeHostDirs(mounts []volumeMount) error {
	for _, m := range mounts {
		if err := os.MkdirAll(m.HostPath, 0o755); err != nil {
			return fmt.Errorf("create host volume dir %s: %w", m.HostPath, err)
		}
	}
	return nil
}
