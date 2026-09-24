package executor

import (
	"fmt"
	"sort"
	"strings"
)

const (
	defaultAppPidsLimit      = 1024
	defaultDatabasePidsLimit = 4096
)

// isolationSpec is the container-level hardening applied to both the
// compose (recreate / fast-restart) and `docker run` (rolling / one-shot)
// paths. Zero values mean "do not emit that knob".
//
// Defaults (isolationFromPayload with an empty payload):
//
//	no-new-privileges:true
//	cap_drop: [ALL]
//	pids_limit: 1024
//	read_only: false
//
// Escape hatches (deploy payload):
//
//	isolationRelaxed: true       — historical Docker defaults (no drop/nnp/pids)
//	allowPrivilegeEscalation: true — keep cap_drop/pids, omit no-new-privileges
//	privileged: true             — --privileged; skips cap_drop/cap_add
//	capAdd: ["NET_BIND_SERVICE"] — additive after ALL is dropped
//	capDrop: ["ALL"]             — replace the default drop list when present
//	pidsLimit: 256               — override (0 with isolationRelaxed = unlimited)
//	readOnlyRoot: true           — read-only rootfs + default tmpfs
//	tmpfs: ["/var/cache"]        — extra tmpfs mounts (writable)
type isolationSpec struct {
	Relaxed         bool
	NoNewPrivileges bool
	Privileged      bool
	CapDrop         []string
	CapAdd          []string
	PidsLimit       int
	ReadOnly        bool
	Tmpfs           []string
}

func defaultAppIsolation() isolationSpec {
	return isolationSpec{
		NoNewPrivileges: true,
		CapDrop:         []string{"ALL"},
		PidsLimit:       defaultAppPidsLimit,
	}
}

// databaseIsolation is the tightest set official postgres/mysql/mongo/redis
// images need after cap_drop ALL. They start as root, chown the data dir,
// then setuid to the engine user (gosu / su-exec).
func databaseIsolation() isolationSpec {
	return isolationSpec{
		NoNewPrivileges: true,
		CapDrop:         []string{"ALL"},
		CapAdd:          []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETPCAP", "SETUID", "SYS_NICE"},
		PidsLimit:       defaultDatabasePidsLimit,
	}
}

func isolationFromPayload(payload map[string]interface{}) isolationSpec {
	if getBoolPayload(payload, "isolationRelaxed", false) {
		spec := isolationSpec{Relaxed: true}
		if n := getIntPayload(payload, "pidsLimit"); n > 0 {
			spec.PidsLimit = n
		}
		return spec
	}

	spec := defaultAppIsolation()
	if getBoolPayload(payload, "allowPrivilegeEscalation", false) {
		spec.NoNewPrivileges = false
	}
	if getBoolPayload(payload, "privileged", false) {
		spec.Privileged = true
		spec.CapDrop = nil
		spec.CapAdd = nil
	}
	if payloadHasKey(payload, "capDrop") {
		spec.CapDrop = filterLinuxCaps(parseStringList(payload, "capDrop"))
	}
	if adds := filterLinuxCaps(parseStringList(payload, "capAdd")); len(adds) > 0 && !spec.Privileged {
		spec.CapAdd = uniqueSorted(adds)
	}
	if n := getIntPayload(payload, "pidsLimit"); n > 0 {
		spec.PidsLimit = n
	}
	if getBoolPayload(payload, "readOnlyRoot", false) {
		spec.ReadOnly = true
		spec.Tmpfs = []string{"/run", "/tmp", "/var/run"}
	}
	if extra := filterAbsPaths(parseStringList(payload, "tmpfs")); len(extra) > 0 {
		spec.Tmpfs = uniqueSorted(append(spec.Tmpfs, extra...))
	} else if len(spec.Tmpfs) > 0 {
		spec.Tmpfs = uniqueSorted(spec.Tmpfs)
	}
	if spec.Privileged {
		spec.CapDrop = nil
		spec.CapAdd = nil
	}
	return spec
}

func renderComposeIsolation(spec isolationSpec) string {
	if spec.Relaxed && spec.PidsLimit <= 0 && !spec.ReadOnly && !spec.Privileged {
		return ""
	}
	var b strings.Builder
	if spec.Privileged {
		b.WriteString("    privileged: true\n")
	}
	if spec.NoNewPrivileges {
		b.WriteString("    security_opt:\n      - no-new-privileges:true\n")
	}
	if len(spec.CapDrop) > 0 {
		b.WriteString("    cap_drop:\n")
		for _, c := range spec.CapDrop {
			fmt.Fprintf(&b, "      - %s\n", yamlQuote(c))
		}
	}
	if len(spec.CapAdd) > 0 {
		b.WriteString("    cap_add:\n")
		for _, c := range spec.CapAdd {
			fmt.Fprintf(&b, "      - %s\n", yamlQuote(c))
		}
	}
	if spec.PidsLimit > 0 {
		fmt.Fprintf(&b, "    pids_limit: %d\n", spec.PidsLimit)
	}
	if spec.ReadOnly {
		b.WriteString("    read_only: true\n")
	}
	if len(spec.Tmpfs) > 0 {
		b.WriteString("    tmpfs:\n")
		for _, t := range spec.Tmpfs {
			fmt.Fprintf(&b, "      - %s\n", yamlQuote(t))
		}
	}
	return b.String()
}

func isolationDockerArgs(spec isolationSpec) []string {
	var args []string
	if spec.Privileged {
		args = append(args, "--privileged")
	}
	if spec.NoNewPrivileges {
		args = append(args, "--security-opt=no-new-privileges:true")
	}
	for _, c := range spec.CapDrop {
		args = append(args, "--cap-drop="+c)
	}
	for _, c := range spec.CapAdd {
		args = append(args, "--cap-add="+c)
	}
	if spec.PidsLimit > 0 {
		args = append(args, fmt.Sprintf("--pids-limit=%d", spec.PidsLimit))
	}
	if spec.ReadOnly {
		args = append(args, "--read-only")
	}
	for _, t := range spec.Tmpfs {
		args = append(args, "--tmpfs="+t)
	}
	return args
}

func filterLinuxCaps(in []string) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		if c == "" {
			continue
		}
		ok := true
		for _, r := range c {
			if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

func filterAbsPaths(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
			continue
		}
		// tmpfs destinations are paths, not bind specs. A colon lets a
		// payload smuggle `host:container` into compose.
		if strings.ContainsAny(p, ":,\n\r\t ") {
			continue
		}
		skip := false
		for _, part := range strings.Split(p, "/") {
			if part == ".." {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

func payloadHasKey(payload map[string]interface{}, key string) bool {
	if payload == nil {
		return false
	}
	_, ok := payload[key]
	return ok
}

func parseStringList(payload map[string]interface{}, key string) []string {
	if payload == nil {
		return nil
	}
	switch raw := payload[key].(type) {
	case []string:
		out := make([]string, 0, len(raw))
		for _, s := range raw {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
