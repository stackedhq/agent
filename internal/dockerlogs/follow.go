// Package dockerlogs holds the shared `docker logs` invocation used by the
// runtime and database log shippers.
package dockerlogs

import "time"

// MaxResumeAge is the oldest cursor we will honour as `--since`. A cursor
// older than this is treated as "follow from now" so a restarted agent
// never replays days of json-file history into the control plane.
const MaxResumeAge = 2 * time.Minute

// FollowArgs returns `docker logs` arguments that follow a container
// without dumping its historical json-file. `--tail 0` is the actual
// follow-from-now switch; `--since` is a second bound in case an older
// Docker treats tail=0 as "all".
//
// `cursor` is an RFC3339Nano timestamp previously persisted by the
// shipper. It is used only when it falls within MaxResumeAge; ancient
// cursors (the production failure mode: a July timestamp surviving on
// disk) are ignored.
func FollowArgs(containerID, cursor string, now time.Time) []string {
	args := []string{"logs", "-f", "--timestamps", "--tail", "0", "--since", sinceArg(cursor, now)}
	return append(args, containerID)
}

func sinceArg(cursor string, now time.Time) string {
	if cursor == "" {
		return "2m"
	}
	t, err := time.Parse(time.RFC3339Nano, cursor)
	if err != nil {
		return "2m"
	}
	if t.After(now) || now.Sub(t) > MaxResumeAge {
		return "2m"
	}
	return cursor
}

// ShouldShip reports whether a docker-log timestamp is recent enough to
// forward. Untimestamped / malformed lines pass through so we never drop
// live output we cannot date. Historical lines (the json-file replay
// that saturated the control plane) return false.
func ShouldShip(ts string, now time.Time) bool {
	if ts == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return true
	}
	if t.After(now) {
		return true
	}
	return now.Sub(t) <= MaxResumeAge
}
