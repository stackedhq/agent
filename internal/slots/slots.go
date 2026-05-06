// Package slots persists per-service active-slot state for rolling
// deploys. The state file is consulted by:
//
//   - The deploy executor, to pick the inactive slot for the next rolling
//     deploy and to record which slot is live after a successful flip.
//   - The proxy executor, when generating the Caddyfile so the upstream
//     resolves to <serviceID>-<activeSlot>:<port> instead of <serviceID>:<port>.
//   - The runtimelogs and heartbeat packages, so they only stream logs /
//     report metrics for the active slot during a rolling overlap.
//
// Services in the historical "recreate" mode never get a state entry —
// their containers keep the legacy <serviceID> name and no slot label,
// and the consumers fall back to "show whatever's there" when no entry
// exists. A service can move between recreate and rolling at any time;
// the first rolling deploy after a flip writes the state entry.
//
// The file lives next to the agent's other state at
// /opt/stacked/active-slots.json. It's flock-protected against concurrent
// writers (the agent runs ops sequentially today, but proxy_config and a
// deploy can race during a rolling promotion). Reads are unlocked — the
// file is small (one int per service) and torn reads are caught by the
// JSON decoder, which we treat as "no state" and fall back gracefully.
package slots

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Slot is the stable identifier for one of the two rolling-deploy slots.
// The empty value Slot("") means "no slot recorded" — used by callers as
// a fallback signal, never persisted as a value.
type Slot string

const (
	Blue  Slot = "blue"
	Green Slot = "green"
	// Legacy is a sentinel written exactly once during the very first
	// rolling deploy of a service that previously ran in recreate mode
	// (so its existing container is named <serviceID> with no slot
	// label). Filtering rules in runtimelogs / heartbeat treat
	// "Legacy" as "the no-slot-label container is the active one." On
	// promotion, the entry is overwritten with Blue or Green and the
	// legacy container is removed.
	Legacy Slot = "legacy"
)

// Other returns the slot opposite the given one. Only valid for Blue/Green.
// Legacy maps to Blue (the natural first real slot after migration).
func (s Slot) Other() Slot {
	switch s {
	case Blue:
		return Green
	case Green:
		return Blue
	default:
		return Blue
	}
}

// stateFile is a var, not a const, so tests can redirect it to a tmpdir.
// In production it's never reassigned.
var stateFile = "/opt/stacked/active-slots.json"

// mu serializes in-process callers. Cross-process safety comes from the
// flock in writeAll. The agent itself runs ops sequentially today, but
// the heartbeat goroutine and the executor can both call Active() — only
// the writers need exclusion, but holding the same mutex everywhere is
// trivially correct and not a hot path.
var mu sync.Mutex

func readAll() (map[string]Slot, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]Slot{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return map[string]Slot{}, nil
	}
	m := map[string]Slot{}
	if err := json.Unmarshal(data, &m); err != nil {
		// Treat a corrupt state file as "no state recorded." This makes
		// recovery a one-line `rm /opt/stacked/active-slots.json` for
		// the operator and avoids halting all rolling deploys on a
		// single bad write. The next successful promotion will rewrite
		// the file from scratch.
		return map[string]Slot{}, nil
	}
	return m, nil
}

// writeAll persists `m` atomically via tmp+rename, with a flock on the
// destination file to keep concurrent writers in different processes
// from clobbering each other. The flock is on the destination, not the
// tmp file — fcntl locks are released on close, and we only close after
// rename, so the lock window covers the whole swap.
func writeAll(m map[string]Slot) error {
	if err := os.MkdirAll(filepath.Dir(stateFile), 0755); err != nil {
		return fmt.Errorf("ensure state dir: %w", err)
	}

	// Open destination (or create empty) for the lock. We don't write
	// through this fd; the actual write goes via tmp+rename.
	lockFD, err := os.OpenFile(stateFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("open state for lock: %w", err)
	}
	defer lockFD.Close()

	if err := syscall.Flock(int(lockFD.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock state: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lockFD.Fd()), syscall.LOCK_UN) }()

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	tmp := stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write tmp state: %w", err)
	}
	if err := os.Rename(tmp, stateFile); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// Active returns the recorded active slot for serviceID, or "" when no
// entry exists. A "" return is the signal callers use to fall back to
// historical "no slot label" behavior.
func Active(serviceID string) Slot {
	mu.Lock()
	defer mu.Unlock()
	m, err := readAll()
	if err != nil {
		return ""
	}
	return m[serviceID]
}

// All returns a copy of the full state map. Used by Caddyfile generation
// so a single read can satisfy upstream lookups for many domains.
func All() map[string]Slot {
	mu.Lock()
	defer mu.Unlock()
	m, err := readAll()
	if err != nil {
		return map[string]Slot{}
	}
	cp := make(map[string]Slot, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// SetActive records `slot` as the live one for serviceID. Called at flip
// time, after Caddy has been reloaded onto the new upstream and the new
// container has passed health gating. Idempotent.
func SetActive(serviceID string, slot Slot) error {
	mu.Lock()
	defer mu.Unlock()
	m, err := readAll()
	if err != nil {
		return err
	}
	m[serviceID] = slot
	return writeAll(m)
}

// Clear removes the state entry for serviceID. Called on service deletion
// or when the user flips a service back from rolling to recreate (so the
// next deploy resumes the legacy <serviceID> container_name shape).
func Clear(serviceID string) error {
	mu.Lock()
	defer mu.Unlock()
	m, err := readAll()
	if err != nil {
		return err
	}
	if _, ok := m[serviceID]; !ok {
		return nil
	}
	delete(m, serviceID)
	return writeAll(m)
}
