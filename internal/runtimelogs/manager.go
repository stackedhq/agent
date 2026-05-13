package runtimelogs

import (
	"log"
	"os/exec"
	"strings"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/slots"
)

// Manager owns the set of active Forwarders, one per running Stacked-managed
// container. Reconcile() is called from the heartbeat loop and brings the
// forwarder set in line with the live `docker ps` view.
//
// All public methods are goroutine-safe.
type Manager struct {
	client *client.Client

	mu  sync.Mutex
	fwd map[string]*forwarderEntry // keyed by serviceID
}

type forwarderEntry struct {
	containerID string
	fwd         *Forwarder
}

func NewManager(c *client.Client) *Manager {
	return &Manager{
		client: c,
		fwd:    make(map[string]*forwarderEntry),
	}
}

// Reconcile enumerates Stacked-managed containers and ensures exactly one
// running Forwarder per (serviceID, containerID). Forwarders for vanished
// services are stopped; redeployed services (new containerID) get a fresh
// forwarder.
//
// Errors are logged, not returned: this runs on a heartbeat tick and a
// transient docker error shouldn't poison the agent.
func (m *Manager) Reconcile() {
	live := listStackedContainers()

	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]string, len(live)) // serviceID -> containerID
	for _, c := range live {
		// Skip non-running states (created, exited, restarting). `docker
		// logs -f` against a non-running container exits immediately, which
		// would just churn forwarders. We'll catch the container on a later
		// tick once it's running.
		if c.state != "running" {
			continue
		}
		want[c.serviceID] = c.id
	}

	// Stop forwarders for services that vanished or whose container was
	// replaced (redeploy).
	for serviceID, entry := range m.fwd {
		newContainerID, stillThere := want[serviceID]
		if !stillThere || newContainerID != entry.containerID {
			log.Printf("runtimelogs: stopping forwarder for %s (replaced=%v)", serviceID, stillThere)
			go entry.fwd.Stop() // Stop() blocks; don't hold the manager lock.
			delete(m.fwd, serviceID)
		}
	}

	// Start forwarders for services without one.
	for serviceID, containerID := range want {
		if _, exists := m.fwd[serviceID]; exists {
			continue
		}
		log.Printf("runtimelogs: starting forwarder for %s (container=%s)", serviceID, containerID[:12])
		fwd := NewForwarder(m.client, serviceID, containerID)
		m.fwd[serviceID] = &forwarderEntry{containerID: containerID, fwd: fwd}
		go fwd.Run()
	}
}

// StopAll shuts down every active forwarder. Called on agent shutdown.
func (m *Manager) StopAll() {
	m.mu.Lock()
	entries := make([]*forwarderEntry, 0, len(m.fwd))
	for _, e := range m.fwd {
		entries = append(entries, e)
	}
	m.fwd = make(map[string]*forwarderEntry)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func(e *forwarderEntry) {
			defer wg.Done()
			e.fwd.Stop()
		}(e)
	}
	wg.Wait()
}

// containerRow mirrors the equivalent in heartbeat/containers.go but is kept
// local to the runtimelogs package so the two consumers don't have to share
// a lower-level container-listing module.
type containerRow struct {
	id        string
	serviceID string
	state     string
	// slot is the value of the `com.stacked.slot` label, or "" when the
	// container has no slot label (the historical recreate-mode shape
	// where a service has exactly one container named <serviceID>).
	slot string
}

// listStackedContainers enumerates Stacked-managed service containers,
// identified by the `com.stacked.kind=service` label that the deploy
// executor writes on every container it creates (both recreate-mode
// compose templates and rolling-mode `docker run` invocations).
//
// We intentionally do NOT fall back to "any container with a compose
// project label" — that historical back-compat clause was meant to
// catch services deployed by ancient agents that pre-dated the kind
// label, but in practice it also swept up:
//
//   - the Caddy proxy container (compose project = literal "proxy")
//   - unrelated docker-compose projects the user runs on the same
//     host (e.g. their own side projects)
//
// Both produced bogus POSTs to /api/agent/logs/<non-uuid> which the
// dashboard rejected as 500s and which spammed the agent log. Every
// active code path that creates a Stacked service now sets the kind
// label, so a positive allowlist is safe.
//
// Database containers (`com.stacked.kind=database`) are handled by a
// separate forwarder in the databaselogs package and are excluded by
// the same label-equality filter.
//
// During a rolling (blue/green) deploy, both <serviceID>-blue and
// <serviceID>-green can be running simultaneously — they share the
// same compose-project label. We disambiguate via `com.stacked.slot`:
// the executor writes that label on rolling-mode containers, and we
// keep only the row matching the active slot recorded in the slots
// state file. Recreate-mode containers have no slot label and are
// always kept.
func listStackedContainers() []containerRow {
	cmd := exec.Command(
		"docker", "ps", "-a",
		// Docker-side filter shortcuts the common case where the
		// user runs other compose projects on the box. The
		// parser-side check below is defence in depth.
		"--filter", "label=com.stacked.kind=service",
		"--format", `{{.ID}}	{{.Label "com.docker.compose.project"}}	{{.State}}	{{.Label "com.stacked.kind"}}	{{.Label "com.stacked.slot"}}`,
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("runtimelogs: docker ps failed: %v", err)
		return nil
	}

	var rows []containerRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		if parts[3] != "service" {
			// Belt-and-braces: the docker-side filter should
			// have excluded these already.
			continue
		}
		serviceID := parts[1]
		if !isUUID(serviceID) {
			// A Stacked service container with a non-UUID
			// project label shouldn't exist (executor always
			// uses the UUID). Warn once per project and skip
			// so we don't POST garbage to the server.
			warnNonUUIDOnce(serviceID)
			continue
		}
		slot := ""
		if len(parts) >= 5 {
			slot = parts[4]
		}
		rows = append(rows, containerRow{
			id:        parts[0],
			serviceID: serviceID,
			state:     parts[2],
			slot:      slot,
		})
	}
	return filterActiveSlot(rows)
}

// isUUID is a cheap shape check for the 8-4-4-4-12 hex form. We only
// need to reject things like "proxy" or compose-project slugs that
// would 500 the server's UUID-typed query — not validate version /
// variant bits.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// warnedNonUUID tracks projects we've already warned about so a
// long-lived stray container doesn't fill the agent log on every
// Reconcile tick.
var (
	warnedNonUUIDMu sync.Mutex
	warnedNonUUID   = map[string]struct{}{}
)

func warnNonUUIDOnce(project string) {
	warnedNonUUIDMu.Lock()
	defer warnedNonUUIDMu.Unlock()
	if _, seen := warnedNonUUID[project]; seen {
		return
	}
	warnedNonUUID[project] = struct{}{}
	log.Printf("runtimelogs: skipping container with com.stacked.kind=service but non-UUID project %q", project)
}

// filterActiveSlot drops rows that don't correspond to the active slot
// for their service. For services with no slot state recorded (the
// recreate-mode default), all rows pass through unchanged. For
// rolling-mode services, only the row whose `slot` label matches the
// recorded active slot is kept; all other slot-bearing rows for the
// same service are dropped, and unlabeled (legacy) rows are kept only
// when the recorded active slot is exactly `legacy`.
func filterActiveSlot(rows []containerRow) []containerRow {
	if len(rows) == 0 {
		return rows
	}
	state := slots.All()
	if len(state) == 0 {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		active, ok := state[r.serviceID]
		if !ok {
			// No state for this service — keep everything as before.
			out = append(out, r)
			continue
		}
		if r.slot == "" {
			// Legacy unlabeled container. Keep only when state says so.
			if string(active) == "legacy" {
				out = append(out, r)
			}
			continue
		}
		if r.slot == string(active) {
			out = append(out, r)
		}
	}
	return out
}
