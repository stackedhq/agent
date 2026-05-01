// Package databaselogs streams `docker logs -f` output from Stacked-managed
// database containers up to the dashboard's database Console tab.
//
// Structurally a near-twin of the runtimelogs package (services), but kept
// separate because the two consumers diverge on cursor path, target API
// endpoint, and container filter. The duplication is honest — sharing a
// base abstraction would save ~150 lines while adding a leaky
// parameterization. If a third subject ever appears, factor then.
package databaselogs

import (
	"log"
	"os/exec"
	"strings"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Manager owns the set of active Forwarders, one per running Stacked-managed
// database container. Reconcile() is called from a periodic loop in main and
// brings the forwarder set in line with the live `docker ps` view.
type Manager struct {
	client *client.Client

	mu  sync.Mutex
	fwd map[string]*forwarderEntry // keyed by databaseID
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

// Reconcile enumerates Stacked database containers and ensures exactly one
// running Forwarder per (databaseID, containerID).
func (m *Manager) Reconcile() {
	live := listDatabaseContainers()

	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]string, len(live))
	for _, c := range live {
		if c.state != "running" {
			continue
		}
		want[c.databaseID] = c.id
	}

	// Stop forwarders for databases that vanished or whose container was
	// replaced (re-provision after destroy).
	for databaseID, entry := range m.fwd {
		newContainerID, stillThere := want[databaseID]
		if !stillThere || newContainerID != entry.containerID {
			log.Printf("databaselogs: stopping forwarder for %s (replaced=%v)", databaseID, stillThere)
			go entry.fwd.Stop()
			delete(m.fwd, databaseID)
		}
	}

	// Start forwarders for databases without one.
	for databaseID, containerID := range want {
		if _, exists := m.fwd[databaseID]; exists {
			continue
		}
		log.Printf("databaselogs: starting forwarder for %s (container=%s)", databaseID, containerID[:12])
		fwd := NewForwarder(m.client, databaseID, containerID)
		m.fwd[databaseID] = &forwarderEntry{containerID: containerID, fwd: fwd}
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

// containerRow holds the fields we need from `docker ps`.
type containerRow struct {
	id         string
	databaseID string
	state      string
}

// listDatabaseContainers enumerates Stacked-managed database containers.
// Identified strictly by `com.stacked.kind=database`. The compose-project
// label still carries the databaseID (basename of the working dir).
func listDatabaseContainers() []containerRow {
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--filter", "label=com.stacked.kind=database",
		"--format", `{{.ID}}	{{.Label "com.docker.compose.project"}}	{{.State}}`,
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("databaselogs: docker ps failed: %v", err)
		return nil
	}

	var rows []containerRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		rows = append(rows, containerRow{
			id:         parts[0],
			databaseID: parts[1],
			state:      parts[2],
		})
	}
	return rows
}
