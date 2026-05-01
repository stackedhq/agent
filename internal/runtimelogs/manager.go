package runtimelogs

import (
	"log"
	"os/exec"
	"strings"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
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
}

// listStackedContainers enumerates Stacked-managed containers, identified by
// the `com.docker.compose.project` label which the deploy executor sets to
// the serviceID via the per-service working directory name.
//
// Database containers are explicitly skipped via the `com.stacked.kind`
// label introduced when the agent gained db_* support — forwarders for
// databases live in the databaselogs package and post to a different API
// endpoint. Containers with no `com.stacked.kind` label are treated as
// services for back-compat with already-deployed services that pre-date
// the label (they keep streaming until their next deploy picks up the
// updated compose template).
func listStackedContainers() []containerRow {
	cmd := exec.Command(
		"docker", "ps", "-a",
		"--filter", "label=com.docker.compose.project",
		"--format", `{{.ID}}	{{.Label "com.docker.compose.project"}}	{{.State}}	{{.Label "com.stacked.kind"}}`,
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
		if len(parts) < 3 {
			continue
		}
		kind := ""
		if len(parts) >= 4 {
			kind = parts[3]
		}
		if kind == "database" {
			continue
		}
		rows = append(rows, containerRow{
			id:        parts[0],
			serviceID: parts[1],
			state:     parts[2],
		})
	}
	return rows
}
