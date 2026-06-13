package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/config"
	"github.com/stackedapp/stacked/agent/internal/databaselogs"
	"github.com/stackedapp/stacked/agent/internal/executor"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
	"github.com/stackedapp/stacked/agent/internal/poller"
	"github.com/stackedapp/stacked/agent/internal/runtimelogs"
)

const (
	pollInterval         = 5 * time.Second
	heartbeatInterval    = 10 * time.Second
	logReconcileInterval = 10 * time.Second
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(heartbeat.Version)
		return
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("Starting Stacked agent v%s", heartbeat.Version)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Server: %s", cfg.Agent.Server)

	c := client.New(cfg.Agent.Server, cfg.Agent.Token)
	// Record the server origin for on-demand TLS `ask` URL rendering
	// before any op (or the startup proxy reconcile) can regenerate
	// the Caddyfile.
	executor.SetServerBaseURL(cfg.Agent.Server)
	exec := executor.New(c)
	logMgr := runtimelogs.NewManager(c)
	dbLogMgr := databaselogs.NewManager(c)

	// Reconcile the proxy compose file and Caddy container against the
	// current agent version. This lets embedded-template changes (e.g.
	// extra_hosts in proxyCompose) land on existing installs as soon as
	// systemd restarts us with the new binary after self-update, without
	// needing a manual reinstall or waiting for the next proxy_config op.
	// A no-op on machines that haven't run Setup yet. Errors are logged
	// and swallowed — the agent must always come up so the poller can
	// recover via subsequent ops.
	if err := executor.ReconcileProxy(); err != nil {
		log.Printf("Startup proxy reconcile skipped: %v", err)
	}

	stop := make(chan struct{})

	go heartbeat.Loop(c, heartbeatInterval, stop)
	go poller.Loop(c, exec, pollInterval, stop)
	go runtimeLogReconcileLoop(logMgr, logReconcileInterval, stop)
	go databaseLogReconcileLoop(dbLogMgr, logReconcileInterval, stop)

	log.Println("Agent running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	close(stop)

	// Stop all log forwarders cleanly so cursors get persisted before we
	// exit. Bounded by the forwarder's own context cancellation, so this
	// won't hang the process. Service and database forwarders are
	// independent; stop them in parallel to keep shutdown quick.
	var shutdownWg sync.WaitGroup
	shutdownWg.Add(2)
	go func() { defer shutdownWg.Done(); logMgr.StopAll() }()
	go func() { defer shutdownWg.Done(); dbLogMgr.StopAll() }()
	shutdownWg.Wait()

	// Give goroutines a moment to finish
	time.Sleep(1 * time.Second)
	log.Println("Agent stopped.")
}

// databaseLogReconcileLoop is the database equivalent of
// runtimeLogReconcileLoop. Two separate loops so a stalled docker call in
// one doesn't delay reconciliation of the other.
func databaseLogReconcileLoop(m *databaselogs.Manager, interval time.Duration, stop <-chan struct{}) {
	m.Reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.Reconcile()
		case <-stop:
			return
		}
	}
}

// runtimeLogReconcileLoop periodically syncs the runtime log forwarder set
// against currently-running Stacked containers. Runs immediately on startup
// to pick up containers from a prior agent process.
func runtimeLogReconcileLoop(m *runtimelogs.Manager, interval time.Duration, stop <-chan struct{}) {
	m.Reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.Reconcile()
		case <-stop:
			return
		}
	}
}
