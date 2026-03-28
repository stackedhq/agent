package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/config"
	"github.com/stackedapp/stacked/agent/internal/executor"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
	"github.com/stackedapp/stacked/agent/internal/poller"
)

const (
	pollInterval      = 5 * time.Second
	heartbeatInterval = 30 * time.Second
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Starting Stacked agent...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("Server: %s", cfg.Agent.Server)

	c := client.New(cfg.Agent.Server, cfg.Agent.Token)
	exec := executor.New(c)

	stop := make(chan struct{})

	go heartbeat.Loop(c, heartbeatInterval, stop)
	go poller.Loop(c, exec, pollInterval, stop)

	log.Println("Agent running. Press Ctrl+C to stop.")

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	close(stop)

	// Give goroutines a moment to finish
	time.Sleep(1 * time.Second)
	log.Println("Agent stopped.")
}
