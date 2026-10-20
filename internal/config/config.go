package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/stackedapp/stacked/agent/internal/client"
)

type Config struct {
	Agent AgentConfig `toml:"agent"`
}

type AgentConfig struct {
	Token  string `toml:"token"`
	Server string `toml:"server"`
}

const defaultConfigPath = "/opt/stacked/agent.toml"

func Load() (*Config, error) {
	path := os.Getenv("STACKED_CONFIG")
	if path == "" {
		path = defaultConfigPath
	}

	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to read config %s: %w", path, err)
	}

	if cfg.Agent.Token == "" {
		return nil, fmt.Errorf("agent.token is required in %s", path)
	}
	if !strings.HasPrefix(cfg.Agent.Token, "stk_") {
		return nil, fmt.Errorf("agent.token must start with stk_")
	}
	if cfg.Agent.Server == "" {
		return nil, fmt.Errorf("agent.server is required in %s", path)
	}

	// Strip trailing slash
	cfg.Agent.Server = strings.TrimRight(cfg.Agent.Server, "/")

	// The token rides on every request and ops are executed as
	// root-equivalent, so plain http is never used for a remote server.
	// A legacy http:// URL on a non-loopback host is upgraded to https
	// instead of failing: exiting here would put the agent in a systemd
	// restart loop with no way to receive further updates.
	if upgraded, changed := client.NormalizeServerURL(cfg.Agent.Server); changed {
		log.Printf("WARNING: agent.server in %s is %q, which would send the agent token over plain http. "+
			"Using %q instead. Update agent.server to https:// to silence this warning.", path, cfg.Agent.Server, upgraded)
		cfg.Agent.Server = upgraded
	}
	if err := client.ValidateServerURL(cfg.Agent.Server); err != nil {
		return nil, fmt.Errorf("agent.server in %s: %w", path, err)
	}

	return &cfg, nil
}
