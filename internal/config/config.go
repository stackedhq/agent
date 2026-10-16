package config

import (
	"fmt"
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

	// Fail fast on insecure server URLs: the token rides on every
	// request and ops are executed as root-equivalent.
	if err := client.ValidateServerURL(cfg.Agent.Server); err != nil {
		return nil, fmt.Errorf("agent.server in %s: %w", path, err)
	}

	return &cfg, nil
}
