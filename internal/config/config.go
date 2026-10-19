package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Agent   AgentConfig   `toml:"agent"`
	Volumes VolumesConfig `toml:"volumes"`
}

type AgentConfig struct {
	Token  string `toml:"token"`
	Server string `toml:"server"`
}

// VolumesConfig is machine-local only. The dashboard cannot widen it.
type VolumesConfig struct {
	AllowedHostRoots []string `toml:"allowed_host_roots"`
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

	return &cfg, nil
}
