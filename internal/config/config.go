package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
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

// AllowInsecureHTTPEnv is the explicit opt-in that permits an http://
// control-plane origin. Even with the flag set, the host must be
// loopback — this is a local-dev escape hatch, not a production knob.
const AllowInsecureHTTPEnv = "STACKED_ALLOW_INSECURE_HTTP"

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

	normalized, err := ValidateServerOrigin(cfg.Agent.Server, insecureHTTPAllowed())
	if err != nil {
		return nil, fmt.Errorf("agent.server: %w", err)
	}
	cfg.Agent.Server = normalized

	return &cfg, nil
}

func insecureHTTPAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(AllowInsecureHTTPEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ValidateServerOrigin parses raw as a control-plane origin.
//
// Production origins must be HTTPS with no userinfo, query, fragment, or
// path other than "/". HTTP is accepted only for loopback hosts when
// allowInsecureHTTP is set (installer --server / local-dev opt-in).
func ValidateServerOrigin(raw string, allowInsecureHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("is required")
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("must not contain whitespace")
	}
	if strings.Contains(raw, "?") {
		return "", fmt.Errorf("must not include a query string")
	}
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("must not include a fragment")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if u.Opaque != "" {
		return "", fmt.Errorf("must be an absolute http(s) origin")
	}
	if u.User != nil {
		return "", fmt.Errorf("must not include userinfo")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("must include a host")
	}
	if path := u.EscapedPath(); path != "" && path != "/" {
		return "", fmt.Errorf("must be an origin (no path %q)", path)
	}
	if u.RawPath != "" && u.RawPath != "/" {
		return "", fmt.Errorf("must be an origin (no path %q)", u.RawPath)
	}

	host := u.Hostname()
	if err := validateHost(host); err != nil {
		return "", err
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid port %q", port)
		}
	}

	if u.Scheme == "http" {
		if !allowInsecureHTTP {
			return "", fmt.Errorf("http is not allowed; use https, or set %s=1 for loopback development", AllowInsecureHTTPEnv)
		}
		if !isLoopbackHost(host) {
			return "", fmt.Errorf("http is only allowed for loopback hosts (got %q)", host)
		}
	}

	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("must include a host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}

	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return fmt.Errorf("malformed host %q", host)
	}
	if len(name) > 253 {
		return fmt.Errorf("malformed host %q", host)
	}
	for _, label := range strings.Split(name, ".") {
		if l := len(label); l == 0 || l > 63 {
			return fmt.Errorf("malformed host %q", host)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("malformed host %q", host)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("malformed host %q", host)
			}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
