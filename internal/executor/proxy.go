package executor

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
)

func (e *Executor) ProxyConfig(op client.Operation) error {
	domainsRaw, ok := op.Payload["domains"]
	if !ok {
		return fmt.Errorf("proxy_config requires domains in payload")
	}

	domains, ok := domainsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("proxy_config domains must be an array")
	}

	caddyfile := generateCaddyfile(domains)

	caddyfilePath := filepath.Join(proxyDir, "Caddyfile")
	if err := writeFile(caddyfilePath, caddyfile); err != nil {
		return fmt.Errorf("write Caddyfile: %w", err)
	}

	log.Printf("Updated Caddyfile with %d domain(s)", len(domains))

	// Hot-reload Caddy (zero downtime). Falls back to restart if reload
	// fails — which only happens on the very first proxy_config when Caddy
	// started with an empty Caddyfile and has no running config yet.
	if _, err := runCommandSilent(proxyDir, "docker", "compose", "exec", "caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"); err != nil {
		log.Println("Caddy reload failed, falling back to restart")
		if out, err := runCommandSilent(proxyDir, "docker", "compose", "restart", "caddy"); err != nil {
			return fmt.Errorf("caddy restart: %s: %w", out, err)
		}
	}

	log.Println("Caddy config updated")
	return nil
}

func generateCaddyfile(domains []interface{}) string {
	var b strings.Builder
	b.WriteString("# Managed by Stacked — do not edit manually\n\n")

	for _, d := range domains {
		dm, ok := d.(map[string]interface{})
		if !ok {
			continue
		}

		domain, _ := dm["domain"].(string)
		serviceID, _ := dm["serviceId"].(string)
		if domain == "" || serviceID == "" {
			continue
		}

		// Read port from payload, default to 3000 for backward compat
		port := 3000
		if p, ok := dm["port"].(float64); ok && p > 0 {
			port = int(p)
		}

		// Container name matches the service name in docker-compose.yml,
		// which is the serviceID.
		fmt.Fprintf(&b, "%s {\n", domain)
		fmt.Fprintf(&b, "    reverse_proxy %s:%d\n", serviceID, port)
		fmt.Fprintf(&b, "}\n\n")
	}

	return b.String()
}
