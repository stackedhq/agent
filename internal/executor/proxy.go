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

	// Reload Caddy
	if out, err := runCommandSilent(proxyDir, "docker", "compose", "exec", "caddy", "caddy", "reload", "--config", "/etc/caddy/Caddyfile"); err != nil {
		return fmt.Errorf("caddy reload: %s: %w", out, err)
	}

	log.Println("Caddy reloaded")
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

		// Container name matches the service name in docker-compose.yml,
		// which is the serviceID. Default port is 3000.
		fmt.Fprintf(&b, "%s {\n", domain)
		fmt.Fprintf(&b, "    reverse_proxy %s:3000\n", serviceID)
		fmt.Fprintf(&b, "}\n\n")
	}

	return b.String()
}
