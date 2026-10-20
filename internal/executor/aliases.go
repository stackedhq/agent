package executor

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// reservedAliases are DNS names on the shared `stacked` network that a
// user service must never claim: they belong to (or could impersonate)
// Stacked's own infrastructure (Caddy, the auth gate sidecar, the
// docker host alias). Mirrors the server's service-aliases.ts list.
var reservedAliases = map[string]bool{
	"gate":                 true,
	"stacked-gate":         true,
	"caddy":                true,
	"proxy":                true,
	"stacked":              true,
	"localhost":            true,
	"host":                 true,
	"docker":               true,
	"host-docker-internal": true,
}

// uuidRe matches a lowercase canonical UUID. Service and machine IDs
// have this shape; container names and the `<serviceID>` alias floor
// use it, so friendly aliases must not.
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// isReservedAlias reports whether s is a name user services may not use
// as a network alias (static list, reserved prefixes, UUID-shaped).
func isReservedAlias(s string) bool {
	s = strings.ToLower(s)
	if reservedAliases[s] {
		return true
	}
	if strings.HasPrefix(s, "stk-") || strings.HasPrefix(s, "stacked-") {
		return true
	}
	return uuidRe.MatchString(s)
}

// containerNamesFn lists every container name on the machine (running
// or not). Package var so tests can stub docker out.
var containerNamesFn = listContainerNames

func listContainerNames() (map[string]bool, error) {
	out, err := runCommandSilent("", "docker", "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return nil, fmt.Errorf("list containers: %s: %w", strings.TrimSpace(out), err)
	}
	names := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		if n := strings.TrimSpace(line); n != "" {
			names[strings.ToLower(n)] = true
		}
	}
	return names, nil
}

// resolveNetworkAliases returns the subset of the server-provided
// friendly aliases that are safe to register: valid DNS labels, not
// reserved, and not equal to the name of any existing container on the
// machine (a container name is itself resolvable on the network, so an
// alias matching one would let this service hijack that name). Docker
// is queried once per call, i.e. once per deploy op. Dropped aliases are
// logged. A docker failure is returned so the deploy fails rather than
// registering unchecked names.
func resolveNetworkAliases(aliases []string) ([]string, error) {
	if len(aliases) == 0 {
		return aliases, nil
	}
	existing, err := containerNamesFn()
	if err != nil {
		return nil, fmt.Errorf("check network aliases: %w", err)
	}
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		switch {
		case !validNetworkAlias(a):
			log.Printf("deploy: dropping network alias %q: invalid or reserved name", a)
		case existing[strings.ToLower(a)]:
			log.Printf("deploy: dropping network alias %q: a container with that name exists", a)
		default:
			out = append(out, a)
		}
	}
	return out, nil
}
