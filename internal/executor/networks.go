package executor

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/logs"
)

const (
	stackedNetwork     = "stacked"
	stackedDataNetwork = "stacked-data"
	serviceNetPrefix   = "stacked-svc-"
	databaseNetPrefix  = "stacked-db-"
)

// networkPlan is the set of Docker networks a service (or one-shot
// cron/release container) joins.
//
// Isolation is opt-in. A payload with no `networkIsolation` /
// `linkedServiceIds` / `linkedDatabaseIds` stays on the historical
// shared `stacked` network so already-running siblings still resolve
// after upgrade. When isolation is on, the service sits on its own
// `stacked-svc-<id>` network (Caddy is attached after start) and can
// reach databases only via `stacked-data` or explicit
// `linkedDatabaseIds`. Sibling apps are unreachable unless listed in
// `linkedServiceIds`.
//
// Escape hatches:
//
//	networkIsolation: false  — historical shared `stacked` network
//	isolationRelaxed: true   — also forces shared `stacked`
type networkPlan struct {
	Isolation bool
	Primary   string
	Attach    []string
	Aliases   []string
}

func serviceNetworkName(serviceID string) string {
	return serviceNetPrefix + serviceID
}

func databaseNetworkName(databaseID string) string {
	return databaseNetPrefix + databaseID
}

func sharedNetworkPlan(aliases []string) networkPlan {
	return networkPlan{
		Isolation: false,
		Primary:   stackedNetwork,
		Aliases:   aliases,
	}
}

func networkPlanFromPayload(serviceID string, payload map[string]interface{}, aliases []string) networkPlan {
	if serviceID == "" {
		return sharedNetworkPlan(aliases)
	}
	// Isolation is opt-in via the modern link schema. A payload that omits
	// networkIsolation / linked* keeps the historical shared `stacked`
	// network so already-running siblings still resolve after upgrade.
	isolated := false
	if payload != nil {
		if v, ok := payload["networkIsolation"].(bool); ok {
			isolated = v
		} else if payloadHasKey(payload, "linkedServiceIds") || payloadHasKey(payload, "linkedDatabaseIds") {
			isolated = true
		}
	}
	if getBoolPayload(payload, "isolationRelaxed", false) {
		isolated = false
	}
	if !isolated {
		return sharedNetworkPlan(aliases)
	}

	plan := networkPlan{
		Isolation: true,
		Primary:   serviceNetworkName(serviceID),
		Aliases:   aliases,
	}

	for _, id := range parseStringList(payload, "linkedServiceIds") {
		if !isSafeNetworkName(serviceNetworkName(id)) {
			continue
		}
		if id == serviceID {
			continue
		}
		plan.Attach = append(plan.Attach, serviceNetworkName(id))
	}

	if payloadHasKey(payload, "linkedDatabaseIds") {
		for _, id := range parseStringList(payload, "linkedDatabaseIds") {
			if !isSafeNetworkName(databaseNetworkName(id)) {
				continue
			}
			plan.Attach = append(plan.Attach, databaseNetworkName(id))
		}
	} else {
		// Older servers don't send links. Join the shared data plane so
		// existing DATABASE_URL hostnames to managed DBs keep working,
		// without putting the app back on the global app network.
		plan.Attach = append(plan.Attach, stackedDataNetwork)
	}

	plan.Attach = uniqueSorted(plan.Attach)
	return plan
}

func databaseNetworkPlan(databaseID string) networkPlan {
	attach := []string{stackedNetwork, stackedDataNetwork}
	if databaseID != "" && isSafeNetworkName(databaseNetworkName(databaseID)) {
		attach = append(attach, databaseNetworkName(databaseID))
	}
	return networkPlan{
		Isolation: true,
		Primary:   stackedDataNetwork,
		Attach:    uniqueSorted(attach),
	}
}

func (p networkPlan) all() []string {
	seen := map[string]struct{}{p.Primary: {}}
	out := []string{p.Primary}
	for _, n := range p.Attach {
		if n == "" || n == p.Primary {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func ensureNetworkPlan(plan networkPlan) {
	for _, name := range plan.all() {
		ensureDockerNetwork(name)
	}
}

func ensureDockerNetwork(name string) {
	if name == "" || !isSafeNetworkName(name) {
		return
	}
	args := []string{"network", "create", "--label", "com.stacked.managed=1"}
	switch {
	case name == stackedNetwork:
		args = append(args, "--label", "com.stacked.role=proxy")
	case name == stackedDataNetwork || strings.HasPrefix(name, databaseNetPrefix):
		args = append(args, "--label", "com.stacked.role=data")
	case strings.HasPrefix(name, serviceNetPrefix):
		args = append(args, "--label", "com.stacked.role=service")
	}
	args = append(args, name)
	_, _ = runCommandSilent("", "docker", args...)
}

func renderComposeServiceNetworks(plan networkPlan) string {
	names := plan.all()
	aliases := validAliases(plan.Aliases)
	if len(names) == 1 && len(aliases) == 0 {
		return "    networks:\n      - " + names[0] + "\n"
	}
	var b strings.Builder
	b.WriteString("    networks:\n")
	for _, name := range names {
		if name == plan.Primary && len(aliases) > 0 {
			fmt.Fprintf(&b, "      %s:\n        aliases:\n", name)
			for _, a := range aliases {
				fmt.Fprintf(&b, "          - %s\n", a)
			}
			continue
		}
		fmt.Fprintf(&b, "      %s: {}\n", name)
	}
	return b.String()
}

func renderComposeNetworkDefs(plan networkPlan) string {
	var b strings.Builder
	b.WriteString("networks:\n")
	for _, name := range plan.all() {
		fmt.Fprintf(&b, "  %s:\n    name: %s\n    external: true\n", name, name)
	}
	return b.String()
}

func validAliases(aliases []string) []string {
	var out []string
	for _, a := range aliases {
		if validNetworkAlias(a) {
			out = append(out, a)
		}
	}
	return out
}

func connectNetwork(network, container string, aliases ...string) error {
	if network == "" || container == "" {
		return nil
	}
	args := []string{"network", "connect"}
	for _, a := range aliases {
		if validNetworkAlias(a) {
			args = append(args, "--alias", a)
		}
	}
	args = append(args, network, container)
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if alreadyOnNetwork(fmt.Errorf("%s", msg)) {
			return nil
		}
		msg = strings.TrimPrefix(msg, "Error response from daemon: ")
		if msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

func applyNetworkAttachments(container string, plan networkPlan) {
	aliases := validAliases(plan.Aliases)
	if plan.Isolation && container != "" && validNetworkAlias(stripSlotSuffix(container)) {
		aliases = uniqueSorted(append(aliases, stripSlotSuffix(container)))
	}
	for _, name := range plan.Attach {
		if err := connectNetwork(name, container, aliases...); err != nil {
			log.Printf("network connect %s %s: %v", name, container, err)
		}
	}
	if plan.Isolation {
		attachProxyToNetwork(plan.Primary)
	}
}

func attachProxyToNetwork(network string) {
	if network == "" || network == stackedNetwork {
		return
	}
	id, err := stackedCaddyContainerID()
	if err != nil {
		log.Printf("attach proxy to %s: %v", network, err)
		return
	}
	if err := connectNetwork(network, id); err != nil {
		log.Printf("attach proxy to %s: %v", network, err)
	}
}

func reconnectProxyServiceNetworks() {
	id, err := stackedCaddyContainerID()
	if err != nil {
		return
	}
	out, err := runCommandSilent("", "docker", "network", "ls", "--filter", "label=com.stacked.role=service", "--format", "{{.Name}}")
	if err != nil {
		return
	}
	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		_ = connectNetwork(name, id)
	}
}

func removeServiceNetwork(serviceID string) {
	name := serviceNetworkName(serviceID)
	if id, err := stackedCaddyContainerID(); err == nil {
		_, _ = runCommandSilent("", "docker", "network", "disconnect", name, id)
	}
	_, _ = runCommandSilent("", "docker", "network", "rm", name)
}

func stripSlotSuffix(name string) string {
	if base, ok := strings.CutSuffix(name, "-blue"); ok {
		return base
	}
	if base, ok := strings.CutSuffix(name, "-green"); ok {
		return base
	}
	return name
}

func probeNetworkFor(container string) string {
	return serviceNetworkName(stripSlotSuffix(container))
}

// runOneShotContainer starts a create → attach → start -a → rm container so
// cron/release join the same networks as the service (docker run can only
// attach one network at create time).
func (e *Executor) runOneShotContainer(streamer *logs.Streamer, dir, name, image, envPath string, iso isolationSpec, nets networkPlan, mountArgs []string, command []string) error {
	ensureNetworkPlan(nets)
	create := []string{
		"create",
		"--name", name,
		"--network", nets.Primary,
	}
	create = append(create, isolationDockerArgs(iso)...)
	if envPath != "" {
		create = append(create, "--env-file="+envPath)
	}
	create = append(create, mountArgs...)
	create = append(create, image)
	create = append(create, command...)
	if err := e.runCommandWithStreamer(streamer, dir, "docker", create...); err != nil {
		return err
	}
	defer func() { _, _ = runCommandSilent("", "docker", "rm", "-f", name) }()
	applyNetworkAttachments(name, nets)
	return e.runCommandWithStreamer(streamer, dir, "docker", "start", "-a", name)
}
