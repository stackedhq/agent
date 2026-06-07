package executor

import (
	"fmt"
	"os/exec"
	"strings"
)

// Source-IP allowlisting for publicly-exposed database ports.
//
// Docker publishes container ports by inserting its own iptables rules into
// the nat/filter chains, which are evaluated *before* a host firewall like
// UFW — the well-known "Docker bypasses UFW" footgun. The supported seam for
// host operators to filter container traffic is the `DOCKER-USER` chain,
// which Docker jumps to first and never flushes. We manage a tagged set of
// rules there so a `public` database only accepts connections from the user's
// allowlisted CIDRs.
//
// Every rule we add carries an iptables comment of the form
// `stacked-db:<containerName>` so reconciliation can find and remove exactly
// our rules without disturbing Docker's or anyone else's.
//
// All of this requires root (the agent runs as root) and a host with iptables
// + the DOCKER-USER chain (present whenever Docker manages iptables, which is
// the default). On hosts without it we degrade gracefully: log and leave the
// port as Docker published it, rather than failing the operation.

func firewallTag(containerName string) string {
	return "stacked-db:" + containerName
}

// iptablesAvailable reports whether we can manage DOCKER-USER rules: the
// `iptables` binary exists and the DOCKER-USER chain is present.
func iptablesAvailable() bool {
	if _, err := exec.LookPath("iptables"); err != nil {
		return false
	}
	// `-S DOCKER-USER` lists the chain; non-zero exit means it's absent.
	cmd := exec.Command("iptables", "-S", "DOCKER-USER")
	return cmd.Run() == nil
}

// clearDatabaseFirewall removes all DOCKER-USER rules tagged for this
// container. Idempotent — safe to call when none exist (e.g. switching a DB
// from public back to internal/tailnet). Returns nil when iptables isn't
// available since there's nothing to clean up.
func clearDatabaseFirewall(containerName string) error {
	if !iptablesAvailable() {
		return nil
	}
	return deleteTaggedRules(firewallTag(containerName))
}

// reconcileDatabaseFirewall makes the DOCKER-USER rules for this container's
// published port match `allowedCIDRs` exactly: traffic from a listed CIDR is
// accepted, everything else to that port is dropped. An empty allowlist means
// "drop all external traffic to the port" — the UI prevents that for a DB the
// user intends to keep reachable, but we honour it literally (fail closed).
func reconcileDatabaseFirewall(containerName string, hostPort int, allowedCIDRs []string) error {
	if !iptablesAvailable() {
		// Can't enforce — leave Docker's published port as-is. The server
		// still records the intended allowlist; a host that later gains the
		// DOCKER-USER chain will be reconciled on the next access change.
		return fmt.Errorf("iptables/DOCKER-USER unavailable; cannot enforce allowlist")
	}

	tag := firewallTag(containerName)
	// Start from a clean slate so repeated reconciles don't accumulate rules.
	if err := deleteTaggedRules(tag); err != nil {
		return fmt.Errorf("clear existing rules: %w", err)
	}

	// Insert at the top of DOCKER-USER (position 1). We insert the DROP first
	// so it ends up *below* the subsequent allow rules: each `-I … 1` pushes
	// the previous top down. Final top-to-bottom order becomes:
	//   allow <cidrN> … allow <cidr1>  DROP(new)
	// i.e. listed sources RETURN to normal processing, the rest are dropped.
	if err := runIptables(dropRuleArgs(hostPort, tag)); err != nil {
		return fmt.Errorf("insert drop rule: %w", err)
	}
	for _, cidr := range allowedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if err := runIptables(allowRuleArgs(hostPort, cidr, tag)); err != nil {
			return fmt.Errorf("insert allow rule for %s: %w", cidr, err)
		}
	}
	return nil
}

// allowRuleArgs / dropRuleArgs build the DOCKER-USER rule argv. They are pure
// so the exact match semantics — the part that's easy to get wrong — can be
// unit-tested without invoking iptables.
//
// Critical detail: DOCKER-USER is traversed in the FORWARD chain, *after*
// Docker's nat/PREROUTING DNAT has already rewritten the packet's destination
// from <hostPort> to the container's native port. Matching on `--dport` would
// therefore never match (and would also match every container sharing that
// native port). We instead match `conntrack --ctorigdstport <hostPort>`, which
// is the original, pre-DNAT destination port — unique to this database's
// published port. The DROP additionally matches `--ctstate NEW` so only new
// inbound connections from non-allowlisted sources are blocked; established
// and return traffic flow normally.
func allowRuleArgs(hostPort int, cidr, tag string) []string {
	return []string{
		"-I", "DOCKER-USER", "1",
		"-p", "tcp",
		"-m", "conntrack", "--ctorigdstport", fmt.Sprintf("%d", hostPort),
		"-s", cidr,
		"-m", "comment", "--comment", tag,
		"-j", "RETURN",
	}
}

func dropRuleArgs(hostPort int, tag string) []string {
	return []string{
		"-I", "DOCKER-USER", "1",
		"-p", "tcp",
		"-m", "conntrack", "--ctorigdstport", fmt.Sprintf("%d", hostPort), "--ctstate", "NEW",
		"-m", "comment", "--comment", tag,
		"-j", "DROP",
	}
}

// deleteTaggedRules removes every DOCKER-USER rule carrying `tag`. It reads
// the current ruleset with `-S`, finds our tagged `-A DOCKER-USER …` lines,
// and deletes each by reissuing the identical spec with `-D`. Reissuing the
// full spec (rather than deleting by line number) is robust against
// concurrent edits shifting line numbers between list and delete.
func deleteTaggedRules(tag string) error {
	out, err := exec.Command("iptables", "-S", "DOCKER-USER").CombinedOutput()
	if err != nil {
		return fmt.Errorf("list DOCKER-USER: %s: %w", strings.TrimSpace(string(out)), err)
	}
	needle := fmt.Sprintf("--comment %s", tag)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, needle) {
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		// Turn the `-A DOCKER-USER …` spec into a `-D DOCKER-USER …` delete.
		spec := strings.TrimPrefix(line, "-A ")
		args := append([]string{"-D"}, splitIptablesSpec(spec)...)
		if err := runIptables(args); err != nil {
			return fmt.Errorf("delete rule %q: %w", line, err)
		}
	}
	return nil
}

// splitIptablesSpec splits an `iptables -S` rule line into argv. The comment
// value we use ("stacked-db:<name>") contains no spaces, so a plain field
// split is sufficient and avoids a shell-quoting parser.
func splitIptablesSpec(spec string) []string {
	return strings.Fields(spec)
}

func runIptables(args []string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}
