package heartbeat

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
)

// Tailscale status collected once per heartbeat. Cached so the
// 10s-cadence heartbeat doesn't shell out every tick when the value
// rarely changes — we only need to surface NEW state to the
// dashboard, not maintain a sub-second feed.
var (
	tailscaleStatusMu       sync.Mutex
	tailscaleStatusCached   *client.TailscaleStatus
	tailscaleStatusCachedAt time.Time
)

const tailscaleStatusTTL = 30 * time.Second

// collectTailscaleStatus returns the current Tailscale state for the
// machine, or nil if Tailscale is not installed (most users won't have
// it). nil intentionally results in an omitted `tailscale` field on the
// heartbeat — the server then knows to do nothing for this machine.
//
// On install-but-not-up hosts we still return a value (BackendState
// "Stopped" or "NoState") so the server can keep showing the right
// status if the user disables Tailscale on the VPS directly.
func collectTailscaleStatus() *client.TailscaleStatus {
	tailscaleStatusMu.Lock()
	defer tailscaleStatusMu.Unlock()
	if tailscaleStatusCached != nil && time.Since(tailscaleStatusCachedAt) < tailscaleStatusTTL {
		return tailscaleStatusCached
	}

	// Bail fast if the binary isn't installed. We don't want to log
	// noise on every heartbeat for the 99% of users who never enable
	// Tailscale.
	if _, err := exec.LookPath("tailscale"); err != nil {
		tailscaleStatusCached = nil
		tailscaleStatusCachedAt = time.Now()
		return nil
	}

	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		// Common case: tailscaled isn't running, or the CLI errored.
		// Don't cache the error — if the user just ran `tailscale up`
		// we want to pick that up on the next heartbeat.
		log.Printf("tailscale status --json failed: %v", err)
		return nil
	}

	parsed := parseTailscaleStatus(out)
	tailscaleStatusCached = parsed
	tailscaleStatusCachedAt = time.Now()
	return parsed
}

// Subset of `tailscale status --json` we care about. The schema is wide
// and not formally versioned; we touch only fields documented in
// tailscale.com/kb/1080/cli and stable across recent releases.
type tailscaleStatusJSON struct {
	BackendState   string   `json:"BackendState"`
	TailscaleIPs   []string `json:"TailscaleIPs"`
	MagicDNSSuffix string   `json:"MagicDNSSuffix"`
	CurrentTailnet *struct {
		Name           string `json:"Name"`
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
	} `json:"CurrentTailnet"`
	Self *struct {
		ID           string   `json:"ID"`
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
	User map[string]struct {
		LoginName string `json:"LoginName"`
	} `json:"User"`
}

// parseTailscaleStatus maps BackendState onto the small enum the server
// expects. Split from collectTailscaleStatus so we can test the mapping
// without shelling out.
func parseTailscaleStatus(raw []byte) *client.TailscaleStatus {
	var s tailscaleStatusJSON
	if err := json.Unmarshal(raw, &s); err != nil {
		log.Printf("parse tailscale status: %v", err)
		return nil
	}

	out := &client.TailscaleStatus{}
	switch s.BackendState {
	case "Running":
		// "Running" with a non-empty tailnet means actually connected;
		// "Running" with no IPs is a fleeting startup state that we
		// flatten to "starting" so the server doesn't briefly flap a
		// device to connected and immediately back.
		if len(s.TailscaleIPs) > 0 || (s.Self != nil && len(s.Self.TailscaleIPs) > 0) {
			out.Status = "connected"
		} else {
			out.Status = "starting"
		}
	case "NeedsLogin":
		// Node key expired or auth was revoked. User can re-authorize
		// themselves with the same browser dance — no tailnet-admin
		// involvement needed. Dashboard renders this as "Key expired".
		out.Status = "needs_login"
	case "NeedsMachineAuth":
		// Device approved itself but the tailnet has device-approval
		// enabled and is waiting for an admin to approve in the
		// Tailscale console. The end user can't fix this by clicking
		// anything in Stacked — we surface a different message that
		// points them at the admin console.
		out.Status = "needs_admin_approval"
	case "Stopped":
		out.Status = "stopped"
	case "Starting", "NoState":
		out.Status = "starting"
	default:
		// Unknown state. Don't lie to the server.
		return nil
	}

	// IPs: prefer top-level TailscaleIPs, then fall back to Self.
	ips := s.TailscaleIPs
	if len(ips) == 0 && s.Self != nil {
		ips = s.Self.TailscaleIPs
	}
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			if out.IPv6 == "" {
				out.IPv6 = ip
			}
		} else if out.IPv4 == "" {
			out.IPv4 = ip
		}
	}

	if s.Self != nil {
		out.NodeID = s.Self.ID
		// DNSName has a trailing dot per DNS convention; strip it
		// before showing to humans or using in connection strings.
		out.MagicDNSName = strings.TrimSuffix(s.Self.DNSName, ".")
	}

	if s.CurrentTailnet != nil {
		out.TailnetName = s.CurrentTailnet.Name
	}

	// The Users map is keyed by stringified user ID. Pick any login
	// name — there's typically only one for a single-user tailnet, and
	// we just want something to show in the UI.
	for _, u := range s.User {
		if u.LoginName != "" {
			out.LoginName = u.LoginName
			break
		}
	}

	return out
}
