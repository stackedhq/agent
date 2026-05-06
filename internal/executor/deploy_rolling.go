package executor

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/heartbeat"
	"github.com/stackedapp/stacked/agent/internal/logs"
	"github.com/stackedapp/stacked/agent/internal/slots"
)

// deployRolling executes a rolling deploy for a service that has opted
// into deploy_strategy=rolling. It branches on whether the service has
// volumes attached:
//
//   - No volumes: blue/green. Bring up the inactive slot alongside the
//     live one, health-gate, flip Caddy, drain the old slot.
//
//   - Volumes attached: fast stop-start. Pre-pull the image so the gap
//     doesn't include a slow registry fetch, stop old, start new with
//     the same container_name (so the volume isn't shared between two
//     concurrently running containers), health-gate, done.
//
// The "fast stop-start when volumes are attached" rule mirrors what
// Railway, Fly, and Kubernetes RWO do: nobody offers true zero-downtime
// for host-volume-attached services because the volume can't be safely
// shared between two writers, and the platform can't introspect what's
// inside it (SQLite vs. uploads dir vs. RO config) to know if sharing
// would be safe.
func (e *Executor) deployRolling(op client.Operation, streamer *logs.Streamer) (map[string]interface{}, error) {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return nil, fmt.Errorf("rolling deploy requires serviceId in payload")
	}

	// `volumes` arrives as []interface{} from the JSON payload — we just
	// need its length to pick the sub-strategy. The actual volume
	// mounting inside the container is owned by generateCompose /
	// runRollingContainer below; this branch is purely about whether
	// blue and green can coexist safely.
	hasVolumes := false
	if v, ok := op.Payload["volumes"].([]interface{}); ok && len(v) > 0 {
		hasVolumes = true
	}

	if hasVolumes {
		streamer.AddLine("Rolling mode: fast restart (volumes attached, can't run two slots concurrently).")
		streamer.Flush()
		return e.deployFastRestart(op, streamer, serviceID)
	}
	streamer.AddLine("Rolling mode: zero-downtime blue/green.")
	streamer.Flush()
	return e.deployBlueGreen(op, streamer, serviceID)
}

// deployBlueGreen brings up the inactive slot, health-gates it, flips
// Caddy upstream to the new slot, drains the old slot, and removes it.
// Failures pre-flip leave the old slot serving untouched.
func (e *Executor) deployBlueGreen(op client.Operation, streamer *logs.Streamer, serviceID string) (map[string]interface{}, error) {
	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("create service dir: %w", err)
	}

	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	currentSlot := slots.Active(serviceID)
	if currentSlot == "" {
		// First rolling deploy of a service that previously ran in
		// recreate mode. The existing container (if any) is named
		// <serviceID> with no slot label — treat it as the Legacy
		// slot so the post-flip drain targets the right container
		// name and the Caddyfile keeps pointing at it until the flip.
		currentSlot = slots.Legacy
	}
	newSlot := currentSlot.Other()
	streamer.AddLine(fmt.Sprintf("Active slot: %q \u2192 deploying to %q.", string(currentSlot), string(newSlot)))
	streamer.Flush()

	// Memory-headroom precheck. Blue/green peaks at 2× the service's
	// memory limit because both slots run concurrently. On a small VPS
	// (1 GB) with a 600 MB service, starting the second slot would OOM
	// the host and likely kill the live container too. Fail fast with
	// a useful error instead. Skipped when the service has no memory
	// limit configured — we can't compute a budget then, and the user
	// has opted out of resource limits anyway.
	if limitMB := getIntPayloadOr(op.Payload, "memoryLimitMb", 0); limitMB > 0 {
		if avail := heartbeat.AvailableMemoryMB(); avail > 0 && avail < uint64(limitMB)*2 {
			return nil, fail(fmt.Errorf(
				"insufficient memory headroom for blue/green: need %d MB free (2× service limit), have %d MB available; raise the VPS size or switch to recreate mode",
				limitMB*2, avail,
			))
		}
	}

	// Phase 1: resolve image (pull or build). This may have been done
	// already by the release op; the pull/build is idempotent and the
	// docker layer cache makes a repeat near-instant.
	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		return nil, fail(fmt.Errorf("get credentials: %w", err))
	}
	imageName, err := e.resolveImage(op, serviceID, dir, creds, streamer)
	if err != nil {
		return nil, fail(err)
	}

	// Phase 2: write env file (shared by both slots).
	if creds.EnvVars == nil {
		creds.EnvVars = map[string]string{}
	}
	if _, ok := creds.EnvVars["HOST"]; !ok {
		creds.EnvVars["HOST"] = "0.0.0.0"
	}
	envPath := filepath.Join(dir, ".env")
	if err := writeFile(envPath, buildEnvFile(creds.EnvVars)); err != nil {
		return nil, fail(fmt.Errorf("write .env: %w", err))
	}

	// Phase 3: ensure the network exists.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	// Phase 4: bring up the new slot. We use `docker run` directly
	// rather than compose so the slots are independently managed
	// without per-slot compose-file juggling. The `com.stacked.slot`
	// label drives the runtimelogs / heartbeat filtering so only the
	// active slot's logs and metrics surface to the dashboard.
	newContainer := serviceID + "-" + string(newSlot)
	streamer.SetProgress(70)
	streamer.AddLine("Starting new slot " + newContainer + "...")
	streamer.Flush()

	// Defensive: if a previous failed deploy left a stopped container
	// of the same name behind, remove it before starting fresh.
	_, _ = runCommandSilent("", "docker", "rm", "-f", newContainer)

	if err := runRollingContainer(streamer, newContainer, serviceID, string(newSlot), imageName, envPath, op); err != nil {
		return nil, fail(err)
	}

	// Phase 5: health gate. We probe the new container's bridge IP on
	// the configured port. Failures here abort BEFORE the Caddy flip,
	// so the live slot keeps serving — this is the whole point of
	// blue/green.
	probePort := 3000
	if creds.Port > 0 {
		probePort = creds.Port
	}
	healthPath := getStringPayload(op.Payload, "healthCheckPath")
	timeoutSec := getIntPayloadOr(op.Payload, "healthCheckTimeoutSec", 60)
	streamer.SetProgress(85)
	streamer.AddLine(fmt.Sprintf("Health gate: probing %s:%d (timeout=%ds)...", newContainer, probePort, timeoutSec))
	streamer.Flush()
	if err := HealthGate(streamer, newContainer, "stacked", probePort, healthPath, time.Duration(timeoutSec)*time.Second); err != nil {
		// Tear down the failed slot so the next deploy starts clean.
		_, _ = runCommandSilent("", "docker", "rm", "-f", newContainer)
		return nil, fail(fmt.Errorf("health gate: %w", err))
	}

	// Phase 6: flip Caddy. We persist the new slot in state FIRST,
	// then ask the Caddyfile generator to rewrite. Order matters: if
	// Caddy reload fails, slot state already says new — but Caddy is
	// still serving old. We back the state out in that case so the
	// system stays consistent.
	streamer.SetProgress(92)
	streamer.AddLine("Flipping traffic to new slot...")
	streamer.Flush()
	prevSlot := currentSlot
	if err := slots.SetActive(serviceID, newSlot); err != nil {
		_, _ = runCommandSilent("", "docker", "rm", "-f", newContainer)
		return nil, fail(fmt.Errorf("persist slot state: %w", err))
	}
	if err := RegenerateCaddyfile(); err != nil {
		// Roll back state. Old slot keeps serving — Caddy never moved.
		// prevSlot is always non-empty here (Legacy on first rolling
		// deploy, Blue/Green afterwards) so SetActive is enough.
		_ = slots.SetActive(serviceID, prevSlot)
		_, _ = runCommandSilent("", "docker", "rm", "-f", newContainer)
		return nil, fail(fmt.Errorf("caddy reload: %w", err))
	}
	streamer.AddLine("Caddy reloaded; traffic now on " + newContainer + ".")
	streamer.Flush()

	// Phase 7: drain and remove the old slot. `docker stop --time=N`
	// sends SIGTERM, waits up to N seconds for graceful shutdown, then
	// SIGKILLs. The grace period is the user's `stop_grace_sec`.
	graceSec := getIntPayloadOr(op.Payload, "stopGraceSec", 10)
	oldContainer := containerNameForSlot(serviceID, prevSlot)
	streamer.AddLine(fmt.Sprintf("Draining old container %s (grace=%ds)...", oldContainer, graceSec))
	streamer.Flush()
	// `docker stop` returns nonzero when the target doesn't exist; that's
	// fine for the first rolling deploy of a service that never had a
	// recreate-mode container running, or for retries where the old
	// slot was already removed.
	_, _ = runCommandSilent("", "docker", "stop", "--time="+strconv.Itoa(graceSec), oldContainer)
	_, _ = runCommandSilent("", "docker", "rm", "-f", oldContainer)

	// Phase 8: post-flip probe (informational, matches recreate's
	// post-deploy probe so the dashboard's port-mismatch banner still
	// works for rolling deploys).
	probeRes := e.HealthProbe(streamer, newContainer, probePort)

	streamer.SetProgress(100)
	streamer.AddLine("Rolling deploy complete.")
	streamer.Flush()

	result := map[string]interface{}{
		"probeOk":             probeRes.Ok,
		"exposedPorts":        probeRes.ExposedPorts,
		"exposedPortsUnknown": probeRes.ExposedPortsUnknown,
		"activeSlot":          string(newSlot),
	}
	if probeRes.Error != "" {
		result["probeError"] = probeRes.Error
	}
	return result, nil
}

// deployFastRestart implements the volume-aware path: pre-pull the
// image while old container keeps serving, stop old, start new with
// the same container_name (so volumes are exclusive), health-gate.
//
// We deliberately do NOT preserve old-on-failure here in v1 — getting
// reliable rollback when the volume is mid-migrated is its own thing.
// Failure leaves the user on the new container; if it's broken, they
// see a clear failure log and can redeploy a known-good image.
func (e *Executor) deployFastRestart(op client.Operation, streamer *logs.Streamer, serviceID string) (map[string]interface{}, error) {
	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("create service dir: %w", err)
	}

	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		return nil, fail(fmt.Errorf("get credentials: %w", err))
	}
	if creds.EnvVars == nil {
		creds.EnvVars = map[string]string{}
	}
	if _, ok := creds.EnvVars["HOST"]; !ok {
		creds.EnvVars["HOST"] = "0.0.0.0"
	}
	envPath := filepath.Join(dir, ".env")
	if err := writeFile(envPath, buildEnvFile(creds.EnvVars)); err != nil {
		return nil, fail(fmt.Errorf("write .env: %w", err))
	}

	// Pre-pull / pre-build BEFORE stopping the old container so the
	// outage window doesn't include a slow registry fetch. The deploy
	// op may have been preceded by a release op that already populated
	// the layer cache; this is then near-instant.
	imageName, err := e.resolveImage(op, serviceID, dir, creds, streamer)
	if err != nil {
		return nil, fail(err)
	}

	// Generate the compose file targeting the historical container_name
	// `<serviceID>` so volumes mount exclusively (only one writer at
	// a time). Reuses the existing compose template — the recreate
	// path's container shape — so logs/metrics keying is unchanged.
	compose := generateCompose(serviceID, imageName)
	if err := writeFile(filepath.Join(dir, "docker-compose.yml"), compose); err != nil {
		return nil, fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}

	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	// Stop the old container with the user's grace window, then bring
	// up the new one. `docker compose up -d` recreates the container
	// in place because the image changed — we explicitly stop first
	// so SIGTERM has the configured grace, and so the gap window is
	// bounded by `stopGraceSec + container start + health gate`.
	graceSec := getIntPayloadOr(op.Payload, "stopGraceSec", 10)
	streamer.SetProgress(70)
	streamer.AddLine(fmt.Sprintf("Stopping old container (grace=%ds)...", graceSec))
	streamer.Flush()
	_, _ = runCommandSilent(dir, "docker", "stop", "--time="+strconv.Itoa(graceSec), serviceID)

	streamer.AddLine("Starting new container...")
	streamer.Flush()
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d", "--force-recreate", "--remove-orphans"); err != nil {
		return nil, fail(fmt.Errorf("docker compose up: %w", err))
	}

	probePort := 3000
	if creds.Port > 0 {
		probePort = creds.Port
	}
	healthPath := getStringPayload(op.Payload, "healthCheckPath")
	timeoutSec := getIntPayloadOr(op.Payload, "healthCheckTimeoutSec", 60)
	streamer.SetProgress(90)
	streamer.AddLine(fmt.Sprintf("Health gate: probing %s:%d (timeout=%ds)...", serviceID, probePort, timeoutSec))
	streamer.Flush()
	if err := HealthGate(streamer, serviceID, "stacked", probePort, healthPath, time.Duration(timeoutSec)*time.Second); err != nil {
		return nil, fail(fmt.Errorf("health gate: %w", err))
	}

	// Fast-restart never uses slot state — clear any stale entry from
	// a previous blue/green run on this service so the runtimelogs
	// and heartbeat filters fall back to the no-slot-label container.
	_ = slots.Clear(serviceID)

	probeRes := e.HealthProbe(streamer, serviceID, probePort)
	streamer.SetProgress(100)
	streamer.AddLine("Fast-restart deploy complete.")
	streamer.Flush()

	result := map[string]interface{}{
		"probeOk":             probeRes.Ok,
		"exposedPorts":        probeRes.ExposedPorts,
		"exposedPortsUnknown": probeRes.ExposedPortsUnknown,
		"activeSlot":          "",
	}
	if probeRes.Error != "" {
		result["probeError"] = probeRes.Error
	}
	return result, nil
}

// resolveImage returns the image tag the rolling deploy will run. For
// docker-image services it's the configured image (after `docker pull`).
// For git-based services it's `stacked-<serviceID>` (after a Nixpacks
// build). The release op, if it ran, already populated either path's
// cache, so this is near-instant on the second call.
func (e *Executor) resolveImage(op client.Operation, serviceID, dir string, creds *client.Credentials, streamer *logs.Streamer) (string, error) {
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	if dockerImage != "" {
		streamer.SetProgress(20)
		streamer.AddLine("Pulling image " + dockerImage + "...")
		streamer.Flush()

		if creds.RegistryToken != "" {
			cmd := exec.Command("docker", "login", "ghcr.io", "-u", "x-access-token", "--password-stdin")
			cmd.Stdin = strings.NewReader(creds.RegistryToken)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("ghcr login failed (non-fatal): %s", string(out))
			}
		}
		if err := e.runCommandWithStreamer(streamer, dir, "docker", "pull", dockerImage); err != nil {
			return "", fmt.Errorf("docker pull %s: %w", dockerImage, err)
		}
		return dockerImage, nil
	}
	return e.buildFromSource(op, serviceID, dir, creds, streamer)
}

// runRollingContainer starts a per-slot container directly via
// `docker run -d`. We don't use compose for slot containers because
// each slot needs to be independently start/stop-able, and compose's
// orphan handling within a single project gets in the way of running
// blue and green simultaneously.
func runRollingContainer(streamer *logs.Streamer, containerName, serviceID, slot, imageName, envPath string, op client.Operation) error {
	args := []string{
		"run", "-d",
		"--name", containerName,
		"--network=stacked",
		"--restart=unless-stopped",
		"--env-file=" + envPath,
		"--label", "com.docker.compose.project=" + serviceID,
		"--label", "com.stacked.kind=service",
		"--label", "com.stacked.slot=" + slot,
		imageName,
	}
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		streamer.AddLine(strings.TrimSpace(string(out)))
		return fmt.Errorf("docker run %s: %w", containerName, err)
	}
	return nil
}

// containerNameForSlot returns the container name for a service's slot.
// Legacy resolves to the bare serviceID — that's the no-slot-label
// container left behind from a recreate-mode deploy, kept stable so the
// post-flip stop targets the right thing during the first rolling deploy.
func containerNameForSlot(serviceID string, slot slots.Slot) string {
	if slot == slots.Legacy {
		return serviceID
	}
	return serviceID + "-" + string(slot)
}

// getIntPayloadOr is like database.go's getIntPayload but with a caller-
// supplied fallback for unset / wrong-type values. Rolling-deploy fields
// (healthCheckTimeoutSec, stopGraceSec) all have meaningful defaults that
// shouldn't collapse to 0 when the field is absent on older agents'
// payloads, hence the explicit fallback parameter.
func getIntPayloadOr(payload map[string]interface{}, key string, fallback int) int {
	v, ok := payload[key]
	if !ok || v == nil {
		return fallback
	}
	switch n := v.(type) {
	case float64:
		if n == 0 {
			return fallback
		}
		return int(n)
	case int:
		if n == 0 {
			return fallback
		}
		return n
	case int64:
		if n == 0 {
			return fallback
		}
		return int(n)
	}
	return fallback
}
