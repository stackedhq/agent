package executor

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

func (e *Executor) Deploy(op client.Operation) (map[string]interface{}, error) {
	serviceID := getStringPayload(op.Payload, "serviceId")
	dockerImage := getStringPayload(op.Payload, "dockerImage")

	if serviceID == "" {
		return nil, fmt.Errorf("deploy requires serviceId in payload")
	}

	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("create service dir: %w", err)
	}

	// Create a single streamer for the entire deploy lifecycle
	streamer := logs.NewStreamer(e.Client, op.ID)

	// Branch on deploy strategy. `recreate` (default, blank, or older
	// agents that don't read the field) follows the historical
	// in-place container replacement path defined in the rest of this
	// function. `rolling` hands off to deployRolling, which owns the
	// blue/green and fast-restart paths.
	if strategy := getStringPayload(op.Payload, "deployStrategy"); strategy == "rolling" {
		return e.deployRolling(op, streamer)
	}

	// Write deploy errors to the log stream so they appear in the UI
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	// Default port mirrors the server-side schema default. Older servers
	// that don't yet include `port` in the credentials response still get
	// a sensible probe target.
	probePort := 3000

	// Phase: Fetching credentials (0%)
	streamer.SetProgress(0)
	streamer.AddLine("Fetching credentials...")
	streamer.Flush()

	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		// Typed credentials error from the server (e.g. GitHub App not
		// installed for the repo's owner). Surface the server's human
		// message verbatim instead of wrapping in `get credentials:` —
		// the message is already actionable for the end user.
		var credErr *client.CredentialsError
		if errors.As(err, &credErr) {
			return nil, fail(fmt.Errorf("%s", credErr.Message))
		}
		return nil, fail(fmt.Errorf("get credentials: %w", err))
	}
	// Honor an explicit port from the server, including 0 (worker service
	// — HealthProbe skips the TCP probe for non-positive ports). Only fall
	// back to the 3000 default when the field is absent (older server).
	if creds.Port != nil {
		probePort = *creds.Port
	}

	streamer.SetProgress(2)
	streamer.AddLine("Credentials received")
	streamer.Flush()

	// Authenticate with GHCR if a registry token was provided
	if creds.RegistryToken != "" {
		log.Printf("Logging in to ghcr.io for %s", serviceID)
		cmd := exec.Command("docker", "login", "ghcr.io", "-u", "x-access-token", "--password-stdin")
		cmd.Stdin = strings.NewReader(creds.RegistryToken)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("GHCR login failed (non-fatal): %s", string(out))
		}
	}

	// Inject HOST=0.0.0.0 so apps bind to all interfaces (reachable by Caddy on Docker network)
	if _, hasHost := creds.EnvVars["HOST"]; !hasHost {
		if creds.EnvVars == nil {
			creds.EnvVars = make(map[string]string)
		}
		creds.EnvVars["HOST"] = "0.0.0.0"
	}

	// Write .env file from server-managed env vars
	if len(creds.EnvVars) > 0 {
		envContent := buildEnvFile(creds.EnvVars)
		envPath := filepath.Join(dir, ".env")
		if err := writeFile(envPath, envContent); err != nil {
			return nil, fail(fmt.Errorf("write .env: %w", err))
		}
	} else {
		// Ensure .env exists (docker compose requires it with env_file directive)
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); os.IsNotExist(err) {
			if err := writeFile(envPath, ""); err != nil {
				return nil, fail(fmt.Errorf("write .env: %w", err))
			}
		}
	}

	var imageName string

	if dockerImage != "" {
		// Docker image mode: pull the pre-built image
		imageName = dockerImage
		streamer.SetProgress(2)
		streamer.AddLine("Pulling Docker image " + imageName + "...")
		streamer.Flush()

		log.Printf("Pulling Docker image %s for %s", imageName, serviceID)
		if err := e.runCommandWithStreamer(streamer, dir, "docker", "pull", imageName); err != nil {
			return nil, fail(fmt.Errorf("docker pull %s: %w", imageName, err))
		}
	} else {
		// VPS build mode: clone repo + build with Nixpacks
		imageName, err = e.buildFromSource(op, serviceID, dir, creds, streamer)
		if err != nil {
			return nil, fail(err)
		}
	}

	// Generate docker-compose.yml using the image. Volumes are pulled
	// from the op payload — absent / empty / malformed payloads yield
	// an empty mounts list and the template renders identically to the
	// pre-host-volumes version.
	mounts := parseVolumes(op.Payload)
	if err := ensureVolumeHostDirs(mounts); err != nil {
		return nil, fail(err)
	}
	compose := generateCompose(serviceID, imageName, mounts, resourceLimitsFromPayload(op.Payload), creds.NetworkAliases)
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return nil, fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}

	// Phase: Docker compose up (85%)
	streamer.SetProgress(85)
	streamer.AddLine("Starting container...")
	streamer.Flush()

	// Ensure the stacked network exists (idempotent, same as setup.go)
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	log.Printf("Starting container for %s", serviceID)
	if err := e.runCommandWithStreamer(streamer, dir, "docker", "compose", "up", "-d", "--remove-orphans"); err != nil {
		return nil, fail(fmt.Errorf("docker compose up: %w", err))
	}

	// Phase: Health probe (95%)
	streamer.SetProgress(95)
	probeRes := e.HealthProbe(streamer, serviceID, probePort)

	// Phase: Complete (100%)
	streamer.SetProgress(100)
	streamer.AddLine("Deploy complete")
	streamer.Flush()

	log.Printf("Deploy complete for %s", serviceID)

	result := map[string]interface{}{
		"probeOk":             probeRes.Ok,
		"exposedPorts":        probeRes.ExposedPorts,
		"exposedPortsUnknown": probeRes.ExposedPortsUnknown,
	}
	if probeRes.Error != "" {
		result["probeError"] = probeRes.Error
	}
	return result, nil
}

// buildFromSource clones the repo and builds an image with Nixpacks.
func (e *Executor) buildFromSource(op client.Operation, serviceID, dir string, creds *client.Credentials, streamer *logs.Streamer) (string, error) {
	gitBranch := getStringPayload(op.Payload, "gitBranch")
	commitSha := getStringPayload(op.Payload, "commitSha")
	buildCommand := getStringPayload(op.Payload, "buildCommand")
	startCommand := getStringPayload(op.Payload, "startCommand")

	if gitBranch == "" {
		gitBranch = "main"
	}

	repoDir := filepath.Join(dir, "repo")

	gitRepo := creds.GitCloneUrl
	if gitRepo == "" {
		gitRepo = getStringPayload(op.Payload, "gitRepo")
		if gitRepo == "" {
			return "", fmt.Errorf("no git clone URL available")
		}
	}

	// Phase: Git clone/pull (2%)
	streamer.SetProgress(2)
	streamer.AddLine("Cloning repository...")
	streamer.Flush()

	// Clone or pull
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		log.Printf("Cloning into %s", repoDir)
		if err := e.runCommandWithStreamer(streamer, dir, "git", "clone", "--branch", gitBranch, "--single-branch", gitRepo, "repo"); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	} else {
		log.Printf("Pulling latest for %s", serviceID)
		_, _ = runCommandSilent(repoDir, "git", "remote", "set-url", "origin", gitRepo)
		if err := e.runCommandWithStreamer(streamer, repoDir, "git", "fetch", "origin"); err != nil {
			return "", fmt.Errorf("git fetch: %w", err)
		}
		if err := e.runCommandWithStreamer(streamer, repoDir, "git", "reset", "--hard", "origin/"+gitBranch); err != nil {
			return "", fmt.Errorf("git reset: %w", err)
		}
	}

	// Checkout specific commit if requested
	if commitSha != "" {
		if err := e.runCommandWithStreamer(streamer, repoDir, "git", "checkout", commitSha); err != nil {
			return "", fmt.Errorf("git checkout %s: %w", commitSha, err)
		}
	}

	// Phase: Nixpacks build (15%)
	streamer.SetProgress(15)
	streamer.AddLine("Building with Nixpacks...")
	streamer.Flush()

	imageName := "stacked-" + serviceID
	log.Printf("Building image with Nixpacks for %s", serviceID)

	nixpacksArgs := []string{"build", repoDir, "--name", imageName}
	if buildCommand != "" {
		nixpacksArgs = append(nixpacksArgs, "--build-cmd", buildCommand)
	}
	if startCommand != "" {
		nixpacksArgs = append(nixpacksArgs, "--start-cmd", startCommand)
	}
	for k, v := range creds.EnvVars {
		nixpacksArgs = append(nixpacksArgs, "--env", k+"="+v)
	}

	if err := e.runCommandWithStreamer(streamer, dir, "nixpacks", nixpacksArgs...); err != nil {
		return "", fmt.Errorf("nixpacks build: %w", err)
	}

	return imageName, nil
}

// buildEnvFile creates a .env file content from a key-value map.
// Keys are sorted for deterministic output.
func buildEnvFile(vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		// Quote values that contain spaces, newlines, or special chars
		v := vars[k]
		if strings.ContainsAny(v, " \t\n\"'$`\\#") {
			v = "\"" + strings.ReplaceAll(strings.ReplaceAll(v, "\\", "\\\\"), "\"", "\\\"") + "\""
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

// resourceLimits captures the per-container CPU/memory caps and restart
// policy from a deploy op payload. Zero limit values mean "unset" ->
// unlimited; an empty restart policy falls back to unless-stopped. Both
// deploy paths apply these: the recreate path threads them into the
// compose template (generateCompose), the rolling path into `docker run`
// flags (runRollingContainer).
type resourceLimits struct {
	cpuMillicores int    // 1000 = 1 CPU core; <=0 = unlimited
	memoryMB      int    // <=0 = unlimited
	restartPolicy string // docker/compose restart policy
}

func resourceLimitsFromPayload(payload map[string]interface{}) resourceLimits {
	rp := getStringPayload(payload, "restartPolicy")
	if rp == "" {
		rp = "unless-stopped"
	}
	return resourceLimits{
		cpuMillicores: getIntPayload(payload, "cpuLimit"),
		memoryMB:      getIntPayload(payload, "memoryLimitMb"),
		restartPolicy: rp,
	}
}

// cpus renders the CPU cap as a docker/compose decimal core count
// (e.g. 1500 millicores -> "1.5"). Empty string when unset.
func (l resourceLimits) cpus() string {
	if l.cpuMillicores <= 0 {
		return ""
	}
	s := strconv.FormatFloat(float64(l.cpuMillicores)/1000.0, 'f', 3, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func generateCompose(serviceID, imageName string, mounts []volumeMount, limits resourceLimits, aliases []string) string {
	// `com.stacked.kind: service` lets the runtimelogs and databaselogs
	// managers correctly partition `docker ps` output. The runtimelogs
	// manager treats label-less containers as services for back-compat
	// with already-deployed services that pre-date this label — they keep
	// streaming until their next deploy picks up the new template.
	// `container_name` pins the container's name to the serviceID so probe.go
	// (and any other agent code path keyed by serviceID) can resolve it via
	// `docker inspect <serviceID>`. Without this, compose would name the
	// container `<project>-<service>-1` (project = workdir basename =
	// serviceID, service = serviceID), which `docker inspect <serviceID>`
	// cannot match — making every post-deploy health probe fail with
	// `docker inspect: exit status 1`. Databases (database.go) already do
	// this; services were missing it.
	//
	// The `volumes:` block is spliced in only when there are mounts —
	// omitting the key entirely is intentional (some compose versions
	// read an empty `volumes:` as "remove previously configured
	// volumes", which would conflict with the historical no-volumes
	// template). Callers (deploy.go, deploy_rolling.go) are responsible
	// for `ensureVolumeHostDirs` before invoking `docker compose up` so
	// the bind sources exist with predictable mode/ownership.
	volumesBlock := renderComposeVolumes(mounts)
	// Resource block: restart policy is always emitted; mem_limit / cpus
	// only when the service has a configured cap (otherwise the container
	// runs unlimited, matching the historical behaviour). `mem_limit` and
	// `cpus` are both honoured by `docker compose up` in non-swarm mode.
	var resourceBlock strings.Builder
	resourceBlock.WriteString("    restart: " + limits.restartPolicy + "\n")
	if limits.memoryMB > 0 {
		fmt.Fprintf(&resourceBlock, "    mem_limit: %dm\n", limits.memoryMB)
	}
	if c := limits.cpus(); c != "" {
		resourceBlock.WriteString("    cpus: " + c + "\n")
	}
	return fmt.Sprintf(`services:
  %s:
    container_name: %s
    image: %s
%s    env_file:
      - .env
%s%s    labels:
      com.stacked.kind: service

networks:
  stacked:
    name: stacked
    external: true
`, serviceID, serviceID, imageName, resourceBlock.String(), volumesBlock, renderServiceNetworks(aliases))
}

// renderServiceNetworks emits the service-level `networks:` block. With no
// friendly aliases it's the historical list form (`- stacked`). With aliases
// it switches to the map form so we can attach extra `--network-alias` values
// (the human-readable internal hostnames). Docker still registers the compose
// service key (`<serviceID>`) as an alias in both forms, so the UUID floor is
// preserved regardless.
func renderServiceNetworks(aliases []string) string {
	if len(aliases) == 0 {
		return "    networks:\n      - stacked\n"
	}
	var b strings.Builder
	b.WriteString("    networks:\n      stacked:\n        aliases:\n")
	for _, a := range aliases {
		// Defense-in-depth: the server allocates these from a strict slug,
		// but skip anything that isn't a plausible DNS label so a bad value
		// can't corrupt the compose file.
		if !validNetworkAlias(a) {
			continue
		}
		fmt.Fprintf(&b, "          - %s\n", a)
	}
	return b.String()
}

// validNetworkAlias mirrors the server's slug constraints: a lowercase DNS
// label, 1–63 chars, alphanumeric with internal hyphens.
var networkAliasRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validNetworkAlias(s string) bool {
	return networkAliasRe.MatchString(s)
}
