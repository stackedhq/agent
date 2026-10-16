package executor

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

	// Reject payload values that would end up in argv, paths or the
	// compose file before doing any work.
	if err := validateDeployPayload(serviceID, op.Payload); err != nil {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return nil, err
	}

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
	if creds.NetworkAliases, err = resolveNetworkAliases(creds.NetworkAliases); err != nil {
		return nil, fail(err)
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

	// The container env is rendered into docker-compose.yml as an
	// `environment:` map (see service_env.go); nothing is written to the
	// compose project's `.env` any more.
	env, envWarnings := serviceEnv(creds.EnvVars)
	addEnvWarnings(streamer, envWarnings)
	addLiteralEnvWarning(streamer, env)

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

	// Materialize managed file mounts only after the image is ready, but before
	// Compose can start the container. Their plaintext never enters the payload
	// or logs.
	volumeMounts, err := prepareVolumeHostDirs(serviceID, parseVolumes(op.Payload))
	if err != nil {
		return nil, fail(err)
	}
	fileMounts, err := e.prepareFileMounts(op, serviceID)
	if err != nil {
		return nil, fail(err)
	}
	mounts, err := mergeFileMounts(volumeMounts, fileMounts)
	if err != nil {
		return nil, fail(err)
	}
	startCommand := dockerCommandOverride(op.Payload)
	compose := generateCompose(serviceID, imageName, mounts, resourceLimitsFromPayload(op.Payload), creds.NetworkAliases, startCommand, env)
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := writeFile(composePath, compose); err != nil {
		return nil, fail(fmt.Errorf("write docker-compose.yml: %w", err))
	}
	if err := cleanupLegacyEnvFile(dir); err != nil {
		log.Printf("cleanup legacy .env for %s: %v", serviceID, err)
	}

	// Phase: Docker compose up (85%)
	streamer.SetProgress(85)
	streamer.AddLine("Starting container...")
	streamer.Flush()

	// Ensure the stacked network exists (idempotent, same as setup.go)
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	log.Printf("Starting container for %s", serviceID)
	if err := e.runCommandWithStreamer(streamer, dir, "docker", composeArgs(dir, "up", "-d", "--remove-orphans")...); err != nil {
		return nil, fail(fmt.Errorf("docker compose up: %w", err))
	}

	// Phase: Health probe (95%)
	streamer.SetProgress(95)
	probeRes := e.HealthProbe(streamer, serviceID, probePort)

	// Reconcile away any leftover blue/green state from a previous
	// rolling run on this service. Switching a service from `rolling`
	// back to `recreate` (or attaching a volume, which routes the next
	// rolling deploy through fast-restart) leaves the old <serviceID>-blue
	// container running, the slot state set, and the Caddyfile still
	// routing HTTP to that stale slot container. The new <serviceID>
	// container we just brought up would look healthy while no traffic
	// ever reaches it. Repoint Caddy at <serviceID> and tear down the
	// stale slots. No-op for services that were never rolling.
	reconcileUnslotted(streamer, serviceID, getIntPayloadOr(op.Payload, "stopGraceSec", 10))

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
	buildCommand := getStringPayload(op.Payload, "buildCommand")
	startCommand := getStringPayload(op.Payload, "startCommand")

	if gitBranch == "" {
		gitBranch = "main"
	}
	if !validGitBranch(gitBranch) {
		return "", fmt.Errorf("invalid git branch %q", truncateForError(gitBranch))
	}
	commitSha, err := normalizeCommitSha(getStringPayload(op.Payload, "commitSha"))
	if err != nil {
		return "", err
	}

	repoDir := filepath.Join(dir, "repo")

	gitRepo := creds.GitCloneUrl
	if gitRepo == "" {
		gitRepo = getStringPayload(op.Payload, "gitRepo")
		if gitRepo == "" {
			return "", fmt.Errorf("no git clone URL available")
		}
	}
	src, err := parseGitSource(gitRepo)
	if err != nil {
		return "", err
	}
	git, err := newGitSession(src)
	if err != nil {
		return "", err
	}
	defer git.Close()

	// Phase: Git clone/pull (2%)
	streamer.SetProgress(2)
	streamer.AddLine("Cloning repository...")
	streamer.Flush()

	// Clone or pull
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); os.IsNotExist(err) {
		log.Printf("Cloning into %s", repoDir)
		if err := e.runCommandWithStreamerEnv(streamer, dir, git.env, "git", gitCloneArgs(gitBranch, src.URL, "repo")...); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	} else {
		log.Printf("Pulling latest for %s", serviceID)
		// Always (re)point origin at the tokenless URL. This also scrubs
		// the token that older agents embedded in .git/config.
		if out, err := runCommandSilentEnv(repoDir, git.env, "git", gitSetRemoteArgs(src.URL)...); err != nil {
			return "", fmt.Errorf("git remote set-url: %s: %w", strings.TrimSpace(out), err)
		}
		if err := e.runCommandWithStreamerEnv(streamer, repoDir, git.env, "git", gitFetchBranchArgs(gitBranch)...); err != nil {
			return "", fmt.Errorf("git fetch: %w", err)
		}
		if err := e.runCommandWithStreamerEnv(streamer, repoDir, git.env, "git", gitResetArgs(gitBranch)...); err != nil {
			return "", fmt.Errorf("git reset: %w", err)
		}
	}

	// Checkout specific commit if requested
	if commitSha != "" {
		if err := e.runCommandWithStreamerEnv(streamer, repoDir, git.env, "git", gitCheckoutArgs(commitSha, gitSupportsEndOfOptions())...); err != nil {
			return "", fmt.Errorf("git checkout %s: %w", commitSha, err)
		}
	}

	// Phase: Nixpacks build (15%)
	streamer.SetProgress(15)
	streamer.AddLine("Building with Nixpacks...")
	streamer.Flush()

	imageName := "stacked-" + serviceID
	log.Printf("Building image with Nixpacks for %s", serviceID)

	nixpacksArgs, nixpacksEnv := nixpacksBuildArgs(repoDir, imageName, buildCommand, startCommand, creds.EnvVars)
	if err := e.runCommandWithStreamerEnv(streamer, dir, nixpacksEnv, "nixpacks", nixpacksArgs...); err != nil {
		return "", fmt.Errorf("nixpacks build: %w", err)
	}

	return imageName, nil
}

// nixpacksBuildArgs builds the `nixpacks build` argv and process env.
// Build env values are not put in argv: each var is passed as `--env=KEY`,
// which makes nixpacks read the value from its own environment. Names that
// would change how nixpacks, git or the docker CLI behave (PATH, HOME,
// DOCKER_*, NIXPACKS_*, ...) can't go through the process env, so those
// keep the `--env=KEY=VALUE` form; they are configuration, not secrets.
// Returns a nil env (inherit) when nothing needs to be passed.
//
// Note: nixpacks itself forwards build variables to `docker build` as
// `--build-arg KEY=VALUE`, so values are still briefly in that child's
// argv while the image builds.
func nixpacksBuildArgs(repoDir, imageName, buildCommand, startCommand string, vars map[string]string) ([]string, []string) {
	args := []string{"build", repoDir, "--name", imageName}
	if buildCommand != "" {
		args = append(args, "--build-cmd="+buildCommand)
	}
	if startCommand != "" {
		args = append(args, "--start-cmd="+startCommand)
	}
	var extra []string
	for _, k := range sortedKeys(vars) {
		if !validEnvKey(k) || strings.ContainsRune(vars[k], 0) {
			continue
		}
		if nixpacksArgvEnvKey(k) {
			args = append(args, "--env="+k+"="+vars[k])
			continue
		}
		args = append(args, "--env="+k)
		extra = append(extra, k+"="+vars[k])
	}
	if len(extra) == 0 {
		return args, nil
	}
	return args, mergeEnv(os.Environ(), extra)
}

func nixpacksArgvEnvKey(k string) bool {
	if dockerCLIEnvKey(k) {
		return true
	}
	u := strings.ToUpper(k)
	for _, p := range []string{"NIXPACKS_", "GIT_", "RUST_", "CARGO_"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	switch u {
	case "SHELL", "USER", "LOGNAME", "PWD", "IFS", "ENV", "BASH_ENV", "TZ", "LANG", "LC_ALL":
		return true
	}
	return false
}

// validateDeployPayload checks every deploy/release payload field that
// reaches argv, a path, or the compose file. Pure (no filesystem access).
func validateDeployPayload(serviceID string, payload map[string]interface{}) error {
	if !isUUID(serviceID) {
		return fmt.Errorf("invalid serviceId")
	}
	if img := getStringPayload(payload, "dockerImage"); img != "" {
		if err := validateImageReference(img); err != nil {
			return err
		}
	}
	if err := validateRestartPolicy(resourceLimitsFromPayload(payload).restartPolicy); err != nil {
		return err
	}
	if b := getStringPayload(payload, "gitBranch"); b != "" && !validGitBranch(b) {
		return fmt.Errorf("invalid git branch %q", truncateForError(b))
	}
	if _, err := normalizeCommitSha(getStringPayload(payload, "commitSha")); err != nil {
		return err
	}
	if _, err := validateVolumes(serviceID, parseVolumes(payload)); err != nil {
		return err
	}
	return nil
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

func generateCompose(serviceID, imageName string, mounts []volumeMount, limits resourceLimits, aliases []string, startCommand string, env map[string]string) string {
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
	// Every scalar is rendered through compose_yaml.go: JSON-quoted with
	// `$` escaped, so no payload value can add YAML structure or trigger
	// Compose interpolation.
	//
	// The `volumes:` key is emitted only when there are mounts — omitting
	// the key entirely is intentional (some compose versions read an empty
	// `volumes:` as "remove previously configured volumes"). Callers
	// (deploy.go, deploy_rolling.go) are responsible for
	// `prepareVolumeHostDirs` before invoking `docker compose up` so the
	// bind sources exist with predictable mode/ownership.
	//
	// Resource block: restart policy is always emitted; mem_limit / cpus
	// only when the service has a configured cap (otherwise the container
	// runs unlimited, matching the historical behaviour). `mem_limit` and
	// `cpus` are both honoured by `docker compose up` in non-swarm mode.
	svc := yMap{
		{Key: "container_name", Value: yStr(serviceID)},
		{Key: "image", Value: yStr(imageName)},
		{Key: "restart", Value: yStr(limits.restartPolicy)},
	}
	if limits.memoryMB > 0 {
		svc = append(svc, yKV{Key: "mem_limit", Value: yStr(fmt.Sprintf("%dm", limits.memoryMB))})
	}
	if c := limits.cpus(); c != "" {
		svc = append(svc, yKV{Key: "cpus", Value: yRaw(c)})
	}
	if cmd := composeCommand(startCommand); cmd != nil {
		svc = append(svc, yKV{Key: "command", Value: cmd})
	}
	if len(env) > 0 {
		svc = append(svc, yKV{Key: "environment", Value: composeEnvironment(env)})
	}
	if len(mounts) > 0 {
		svc = append(svc, yKV{Key: "volumes", Value: composeVolumeSpecs(mounts)})
	}
	svc = append(svc,
		yKV{Key: "networks", Value: serviceNetworks(aliases)},
		yKV{Key: "labels", Value: yMap{{Key: "com.stacked.kind", Value: yStr("service")}}},
	)
	return renderYAML(yMap{
		{Key: "services", Value: yMap{{Key: serviceID, Value: svc}}},
		{Key: "networks", Value: stackedNetworkDecl()},
	})
}

// stackedNetworkDecl is the shared external `stacked` network.
func stackedNetworkDecl() yMap {
	return yMap{{Key: "stacked", Value: yMap{
		{Key: "name", Value: yStr("stacked")},
		{Key: "external", Value: yRaw("true")},
	}}}
}

// dockerCommandOverride returns the start command for docker-image
// services. The compose path renders it as an exec-form `command:` and the
// rolling `docker run` path appends it after the image; both execute it
// through a shell while preserving the image ENTRYPOINT.
func dockerCommandOverride(payload map[string]interface{}) string {
	if getStringPayload(payload, "dockerImage") == "" {
		return ""
	}
	return strings.TrimSpace(getStringPayload(payload, "startCommand"))
}

// composeCommand returns the exec-form `command:` list, or nil when unset.
func composeCommand(command string) yNode {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	return yStrList("sh", "-lc", command)
}

// serviceNetworks renders the service-level `networks:` value. With no
// friendly aliases it's the historical list form (`- stacked`). With aliases
// it switches to the map form so we can attach extra `--network-alias` values
// (the human-readable internal hostnames). Docker still registers the compose
// service key (`<serviceID>`) as an alias in both forms, so the UUID floor is
// preserved regardless.
func serviceNetworks(aliases []string) yNode {
	var valid []string
	for _, a := range aliases {
		// Defense-in-depth: the server allocates these from a strict slug,
		// but skip anything that isn't a plausible DNS label.
		if validNetworkAlias(a) {
			valid = append(valid, a)
		}
	}
	if len(valid) == 0 {
		return yStrList("stacked")
	}
	return yMap{{Key: "stacked", Value: yMap{{Key: "aliases", Value: yStrList(valid...)}}}}
}

// validNetworkAlias mirrors the server's slug constraints: a lowercase DNS
// label, 1–63 chars, alphanumeric with internal hyphens, and not a name
// reserved for Stacked infrastructure (see aliases.go). Names of existing
// containers are filtered separately by resolveNetworkAliases, which
// needs docker.
var networkAliasRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func validNetworkAlias(s string) bool {
	return networkAliasRe.MatchString(s) && !isReservedAlias(s)
}
