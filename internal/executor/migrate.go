package executor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// DBMigrate dumps a Dokploy-managed source database container into a
// Stacked-managed target container on the SAME VPS via a piped
// `dump | restore`. Same-VPS is a hard v1 assumption — both containers
// are reachable through the local docker socket, so we don't deal with
// SSH tunnels or cross-host networking.
//
// Source data is never modified. Target data IS dropped + recreated on
// every run to guarantee idempotent retries: a botched first attempt
// leaves clean state for the second.
//
// Credentials are fetched on-demand from the server via
// `GetMigrationCredentials` so the operations.payload column never holds
// plaintext source credentials.
func (e *Executor) DBMigrate(op client.Operation) error {
	targetID := getStringPayload(op.Payload, "migrationTargetId")
	dbType := getStringPayload(op.Payload, "dbType")
	if targetID == "" {
		return fmt.Errorf("db_migrate requires migrationTargetId")
	}
	if dbType == "" {
		return fmt.Errorf("db_migrate requires dbType")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("Fetching migration credentials for target %s", targetID))
	streamer.Flush()

	creds, err := e.Client.GetMigrationCredentials(targetID)
	if err != nil {
		return fail(fmt.Errorf("fetch migration credentials: %w", err))
	}
	if creds.Kind != "database" {
		return fail(fmt.Errorf("db_migrate target is not kind=database (got %q)", creds.Kind))
	}
	if creds.Source == nil || creds.Target == nil {
		return fail(fmt.Errorf("db_migrate credentials missing source or target"))
	}

	srcContainer := creds.Source.ContainerName
	tgtContainer := creds.Target.ContainerName
	srcCreds := creds.Source.Creds
	tgtCreds := creds.Target.Creds

	if srcContainer == "" || tgtContainer == "" {
		return fail(fmt.Errorf("migration credentials missing container names"))
	}
	if err := checkContainerName("source", srcContainer); err != nil {
		return fail(err)
	}
	if err := checkContainerName("target", tgtContainer); err != nil {
		return fail(err)
	}

	streamer.AddLine(fmt.Sprintf("Source: %s (Dokploy) → Target: %s (Stacked)", srcContainer, tgtContainer))
	streamer.Flush()

	// --- Pre-flight probes ---
	streamer.SetProgress(10)
	streamer.AddLine("Running pre-flight probes…")
	streamer.Flush()

	if err := assertContainerRunning(srcContainer); err != nil {
		return fail(fmt.Errorf("source container %s not running: %w", srcContainer, err))
	}
	if err := assertContainerRunning(tgtContainer); err != nil {
		return fail(fmt.Errorf("target container %s not running: %w", tgtContainer, err))
	}

	_, restoreTool := dumpToolsForEngine(dbType)
	if requiredTool, err := assertDumpToolInContainer(dbType, srcContainer); err != nil {
		return fail(fmt.Errorf("%s not available in source container %s — most often caused by an alpine/slim variant. Re-create the source DB in Dokploy using the non-alpine image, or migrate manually. (%w)", requiredTool, srcContainer, err))
	}
	if err := assertToolInContainer(tgtContainer, restoreTool); err != nil {
		return fail(fmt.Errorf("%s not available in target container %s: %w", restoreTool, tgtContainer, err))
	}

	// --- Target cleanup (idempotent retry) ---
	streamer.SetProgress(25)
	streamer.AddLine("Resetting target database for idempotent restore…")
	streamer.Flush()
	if err := resetTarget(streamer, dbType, tgtContainer, tgtCreds); err != nil {
		return fail(fmt.Errorf("reset target: %w", err))
	}

	// --- Dump → restore pipeline ---
	streamer.SetProgress(40)
	streamer.AddLine(fmt.Sprintf("Streaming %s dump from source into target…", dbType))
	streamer.Flush()

	if err := runMigrationPipe(streamer, dbType, srcContainer, tgtContainer, srcCreds, tgtCreds); err != nil {
		return fail(fmt.Errorf("dump|restore pipeline: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Database migration complete.")
	streamer.Flush()
	return nil
}

// VolumeMigrate copies the contents of a Dokploy volume or config path into
// a Stacked service's managed host path. The copy runs in a short-lived
// alpine container with `cp -a`, so we don't depend on rsync on the host and
// can read data the (non-root) agent user can't.
//
// Hardening:
//   - the source must be under /etc/dokploy or a docker volume's _data dir
//     (migrateSourceRoots); the target must be inside the managed root;
//   - only the fixed allowlisted root is bind-mounted (read-only), and the
//     path below it is walked inside the container, refusing any symlink
//     component. Inside the container a symlink can only resolve within the
//     container's own filesystem, never to arbitrary host paths, which a
//     bind mount of the raw source path would allow (the daemon resolves
//     symlinks on the host);
//   - the container runs as root, because Dokploy data is typically owned
//     by root or a container uid with 0700 dirs and `cp -a` must preserve
//     ownership. It gets only the capabilities cp needs (CHOWN,
//     DAC_OVERRIDE, FOWNER, FSETID), no network and no-new-privileges.
//
// Target contents are replaced on every run for idempotent retries.
func (e *Executor) VolumeMigrate(op client.Operation) error {
	srcPath := getStringPayload(op.Payload, "sourceVolumePath")
	tgtPath := getStringPayload(op.Payload, "targetVolumePath")

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	cleanSrcPath, cleanTgtPath, err := validateMigratePaths(srcPath, tgtPath)
	if err != nil {
		return fail(err)
	}
	srcPath = cleanSrcPath
	tgtPath = cleanTgtPath
	srcMount, srcRel, err := migrateSourceMount(srcPath)
	if err != nil {
		return fail(err)
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("Volume copy: %s → %s", srcPath, tgtPath))
	streamer.Flush()

	// Host-side symlink checks. The source walk is best effort (the agent
	// user often can't traverse /var/lib/docker); the in-container walk
	// below is authoritative. The target is agent-owned, so it is strict.
	if err := rejectSymlinksInPath(srcPath, true); err != nil {
		return fail(fmt.Errorf("source %s: %w", srcPath, err))
	}
	if err := rejectSymlinksInPath(tgtPath, false); err != nil {
		return fail(fmt.Errorf("target %s: %w", tgtPath, err))
	}
	tgtParent := filepath.Dir(tgtPath)
	if err := ensureDir(tgtParent); err != nil {
		return fail(fmt.Errorf("create target parent dir: %w", err))
	}
	if err := rejectSymlinksInPath(tgtParent, false); err != nil {
		return fail(fmt.Errorf("target %s: %w", tgtParent, err))
	}

	streamer.SetProgress(25)
	streamer.AddLine("Copying with `cp -a` to preserve perms/ownership…")
	streamer.Flush()

	args := volumeMigrateDockerArgs(srcMount, srcRel, tgtParent, filepath.Base(tgtPath))
	if err := e.runCommandWithStreamer(streamer, "", "docker", args...); err != nil {
		return fail(fmt.Errorf("volume copy: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Volume migration complete.")
	streamer.Flush()
	return nil
}

// migrateHelperImage runs the volume copy. Pinned by digest.
// Tag: alpine:3.20 (multi-arch index digest).
const migrateHelperImage = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// volumeMigrateScript runs inside the helper container. $1 is the source
// path relative to /src ("." for /src itself), $2 the target name inside
// /dst. Every source component is checked with `-L` before use; `set -f`
// stops the IFS split from globbing.
const volumeMigrateScript = `set -euf
rel="$1"
name="$2"
src=/src
if [ "$rel" != "." ]; then
  IFS=/
  for part in $rel; do
    [ -n "$part" ] || continue
    src="$src/$part"
    if [ -L "$src" ]; then
      echo "stacked: refusing to copy: source path component '$part' is a symlink" >&2
      exit 3
    fi
  done
  unset IFS
fi
dst="/dst/$name"
if [ -d "$src" ]; then
  rm -rf -- "$dst"
  mkdir -- "$dst"
  cp -a -- "$src/." "$dst/"
elif [ -f "$src" ]; then
  rm -rf -- "$dst"
  cp -a -- "$src" "$dst"
else
  echo "stacked: source path does not exist on host (or is not a file or directory); cannot migrate volume contents" >&2
  exit 4
fi
`

// volumeMigrateDockerArgs builds the helper `docker run`. The source root is
// mounted read-only; the target's parent is the only writable mount.
func volumeMigrateDockerArgs(srcMount, srcRel, tgtParent, tgtName string) []string {
	return []string{
		"run", "--rm",
		"--network", "none",
		"--cap-drop", "ALL",
		"--cap-add", "CHOWN",
		"--cap-add", "DAC_OVERRIDE",
		"--cap-add", "FOWNER",
		"--cap-add", "FSETID",
		"--security-opt", "no-new-privileges",
		"--label", "com.stacked.kind=job",
		"--label", "com.stacked.job=volume-migrate",
		"--mount", "type=bind,source=" + srcMount + ",target=/src,readonly",
		"--mount", "type=bind,source=" + tgtParent + ",target=/dst",
		migrateHelperImage,
		"sh", "-c", volumeMigrateScript, "sh", srcRel, tgtName,
	}
}

// migrateSourceRoots are the only places volume_migrate copies from: Dokploy's
// config/files tree and docker named-volume data.
const (
	dokployConfigRoot = "/etc/dokploy"
	dockerVolumesRoot = "/var/lib/docker/volumes"
)

// migrateSourceMount splits a cleaned source path into the fixed directory
// to bind-mount and the path below it. Docker volumes mount their `_data`
// dir (`<root>/<name>/_data`), which only root on the host can replace;
// Dokploy paths mount /etc/dokploy.
func migrateSourceMount(src string) (mount, rel string, err error) {
	switch {
	case pathStrictlyUnder(src, dockerVolumesRoot):
		parts := strings.Split(strings.TrimPrefix(src, dockerVolumesRoot+"/"), "/")
		if len(parts) < 2 || parts[1] != "_data" || parts[0] == "" {
			return "", "", fmt.Errorf("volume_migrate source %s must be inside a docker volume's _data directory", src)
		}
		mount = filepath.Join(dockerVolumesRoot, parts[0], "_data")
		rel = strings.Join(parts[2:], "/")
	case pathStrictlyUnder(src, dokployConfigRoot):
		mount = dokployConfigRoot
		rel = strings.TrimPrefix(src, dokployConfigRoot+"/")
	default:
		return "", "", fmt.Errorf("volume_migrate source %s is outside the allowed roots (%s, %s/<volume>/_data)", src, dokployConfigRoot, dockerVolumesRoot)
	}
	if rel == "" {
		rel = "."
	}
	return mount, rel, nil
}

func pathStrictlyUnder(path, root string) bool {
	return strings.HasPrefix(path, root+"/") && len(path) > len(root)+1
}

// rejectSymlinksInPath Lstat-walks every existing component of an absolute
// path and fails on a symlink. A missing component ends the walk (it will be
// created, or the copy reports it). With bestEffort, a component the agent
// may not stat (EACCES) also ends the walk instead of failing.
func rejectSymlinksInPath(path string, bestEffort bool) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			if bestEffort && os.IsPermission(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %s is a symlink", current)
		}
	}
	return nil
}

// validateMigratePaths returns cleaned source and target paths after
// enforcing the agent-side security boundary for volume migrations. The
// source must sit under an allowlisted root (migrateSourceMount). The
// target is destructive (replaced + writable docker mount), so it must stay
// inside Stacked's managed volume namespace, at least one level below a
// service dir, both lexically and after resolving symlinks in the existing
// path prefix.
func validateMigratePaths(srcPath, tgtPath string) (string, string, error) {
	return validateMigratePathsWithRoot(srcPath, tgtPath, managedVolumeRoot)
}

func validateMigratePathsWithRoot(srcPath, tgtPath, managedRoot string) (string, string, error) {
	cleanSrc, err := cleanMigratePath("source", srcPath)
	if err != nil {
		return "", "", err
	}
	if _, _, err := migrateSourceMount(cleanSrc); err != nil {
		return "", "", err
	}
	cleanTgt, err := cleanMigratePath("target", tgtPath)
	if err != nil {
		return "", "", err
	}

	if !isPathUnderManagedRoot(cleanTgt, managedRoot) {
		return "", "", fmt.Errorf("volume_migrate target path %s is outside managed volume root %s", cleanTgt, filepath.Clean(managedRoot))
	}
	rel, err := filepath.Rel(filepath.Clean(managedRoot), cleanTgt)
	if err != nil || len(strings.Split(rel, string(os.PathSeparator))) < 2 {
		return "", "", fmt.Errorf("volume_migrate target path %s must be a volume inside a service directory", cleanTgt)
	}

	resolvedTarget, err := resolveExistingPathPrefix(cleanTgt)
	if err != nil {
		return "", "", fmt.Errorf("resolve target path %s: %w", cleanTgt, err)
	}
	if !isPathUnderManagedRoot(resolvedTarget, managedRoot) {
		return "", "", fmt.Errorf("volume_migrate target path %s resolves outside managed volume root %s", cleanTgt, filepath.Clean(managedRoot))
	}

	return cleanSrc, cleanTgt, nil
}

func cleanMigratePath(kind, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("volume_migrate requires %sVolumePath", kind)
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("volume_migrate %s path contains NUL byte", kind)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("volume_migrate %s path must be absolute", kind)
	}
	if hasDotDotSegment(path) {
		return "", fmt.Errorf("volume_migrate %s path must not contain '..' segments", kind)
	}
	return filepath.Clean(path), nil
}

func hasDotDotSegment(path string) bool {
	for _, part := range strings.Split(path, string(os.PathSeparator)) {
		if part == ".." {
			return true
		}
	}
	return false
}

func isPathUnderManagedRoot(path, managedRoot string) bool {
	cleanPath := filepath.Clean(path)
	if managedRoot == managedVolumeRoot {
		return isManagedHostPath(cleanPath)
	}
	cleanRoot := filepath.Clean(managedRoot)
	return strings.HasPrefix(cleanPath, cleanRoot+string(os.PathSeparator))
}

func resolveExistingPathPrefix(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			rel, err := filepath.Rel(current, path)
			if err != nil {
				return "", err
			}
			if rel == "." {
				return filepath.Clean(resolved), nil
			}
			return filepath.Clean(filepath.Join(resolved, rel)), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor")
		}
		current = parent
	}
}

// dumpToolsForEngine returns (source-side tool, target-side tool) for
// pre-flight probes. We probe both: an alpine target image is missing
// pg_restore just as readily as an alpine source is missing pg_dump.
func dumpToolsForEngine(engine string) (string, string) {
	switch engine {
	case "postgres":
		return "pg_dump", "pg_restore"
	case "mysql", "mariadb":
		return "mysqldump", "mysql"
	case "mongo":
		return "mongodump", "mongorestore"
	}
	return "", ""
}

// assertContainerRunning confirms a container exists and is in `running` state.
// Returns a typed error message the pre-flight surface can show verbatim.
func assertContainerRunning(name string) error {
	out, err := opCommand("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker inspect %s: %s", name, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("container %s is not running (State.Running=%s)", name, strings.TrimSpace(string(out)))
	}
	return nil
}

// assertDumpToolInContainer is the pre-flight check for the source-side
// dump tool. MySQL-family containers may ship `mysqldump` or only
// `mariadb-dump` (mariadb:11 dropped the mysql* names), so either counts.
// Returns the tool name for error messages.
func assertDumpToolInContainer(engine, container string) (string, error) {
	tool, _ := dumpToolsForEngine(engine)
	if engine == "mysql" || engine == "mariadb" {
		found, err := detectMySQLDumpTool(container)
		if err != nil {
			return "mysqldump/mariadb-dump", err
		}
		return found.name, nil
	}
	return tool, assertToolInContainer(container, tool)
}

// mysqlDumpTool is the dump binary found in a MySQL-family container and
// whether it is MariaDB's. The zero value is MySQL's `mysqldump`.
type mysqlDumpTool struct {
	name    string
	mariaDB bool
}

// detectMySQLDumpTool finds the dump binary in container (`mysqldump`,
// else `mariadb-dump`) and asks it for its version: MariaDB's dump tool
// rejects MySQL-only flags such as --set-gtid-purged.
func detectMySQLDumpTool(container string) (mysqlDumpTool, error) {
	var lastErr error
	for _, name := range []string{"mysqldump", "mariadb-dump"} {
		out, err := opCommand("docker", "exec", container, name, "--version").CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("%s --version: %v: %s", name, err, strings.TrimSpace(string(out)))
			continue
		}
		return mysqlDumpTool{name: name, mariaDB: name == "mariadb-dump" || isMariaDBVersion(string(out))}, nil
	}
	return mysqlDumpTool{}, fmt.Errorf("neither mysqldump nor mariadb-dump found inside %s (%v)", container, lastErr)
}

// isMariaDBVersion reports whether a `mysqldump --version` banner is
// MariaDB's (e.g. "mysqldump  Ver 10.19 Distrib 10.11.6-MariaDB, ...").
func isMariaDBVersion(banner string) bool {
	return strings.Contains(strings.ToLower(banner), "mariadb")
}

// argv is the dump command line for dbName (without `docker exec`).
func (t mysqlDumpTool) argv(dbName string) []string {
	name := t.name
	if name == "" {
		name = "mysqldump"
	}
	args := []string{name, "-u", "root", "--single-transaction", "--routines", "--triggers"}
	if !t.mariaDB {
		// MySQL with GTIDs on would otherwise emit SET @@GLOBAL.GTID_PURGED,
		// which fails to restore into a server with its own GTID history.
		args = append(args, "--set-gtid-purged=OFF")
	}
	return append(args, dbName)
}

// assertToolInContainer checks `which <tool>` inside the container.
// Detects the alpine/slim image footgun before we ever start a destructive
// drop on the target. Returns an actionable error if the tool is missing.
func assertToolInContainer(container, tool string) error {
	if tool == "" {
		return nil
	}
	cmd := opCommand("docker", "exec", container, "which", tool)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("`%s` not found inside %s (which exit: %v)", tool, container, err)
	}
	return nil
}

// resetTarget drops + recreates the target database/collection so retries
// always start from a clean slate. Mongo handles this via `mongorestore
// --drop` per-collection so we skip the up-front reset.
func resetTarget(streamer *logs.Streamer, engine, container string, creds map[string]string) error {
	switch engine {
	case "postgres":
		user := creds["user"]
		password := creds["password"]
		dbName := creds["dbName"]
		if user == "" || dbName == "" {
			return fmt.Errorf("target postgres creds missing user/dbName")
		}
		// Drop + create against the `postgres` admin database so we can
		// nuke the target DB itself. Force-drop terminates open conns
		// (none should be open since the target was just provisioned,
		// but apps could have raced in).
		secrets := map[string]string{"PGPASSWORD": password}
		drop := newDockerExec(false, container, secrets,
			"psql", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", "postgres", "-c",
			fmt.Sprintf(`DROP DATABASE IF EXISTS "%s" WITH (FORCE)`, sqlIdentEscape(dbName)))
		if out, err := drop.Command().CombinedOutput(); err != nil {
			streamer.AddLine(string(out))
			return fmt.Errorf("drop database: %w", err)
		}
		create := newDockerExec(false, container, secrets,
			"psql", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", "postgres", "-c",
			fmt.Sprintf(`CREATE DATABASE "%s"`, sqlIdentEscape(dbName)))
		if out, err := create.Command().CombinedOutput(); err != nil {
			streamer.AddLine(string(out))
			return fmt.Errorf("create database: %w", err)
		}
		return nil

	case "mysql", "mariadb":
		root := creds["rootPassword"]
		dbName := creds["dbName"]
		if root == "" || dbName == "" {
			return fmt.Errorf("target %s creds missing rootPassword/dbName", engine)
		}
		// MySQL `DROP DATABASE` doesn't have a FORCE; new target should
		// have zero connections so this is fine.
		stmt := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; CREATE DATABASE `%s`;", mysqlIdentEscape(dbName), mysqlIdentEscape(dbName))
		reset := newDockerExec(false, container, map[string]string{"MYSQL_PWD": root},
			"mysql", "-u", "root", "-e", stmt)
		if out, err := reset.Command().CombinedOutput(); err != nil {
			streamer.AddLine(string(out))
			return fmt.Errorf("drop+create mysql database: %w", err)
		}
		return nil

	case "mongo":
		// `mongorestore --drop` drops per-collection during restore.
		// Up-front drop of the whole DB risks deleting the auth user
		// inside the same DB. Skip it.
		return nil
	}
	return fmt.Errorf("resetTarget: unsupported engine %s", engine)
}

// runMigrationPipe runs `docker exec <src> <dump> | docker exec -i <tgt> <restore>`.
// We can't use exec.Command's StdoutPipe across two separate Cmds with a clean
// pipe stage without buffering, so we wire stdout→stdin via a Go-side
// io.Pipe and run both halves as goroutines, capturing stderr from each
// side into the streamer.
func runMigrationPipe(streamer *logs.Streamer, engine, srcContainer, tgtContainer string, src, tgt map[string]string) error {
	srcMongoConfig, cleanupSrc, err := prepareMongoConfig(engine, srcContainer, src)
	if err != nil {
		return err
	}
	defer cleanupSrc()
	tgtMongoConfig, cleanupTgt, err := prepareMongoConfig(engine, tgtContainer, tgt)
	if err != nil {
		return err
	}
	defer cleanupTgt()
	var mysqlDump mysqlDumpTool
	if engine == "mysql" || engine == "mariadb" {
		if mysqlDump, err = detectMySQLDumpTool(srcContainer); err != nil {
			return err
		}
	}
	dump, restore, err := buildPipeArgs(engine, srcContainer, tgtContainer, src, tgt, srcMongoConfig, tgtMongoConfig, mysqlDump)
	if err != nil {
		return err
	}

	dumpCmd := dump.Command()
	restoreCmd := restore.Command()

	// Connect dump.Stdout → restore.Stdin via OS pipe (cheaper than io.Pipe
	// because no extra goroutine copy is needed; docker writes directly to
	// the restore process's fd).
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}
	dumpCmd.Stdout = pw
	restoreCmd.Stdin = pr

	// Stderr from both sides flows into the streamer so the user sees
	// what's happening (and what failed).
	dumpStderr, _ := dumpCmd.StderrPipe()
	restoreStderr, _ := restoreCmd.StderrPipe()

	if err := dumpCmd.Start(); err != nil {
		_ = pw.Close()
		_ = pr.Close()
		return fmt.Errorf("start dump: %w", err)
	}
	// The dump child has its own copy of the write end; closing ours now
	// means restore sees EOF as soon as dump exits.
	_ = pw.Close()
	if err := restoreCmd.Start(); err != nil {
		_ = pr.Close()
		_ = dumpCmd.Process.Kill()
		_ = dumpCmd.Wait()
		return fmt.Errorf("start restore: %w", err)
	}
	// Likewise the read end: if restore dies, dump gets EPIPE instead of
	// blocking on a pipe nobody reads.
	_ = pr.Close()

	// Stream stderr from both to the log. Tagged so users can tell which
	// side complained. We use AddLine (not Stream) so the two stderr
	// readers don't both spawn ticker goroutines that flush past each
	// other; the surrounding deploy code calls Flush() at the end.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tailStderr(streamer, "[dump]", dumpStderr)
	}()
	go func() {
		defer wg.Done()
		tailStderr(streamer, "[restore]", restoreStderr)
	}()

	// Readers finish when both processes exit; Wait only after that
	// (Wait closes the stderr pipes).
	wg.Wait()
	dumpErr := dumpCmd.Wait()
	restoreErr := restoreCmd.Wait()

	// Disambiguate the common SIGPIPE case: when the restore side exits
	// first (bad creds, target unreachable, OOM, etc.), the OS sends
	// SIGPIPE to dump, which then exits with a "broken pipe" error. If
	// we report dumpErr first, the user sees a misleading "dump failed"
	// when the actual cause was on the restore side. Report restoreErr
	// first when both are non-nil so the surfaced error points at the
	// real failure.
	if restoreErr != nil && dumpErr != nil {
		return fmt.Errorf("restore failed (dump likely got SIGPIPE as a result): %w", restoreErr)
	}
	if restoreErr != nil {
		return fmt.Errorf("restore exited with error: %w", restoreErr)
	}
	if dumpErr != nil {
		return fmt.Errorf("dump exited with error: %w", dumpErr)
	}
	return nil
}

// buildPipeArgs returns the `docker exec ...` invocations for the
// source-side dump and the target-side restore for a given engine. For mongo
// the passwords are in --config files already written into each container.
func buildPipeArgs(engine, srcContainer, tgtContainer string, src, tgt map[string]string, srcMongoConfig, tgtMongoConfig string, mysqlDump mysqlDumpTool) (dockerExec, dockerExec, error) {
	switch engine {
	case "postgres":
		if src["user"] == "" || src["dbName"] == "" || tgt["user"] == "" || tgt["dbName"] == "" {
			return dockerExec{}, dockerExec{}, fmt.Errorf("postgres creds incomplete")
		}
	case "mysql", "mariadb":
		// Auth as root on both sides because Dokploy's standard user
		// often lacks permissions for `--routines --triggers`.
		if src["rootPassword"] == "" || src["dbName"] == "" || tgt["rootPassword"] == "" || tgt["dbName"] == "" {
			return dockerExec{}, dockerExec{}, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required on both sides)")
		}
	case "mongo":
		if src["user"] == "" || tgt["user"] == "" {
			return dockerExec{}, dockerExec{}, fmt.Errorf("mongo creds incomplete")
		}
	default:
		return dockerExec{}, dockerExec{}, fmt.Errorf("unsupported engine: %s", engine)
	}
	// The halves are the same commands the backup path uses. For mongo,
	// --archive (no file arg) streams a single binary archive; there is
	// no `-t` on docker exec, a pseudo-TTY would corrupt it.
	dump, err := buildBackupDumpArgs(engine, srcContainer, src, srcMongoConfig, mysqlDump)
	if err != nil {
		return dockerExec{}, dockerExec{}, err
	}
	restore, err := buildBackupRestoreArgs(engine, tgtContainer, tgt, tgtMongoConfig)
	if err != nil {
		return dockerExec{}, dockerExec{}, err
	}
	return dump, restore, nil
}

// tailStderr forwards stderr line by line to the streamer with a side tag
// (`[dump]` / `[restore]`) so failures point at the right half of the
// pipeline. Long lines are truncated and a read error drains the rest, so
// the child never blocks on a full stderr pipe.
func tailStderr(streamer *logs.Streamer, tag string, r io.Reader) {
	_ = logs.ReadLines(r, logs.MaxLineBytes, func(line string) {
		streamer.AddLine(tag + " " + line)
	})
}

// sqlIdentEscape escapes a Postgres identifier for use inside double quotes.
// Postgres identifiers can't legally contain a NUL byte and `"` is the only
// other char that needs escaping inside the quoted form.
func sqlIdentEscape(s string) string {
	return strings.ReplaceAll(s, `"`, `""`)
}

// mysqlIdentEscape escapes a MySQL identifier for use inside backticks.
func mysqlIdentEscape(s string) string {
	return strings.ReplaceAll(s, "`", "``")
}
