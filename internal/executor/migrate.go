package executor

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
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

	requiredTool, restoreTool := dumpToolsForEngine(dbType)
	if err := assertToolInContainer(srcContainer, requiredTool); err != nil {
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

// VolumeMigrate copies the contents of a Dokploy bind-mount host path into
// a Stacked service's host path. Runs an `alpine` sidecar with `cp -a` so
// we don't depend on rsync being installed on the host — alpine is small
// (~5MB) and provides POSIX `cp` with archive semantics.
//
// Source contents are read-only (mounted ro). Target is recreated on every
// run for idempotent retries.
func (e *Executor) VolumeMigrate(op client.Operation) error {
	srcPath := getStringPayload(op.Payload, "sourceVolumePath")
	tgtPath := getStringPayload(op.Payload, "targetVolumePath")
	if srcPath == "" {
		return fmt.Errorf("volume_migrate requires sourceVolumePath")
	}
	if tgtPath == "" {
		return fmt.Errorf("volume_migrate requires targetVolumePath")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("Volume copy: %s → %s", srcPath, tgtPath))
	streamer.Flush()

	// Source must exist; missing source is a hard error (likely indicates
	// the Dokploy mount path was guessed rather than read from a real
	// bind mount).
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fail(fmt.Errorf("source path %s does not exist on host; cannot migrate volume contents", srcPath))
		}
		return fail(fmt.Errorf("stat source %s: %w", srcPath, err))
	}
	if !srcInfo.IsDir() {
		// Single-file mount: copy the file directly.
		streamer.AddLine("Source is a single file; copying directly.")
		streamer.Flush()
		if err := ensureDir(filepath.Dir(tgtPath)); err != nil {
			return fail(fmt.Errorf("ensure target parent dir: %w", err))
		}
		if err := copyFile(srcPath, tgtPath); err != nil {
			return fail(fmt.Errorf("copy file: %w", err))
		}
		streamer.SetProgress(100)
		streamer.AddLine("Volume file copy complete.")
		streamer.Flush()
		return nil
	}

	// Reset target dir before copying so retries always start clean.
	streamer.SetProgress(10)
	if _, err := os.Stat(tgtPath); err == nil {
		streamer.AddLine("Clearing existing target directory…")
		streamer.Flush()
		if err := os.RemoveAll(tgtPath); err != nil {
			return fail(fmt.Errorf("clear target %s: %w", tgtPath, err))
		}
	}
	if err := ensureDir(tgtPath); err != nil {
		return fail(fmt.Errorf("create target dir: %w", err))
	}

	streamer.SetProgress(25)
	streamer.AddLine("Running alpine sidecar with `cp -a` to preserve perms/ownership…")
	streamer.Flush()

	// `cp -a` preserves mode, ownership, timestamps, symlinks. The `/.`
	// at the end of the source ensures we copy *contents* not the dir
	// itself (idempotent against re-runs).
	args := []string{
		"run", "--rm",
		"-v", srcPath + ":/src:ro",
		"-v", tgtPath + ":/dst",
		"alpine:3.20",
		"sh", "-c", "cp -a /src/. /dst/",
	}
	if err := e.runCommandWithStreamer(streamer, "", "docker", args...); err != nil {
		return fail(fmt.Errorf("alpine cp: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Volume migration complete.")
	streamer.Flush()
	return nil
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
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker inspect %s: %s", name, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("container %s is not running (State.Running=%s)", name, strings.TrimSpace(string(out)))
	}
	return nil
}

// assertToolInContainer checks `which <tool>` inside the container.
// Detects the alpine/slim image footgun before we ever start a destructive
// drop on the target. Returns an actionable error if the tool is missing.
func assertToolInContainer(container, tool string) error {
	if tool == "" {
		return nil
	}
	cmd := exec.Command("docker", "exec", container, "which", tool)
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
		drop := []string{"exec", "-e", "PGPASSWORD=" + password, container,
			"psql", "-U", user, "-d", "postgres", "-c",
			fmt.Sprintf(`DROP DATABASE IF EXISTS "%s" WITH (FORCE)`, sqlIdentEscape(dbName))}
		if out, err := exec.Command("docker", drop...).CombinedOutput(); err != nil {
			streamer.AddLine(string(out))
			return fmt.Errorf("drop database: %w", err)
		}
		create := []string{"exec", "-e", "PGPASSWORD=" + password, container,
			"psql", "-U", user, "-d", "postgres", "-c",
			fmt.Sprintf(`CREATE DATABASE "%s"`, sqlIdentEscape(dbName))}
		if out, err := exec.Command("docker", create...).CombinedOutput(); err != nil {
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
		args := []string{"exec", "-e", "MYSQL_PWD=" + root, container,
			"mysql", "-u", "root", "-e", stmt}
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
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
	dumpArgs, restoreArgs, err := buildPipeArgs(engine, srcContainer, tgtContainer, src, tgt)
	if err != nil {
		return err
	}

	dumpCmd := exec.Command("docker", dumpArgs...)
	restoreCmd := exec.Command("docker", restoreArgs...)

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
		return fmt.Errorf("start dump: %w", err)
	}
	if err := restoreCmd.Start(); err != nil {
		_ = dumpCmd.Process.Kill()
		return fmt.Errorf("start restore: %w", err)
	}

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

	// IMPORTANT: close the write end after dump finishes so restore sees EOF.
	dumpErr := dumpCmd.Wait()
	_ = pw.Close()
	restoreErr := restoreCmd.Wait()
	_ = pr.Close()
	wg.Wait()

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

// buildPipeArgs returns the `docker exec ...` arg lists for the source-side
// dump and the target-side restore for a given engine.
func buildPipeArgs(engine, srcContainer, tgtContainer string, src, tgt map[string]string) ([]string, []string, error) {
	switch engine {
	case "postgres":
		srcUser := src["user"]
		srcPw := src["password"]
		srcDB := src["dbName"]
		tgtUser := tgt["user"]
		tgtPw := tgt["password"]
		tgtDB := tgt["dbName"]
		if srcUser == "" || srcDB == "" || tgtUser == "" || tgtDB == "" {
			return nil, nil, fmt.Errorf("postgres creds incomplete")
		}
		dump := []string{
			"exec", "-e", "PGPASSWORD=" + srcPw, srcContainer,
			"pg_dump", "-U", srcUser, "-d", srcDB, "-Fc", "--no-owner", "--no-privileges",
		}
		restore := []string{
			"exec", "-i", "-e", "PGPASSWORD=" + tgtPw, tgtContainer,
			"pg_restore", "-U", tgtUser, "-d", tgtDB, "--no-owner", "--no-privileges",
		}
		return dump, restore, nil

	case "mysql", "mariadb":
		// Auth as root on both sides because Dokploy's standard user
		// often lacks permissions for `--routines --triggers`.
		srcRoot := src["rootPassword"]
		srcDB := src["dbName"]
		tgtRoot := tgt["rootPassword"]
		tgtDB := tgt["dbName"]
		if srcRoot == "" || srcDB == "" || tgtRoot == "" || tgtDB == "" {
			return nil, nil, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required on both sides)")
		}
		dump := []string{
			"exec", "-e", "MYSQL_PWD=" + srcRoot, srcContainer,
			"mysqldump", "-u", "root",
			"--single-transaction", "--routines", "--triggers",
			"--set-gtid-purged=OFF",
			srcDB,
		}
		restore := []string{
			"exec", "-i", "-e", "MYSQL_PWD=" + tgtRoot, tgtContainer,
			"mysql", "-u", "root", tgtDB,
		}
		return dump, restore, nil

	case "mongo":
		srcUser := src["user"]
		srcPw := src["password"]
		tgtUser := tgt["user"]
		tgtPw := tgt["password"]
		if srcUser == "" || tgtUser == "" {
			return nil, nil, fmt.Errorf("mongo creds incomplete")
		}
		// --archive (no file arg) emits a single binary archive on stdout.
		// CRITICAL: no `-t` on docker exec — pseudo-TTY corrupts the archive
		// bytes. We pass `-i` only.
		dump := []string{
			"exec", srcContainer,
			"mongodump", "--archive",
			"--username=" + srcUser,
			"--password=" + srcPw,
			"--authenticationDatabase=admin",
		}
		restore := []string{
			"exec", "-i", tgtContainer,
			"mongorestore", "--archive", "--drop",
			"--username=" + tgtUser,
			"--password=" + tgtPw,
			"--authenticationDatabase=admin",
		}
		return dump, restore, nil
	}
	return nil, nil, fmt.Errorf("unsupported engine: %s", engine)
}

// tailStderr scans stderr line-by-line and forwards each line to the
// streamer with a side tag (`[dump]` / `[restore]`) so failures point at
// the right half of the pipeline.
func tailStderr(streamer *logs.Streamer, tag string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		streamer.AddLine(tag + " " + scanner.Text())
	}
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

// copyFile copies a single file preserving mode. Used by VolumeMigrate
// when the source is a regular file rather than a directory.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
