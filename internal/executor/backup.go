package executor

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// backupTmpDir buffers dumps on disk. A var so tests can point it at a
// temp dir.
var backupTmpDir = filepath.Join(stackedDir, "backups-tmp")

// Backup dumps a database container with the engine-appropriate tool
// (`pg_dump -Fc` / `mysqldump` / `mongodump --archive`), gzips the dump to a
// temp file, and uploads it directly to R2 via a server-issued presigned
// PUT URL. Credentials are fetched on-demand from the server so the
// operations.payload column never holds plaintext DB creds.
//
// We buffer the gzipped dump to a temp file rather than streaming it
// straight to R2 because a presigned single PUT needs a Content-Length up
// front, and database dumps can be large. The temp file is always removed.
func (e *Executor) Backup(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	backupID := getStringPayload(op.Payload, "backupId")
	if databaseID == "" || backupID == "" {
		return fmt.Errorf("db_backup requires databaseId and backupId")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(5)
	streamer.AddLine("Fetching database credentials…")
	streamer.Flush()

	creds, err := e.Client.GetBackupCredentials(databaseID)
	if err != nil {
		return fail(fmt.Errorf("fetch backup credentials: %w", err))
	}
	container := creds.ContainerName
	engine := creds.Engine
	if err := checkContainerName("database", container); err != nil {
		return fail(err)
	}

	streamer.AddLine(fmt.Sprintf("Backing up %s container %s", engine, container))
	streamer.Flush()

	if err := assertContainerRunning(container); err != nil {
		return fail(fmt.Errorf("container %s not running: %w", container, err))
	}
	if dumpTool, err := assertDumpToolInContainer(engine, container); err != nil {
		return fail(fmt.Errorf("%s not available in container %s: %w", dumpTool, container, err))
	}

	streamer.SetProgress(30)
	streamer.AddLine("Dumping and uploading…")
	streamer.Flush()

	if err := dumpAndUpload(streamer, e.Client, engine, container, creds.Creds, backupID); err != nil {
		return fail(err)
	}

	streamer.SetProgress(100)
	streamer.AddLine("Backup complete.")
	streamer.Flush()
	return nil
}

// Restore streams a stored backup back into a database container. It first
// takes a `pre_restore` safety dump (uploaded to its own key) so a bad
// restore is always recoverable, then resets the target and pipes the
// downloaded dump into the engine's restore tool.
//
// Same-container restore only: the dump goes back into the same DB it came
// from. Cross-database restore is intentionally out of scope.
func (e *Executor) Restore(op client.Operation) error {
	databaseID := getStringPayload(op.Payload, "databaseId")
	restoreBackupID := getStringPayload(op.Payload, "restoreBackupId")
	safetyBackupID := getStringPayload(op.Payload, "safetyBackupId")
	if databaseID == "" || restoreBackupID == "" {
		return fmt.Errorf("db_restore requires databaseId and restoreBackupId")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) error {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return err
	}

	streamer.SetProgress(5)
	streamer.AddLine("Fetching database credentials…")
	streamer.Flush()

	creds, err := e.Client.GetBackupCredentials(databaseID)
	if err != nil {
		return fail(fmt.Errorf("fetch backup credentials: %w", err))
	}
	container := creds.ContainerName
	engine := creds.Engine
	if err := checkContainerName("database", container); err != nil {
		return fail(err)
	}

	if err := assertContainerRunning(container); err != nil {
		return fail(fmt.Errorf("container %s not running: %w", container, err))
	}
	_, restoreTool := dumpToolsForEngine(engine)
	if dumpTool, err := assertDumpToolInContainer(engine, container); err != nil {
		return fail(fmt.Errorf("%s not available in container %s: %w", dumpTool, container, err))
	}
	if err := assertToolInContainer(container, restoreTool); err != nil {
		return fail(fmt.Errorf("%s not available in container %s: %w", restoreTool, container, err))
	}

	// Step 1: fetch the backup to local disk and verify it BEFORE anything
	// destructive. A missing object, expired URL, network failure, size or
	// checksum mismatch, or a corrupt gzip stream aborts here with the
	// database untouched. (Streaming straight into the restore tool after
	// the reset would leave an empty database on any of those.)
	streamer.SetProgress(10)
	streamer.AddLine("Downloading and verifying backup…")
	streamer.Flush()
	dumpPath, err := downloadBackupToFile(e.Client, restoreBackupID)
	if err != nil {
		return fail(fmt.Errorf("backup download failed; restore aborted, live data untouched: %w", err))
	}
	defer os.Remove(dumpPath)

	// Step 2: pre-restore safety dump. If this fails we abort BEFORE
	// touching live data, so the database is left exactly as it was.
	if safetyBackupID != "" {
		streamer.SetProgress(30)
		streamer.AddLine("Taking pre-restore safety backup…")
		streamer.Flush()
		if err := dumpAndUpload(streamer, e.Client, engine, container, creds.Creds, safetyBackupID); err != nil {
			return fail(fmt.Errorf("safety backup failed; restore aborted, live data untouched: %w", err))
		}
	}

	// Step 3: reset the target (drop + recreate for SQL engines; mongo
	// restores with --drop), then feed the verified dump back in.
	streamer.SetProgress(50)
	streamer.AddLine("Resetting target before restore…")
	streamer.Flush()
	if err := resetTarget(streamer, engine, container, creds.Creds); err != nil {
		return fail(fmt.Errorf("reset target: %w", err))
	}

	streamer.SetProgress(65)
	streamer.AddLine("Restoring…")
	streamer.Flush()
	if err := restoreFromFile(streamer, engine, container, creds.Creds, dumpPath); err != nil {
		return fail(err)
	}

	streamer.SetProgress(100)
	streamer.AddLine("Restore complete.")
	streamer.Flush()
	return nil
}

// dumpAndUpload runs the engine dump → gzip → temp file, then PUTs the file
// to a presigned URL and confirms. Shared by Backup and the safety-dump
// phase of Restore.
func dumpAndUpload(
	streamer *logs.Streamer,
	c *client.Client,
	engine, container string,
	creds map[string]string,
	backupID string,
) error {
	// Buffer to a disk-backed dir under /opt/stacked rather than the OS
	// temp dir, which on many VPSes is tmpfs (RAM-backed) — a multi-GB
	// dump there could OOM the host.
	tmpDir := backupTmpDir
	if err := ensureDir(tmpDir); err != nil {
		return fmt.Errorf("ensure temp dir: %w", err)
	}
	tmpPath, size, sum, err := dumpToFile(streamer, engine, container, creds, tmpDir)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	issued, err := c.RequestBackupUploadURL(backupID, size)
	if err != nil {
		return fmt.Errorf("request upload URL: %w", err)
	}
	if err := uploadFileToURL(issued.URL, issued.Method, issued.Headers, tmpPath, size); err != nil {
		return fmt.Errorf("upload to R2: %w", err)
	}
	if err := c.ConfirmBackup(backupID, &client.BackupConfirm{
		SizeBytes: size,
		Sha256:    sum,
	}); err != nil {
		return fmt.Errorf("confirm backup: %w", err)
	}
	return nil
}

// dumpToFile runs the engine dump, gzips it into a new 0600 temp file in
// dir, and returns its path, size and hex SHA-256. The caller removes the
// file; on error it is already removed.
func dumpToFile(streamer *logs.Streamer, engine, container string, creds map[string]string, dir string) (path string, size int64, sum string, err error) {
	mongoConfig, cleanupConfig, err := prepareMongoConfig(engine, container, creds)
	if err != nil {
		return "", 0, "", err
	}
	defer cleanupConfig()
	var mysqlDump mysqlDumpTool
	if engine == "mysql" || engine == "mariadb" {
		if mysqlDump, err = detectMySQLDumpTool(container); err != nil {
			return "", 0, "", err
		}
	}
	dump, err := buildBackupDumpArgs(engine, container, creds, mongoConfig, mysqlDump)
	if err != nil {
		return "", 0, "", err
	}

	tmp, err := os.CreateTemp(dir, "stacked-backup-*.gz")
	if err != nil {
		return "", 0, "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	gw := gzip.NewWriter(io.MultiWriter(tmp, hasher))

	cmd := dump.Command()
	cmd.Stdout = gw
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		_ = tmp.Close()
		return "", 0, "", fmt.Errorf("start dump: %w", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailStderr(streamer, "[dump]", stderr)
	}()
	// Drain stderr fully before Wait (Wait closes the pipe).
	wg.Wait()
	dumpErr := cmd.Wait()

	if cerr := gw.Close(); cerr != nil && dumpErr == nil {
		dumpErr = cerr
	}
	if cerr := tmp.Close(); cerr != nil && dumpErr == nil {
		dumpErr = cerr
	}
	if dumpErr != nil {
		return "", 0, "", fmt.Errorf("dump failed: %w", dumpErr)
	}

	info, err := os.Stat(tmpPath)
	if err != nil {
		return "", 0, "", fmt.Errorf("stat dump: %w", err)
	}
	return tmpPath, info.Size(), hex.EncodeToString(hasher.Sum(nil)), nil
}

// downloadBackupToFile fetches a stored backup into a private temp file
// under /opt/stacked/backups-tmp and verifies it: HTTP status, the SHA-256
// recorded when the backup was confirmed (when the server sends it), and
// the gzip stream itself (decompressing it end to end checks its CRC and
// length trailer, so truncated or corrupt objects are caught even without a
// server checksum). Returns the path; the caller removes it.
func downloadBackupToFile(c *client.Client, backupID string) (string, error) {
	issued, err := c.RequestBackupDownloadURL(backupID)
	if err != nil {
		return "", fmt.Errorf("request download URL: %w", err)
	}
	tmpDir := backupTmpDir
	if err := ensureDir(tmpDir); err != nil {
		return "", fmt.Errorf("ensure temp dir: %w", err)
	}
	tmp, err := os.CreateTemp(tmpDir, "stacked-restore-*.gz")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	path := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()

	sum, err := fetchToFile(issued.URL, tmp)
	if cerr := tmp.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if err := verifyBackupFile(path, sum, issued.Sha256); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

// fetchToFile GETs url into f and returns the hex SHA-256 of the body.
func fetchToFile(url string, f *os.File) (string, error) {
	req, err := http.NewRequestWithContext(currentOpContext(), http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("download GET %d: %s", resp.StatusCode, string(b))
	}
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hasher), resp.Body)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return "", fmt.Errorf("download truncated: got %d of %d bytes", n, resp.ContentLength)
	}
	if n == 0 {
		return "", fmt.Errorf("downloaded backup is empty")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// verifyBackupFile checks the downloaded dump against the expected SHA-256
// (skipped when the server didn't send one) and that it is a complete,
// valid gzip stream.
func verifyBackupFile(path, gotSha, wantSha string) error {
	if wantSha != "" && !strings.EqualFold(gotSha, wantSha) {
		return fmt.Errorf("backup checksum mismatch: expected sha256 %s, got %s", wantSha, gotSha)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("backup is not a valid gzip stream: %w", err)
	}
	if _, err := io.Copy(io.Discard, gzr); err != nil {
		return fmt.Errorf("backup gzip stream is corrupt or truncated: %w", err)
	}
	return gzr.Close()
}

// restoreFromFile pipes the decompressed local dump into the engine's
// restore tool inside the container.
func restoreFromFile(
	streamer *logs.Streamer,
	engine, container string,
	creds map[string]string,
	dumpPath string,
) error {
	mongoConfig, cleanupConfig, err := prepareMongoConfig(engine, container, creds)
	if err != nil {
		return err
	}
	defer cleanupConfig()
	restore, err := buildBackupRestoreArgs(engine, container, creds, mongoConfig)
	if err != nil {
		return err
	}

	f, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("open dump: %w", err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gzr.Close()

	cmd := restore.Command()
	cmd.Stdin = gzr
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start restore: %w", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailStderr(streamer, "[restore]", stderr)
	}()
	wg.Wait()
	restoreErr := cmd.Wait()
	if restoreErr != nil {
		return fmt.Errorf("restore failed: %w", restoreErr)
	}
	return nil
}

// uploadFileToURL PUTs a file to a presigned URL with an explicit
// Content-Length (R2 single PUT requires it). Uses a dedicated client with
// no timeout — large dumps can take a while.
func uploadFileToURL(url, method string, headers map[string]string, path string, size int64) error {
	if method == "" {
		method = http.MethodPut
	}
	if method != http.MethodPut {
		return fmt.Errorf("unsupported signed upload method %q", method)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	req, err := http.NewRequestWithContext(currentOpContext(), method, url, f)
	if err != nil {
		return err
	}
	req.ContentLength = size
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/gzip")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("PUT %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// prepareMongoConfig writes the mongo-tools `--config` password file into
// container when engine is mongo; for other engines it is a no-op returning
// an empty path.
func prepareMongoConfig(engine, container string, creds map[string]string) (string, func(), error) {
	if engine != "mongo" {
		return "", func() {}, nil
	}
	return writeMongoToolConfig(container, creds["password"])
}

// buildBackupDumpArgs returns the `docker exec …` invocation for an
// engine-appropriate dump that emits the backup bytes on stdout. Mirrors the
// dump halves of the migration pipeline. Passwords travel in the docker
// CLI's env (`-e NAME`) or, for mongo, in the --config file at mongoConfig.
//
// mysqlDump is the detected MySQL-family dump tool (see
// detectMySQLDumpTool); the zero value is MySQL's mysqldump.
func buildBackupDumpArgs(engine, container string, creds map[string]string, mongoConfig string, mysqlDump mysqlDumpTool) (dockerExec, error) {
	switch engine {
	case "postgres":
		user := creds["user"]
		dbName := creds["dbName"]
		if user == "" || dbName == "" {
			return dockerExec{}, fmt.Errorf("postgres creds incomplete")
		}
		return newDockerExec(false, container, map[string]string{"PGPASSWORD": creds["password"]},
			"pg_dump", "-U", user, "-d", dbName, "-Fc", "--no-owner", "--no-privileges",
		), nil
	case "mysql", "mariadb":
		root := creds["rootPassword"]
		dbName := creds["dbName"]
		if root == "" || dbName == "" {
			return dockerExec{}, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required)")
		}
		return newDockerExec(false, container, map[string]string{"MYSQL_PWD": root},
			mysqlDump.argv(dbName)...,
		), nil
	case "mongo":
		user := creds["user"]
		if user == "" {
			return dockerExec{}, fmt.Errorf("mongo creds incomplete")
		}
		if mongoConfig == "" {
			return dockerExec{}, fmt.Errorf("mongo dump needs a credentials config file")
		}
		// --archive (no file arg) emits a single binary archive on stdout.
		// No `-t`: a pseudo-TTY would corrupt the archive bytes.
		return newDockerExec(false, container, nil,
			"mongodump", "--archive",
			"--config="+mongoConfig,
			"--username="+user,
			"--authenticationDatabase=admin",
		), nil
	}
	return dockerExec{}, fmt.Errorf("unsupported engine: %s", engine)
}

// buildBackupRestoreArgs returns the `docker exec -i …` invocation that
// reads the dump from stdin and restores it.
func buildBackupRestoreArgs(engine, container string, creds map[string]string, mongoConfig string) (dockerExec, error) {
	switch engine {
	case "postgres":
		user := creds["user"]
		dbName := creds["dbName"]
		if user == "" || dbName == "" {
			return dockerExec{}, fmt.Errorf("postgres creds incomplete")
		}
		return newDockerExec(true, container, map[string]string{"PGPASSWORD": creds["password"]},
			"pg_restore", "-U", user, "-d", dbName, "--no-owner", "--no-privileges",
		), nil
	case "mysql", "mariadb":
		root := creds["rootPassword"]
		dbName := creds["dbName"]
		if root == "" || dbName == "" {
			return dockerExec{}, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required)")
		}
		return newDockerExec(true, container, map[string]string{"MYSQL_PWD": root},
			"mysql", "-u", "root", dbName,
		), nil
	case "mongo":
		user := creds["user"]
		if user == "" {
			return dockerExec{}, fmt.Errorf("mongo creds incomplete")
		}
		if mongoConfig == "" {
			return dockerExec{}, fmt.Errorf("mongo restore needs a credentials config file")
		}
		return newDockerExec(true, container, nil,
			"mongorestore", "--archive", "--drop",
			"--config="+mongoConfig,
			"--username="+user,
			"--authenticationDatabase=admin",
		), nil
	}
	return dockerExec{}, fmt.Errorf("unsupported engine: %s", engine)
}
