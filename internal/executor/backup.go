package executor

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

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

	streamer.AddLine(fmt.Sprintf("Backing up %s container %s", engine, container))
	streamer.Flush()

	if err := assertContainerRunning(container); err != nil {
		return fail(fmt.Errorf("container %s not running: %w", container, err))
	}
	dumpTool, _ := dumpToolsForEngine(engine)
	if err := assertToolInContainer(container, dumpTool); err != nil {
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

	if err := assertContainerRunning(container); err != nil {
		return fail(fmt.Errorf("container %s not running: %w", container, err))
	}
	dumpTool, restoreTool := dumpToolsForEngine(engine)
	if err := assertToolInContainer(container, dumpTool); err != nil {
		return fail(fmt.Errorf("%s not available in container %s: %w", dumpTool, container, err))
	}
	if err := assertToolInContainer(container, restoreTool); err != nil {
		return fail(fmt.Errorf("%s not available in container %s: %w", restoreTool, container, err))
	}

	// Step 1: pre-restore safety dump. If this fails we abort BEFORE
	// touching live data, so the database is left exactly as it was.
	if safetyBackupID != "" {
		streamer.SetProgress(15)
		streamer.AddLine("Taking pre-restore safety backup…")
		streamer.Flush()
		if err := dumpAndUpload(streamer, e.Client, engine, container, creds.Creds, safetyBackupID); err != nil {
			return fail(fmt.Errorf("safety backup failed; restore aborted, live data untouched: %w", err))
		}
	}

	// Step 2: reset the target (drop + recreate for SQL engines; mongo
	// restores with --drop), then stream the dump back in.
	streamer.SetProgress(50)
	streamer.AddLine("Resetting target before restore…")
	streamer.Flush()
	if err := resetTarget(streamer, engine, container, creds.Creds); err != nil {
		return fail(fmt.Errorf("reset target: %w", err))
	}

	streamer.SetProgress(65)
	streamer.AddLine("Downloading and restoring…")
	streamer.Flush()
	if err := downloadAndRestore(streamer, e.Client, engine, container, creds.Creds, restoreBackupID); err != nil {
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
	dumpArgs, err := buildBackupDumpArgs(engine, container, creds)
	if err != nil {
		return err
	}

	// Buffer to a disk-backed dir under /opt/stacked rather than the OS
	// temp dir, which on many VPSes is tmpfs (RAM-backed) — a multi-GB
	// dump there could OOM the host.
	tmpDir := filepath.Join(stackedDir, "backups-tmp")
	if err := ensureDir(tmpDir); err != nil {
		return fmt.Errorf("ensure temp dir: %w", err)
	}
	tmp, err := os.CreateTemp(tmpDir, "stacked-backup-*.gz")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	gw := gzip.NewWriter(io.MultiWriter(tmp, hasher))

	cmd := exec.Command("docker", dumpArgs...)
	cmd.Stdout = gw
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("start dump: %w", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailStderr(streamer, "[dump]", stderr)
	}()
	dumpErr := cmd.Wait()
	wg.Wait()

	if cerr := gw.Close(); cerr != nil && dumpErr == nil {
		dumpErr = cerr
	}
	if cerr := tmp.Close(); cerr != nil && dumpErr == nil {
		dumpErr = cerr
	}
	if dumpErr != nil {
		return fmt.Errorf("dump failed: %w", dumpErr)
	}

	info, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("stat dump: %w", err)
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	issued, err := c.RequestBackupUploadURL(backupID)
	if err != nil {
		return fmt.Errorf("request upload URL: %w", err)
	}
	if err := uploadFileToURL(issued.URL, tmpPath, info.Size()); err != nil {
		return fmt.Errorf("upload to R2: %w", err)
	}
	if err := c.ConfirmBackup(backupID, &client.BackupConfirm{
		SizeBytes: info.Size(),
		Sha256:    sum,
	}); err != nil {
		return fmt.Errorf("confirm backup: %w", err)
	}
	return nil
}

// downloadAndRestore streams a presigned GET of the gzipped dump and pipes
// the decompressed bytes into the engine's restore tool inside the container.
func downloadAndRestore(
	streamer *logs.Streamer,
	c *client.Client,
	engine, container string,
	creds map[string]string,
	backupID string,
) error {
	restoreArgs, err := buildBackupRestoreArgs(engine, container, creds)
	if err != nil {
		return err
	}
	issued, err := c.RequestBackupDownloadURL(backupID)
	if err != nil {
		return fmt.Errorf("request download URL: %w", err)
	}

	resp, err := http.Get(issued.URL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("download GET %d: %s", resp.StatusCode, string(b))
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gzr.Close()

	cmd := exec.Command("docker", restoreArgs...)
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
	restoreErr := cmd.Wait()
	wg.Wait()
	if restoreErr != nil {
		return fmt.Errorf("restore failed: %w", restoreErr)
	}
	return nil
}

// uploadFileToURL PUTs a file to a presigned URL with an explicit
// Content-Length (R2 single PUT requires it). Uses a dedicated client with
// no timeout — large dumps can take a while.
func uploadFileToURL(url, path string, size int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	req, err := http.NewRequest("PUT", url, f)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/gzip")

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

// buildBackupDumpArgs returns the `docker exec …` arg list for an
// engine-appropriate dump that emits the backup bytes on stdout. Mirrors the
// dump halves of the migration pipeline.
func buildBackupDumpArgs(engine, container string, creds map[string]string) ([]string, error) {
	switch engine {
	case "postgres":
		user := creds["user"]
		pw := creds["password"]
		dbName := creds["dbName"]
		if user == "" || dbName == "" {
			return nil, fmt.Errorf("postgres creds incomplete")
		}
		return []string{
			"exec", "-e", "PGPASSWORD=" + pw, container,
			"pg_dump", "-U", user, "-d", dbName, "-Fc", "--no-owner", "--no-privileges",
		}, nil
	case "mysql", "mariadb":
		root := creds["rootPassword"]
		dbName := creds["dbName"]
		if root == "" || dbName == "" {
			return nil, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required)")
		}
		return []string{
			"exec", "-e", "MYSQL_PWD=" + root, container,
			"mysqldump", "-u", "root",
			"--single-transaction", "--routines", "--triggers",
			"--set-gtid-purged=OFF",
			dbName,
		}, nil
	case "mongo":
		user := creds["user"]
		pw := creds["password"]
		if user == "" {
			return nil, fmt.Errorf("mongo creds incomplete")
		}
		// --archive (no file arg) emits a single binary archive on stdout.
		// No `-t`: a pseudo-TTY would corrupt the archive bytes.
		return []string{
			"exec", container,
			"mongodump", "--archive",
			"--username=" + user,
			"--password=" + pw,
			"--authenticationDatabase=admin",
		}, nil
	}
	return nil, fmt.Errorf("unsupported engine: %s", engine)
}

// buildBackupRestoreArgs returns the `docker exec -i …` arg list that reads
// the dump from stdin and restores it.
func buildBackupRestoreArgs(engine, container string, creds map[string]string) ([]string, error) {
	switch engine {
	case "postgres":
		user := creds["user"]
		pw := creds["password"]
		dbName := creds["dbName"]
		if user == "" || dbName == "" {
			return nil, fmt.Errorf("postgres creds incomplete")
		}
		return []string{
			"exec", "-i", "-e", "PGPASSWORD=" + pw, container,
			"pg_restore", "-U", user, "-d", dbName, "--no-owner", "--no-privileges",
		}, nil
	case "mysql", "mariadb":
		root := creds["rootPassword"]
		dbName := creds["dbName"]
		if root == "" || dbName == "" {
			return nil, fmt.Errorf("mysql/mariadb creds incomplete (rootPassword required)")
		}
		return []string{
			"exec", "-i", "-e", "MYSQL_PWD=" + root, container,
			"mysql", "-u", "root", dbName,
		}, nil
	case "mongo":
		user := creds["user"]
		pw := creds["password"]
		if user == "" {
			return nil, fmt.Errorf("mongo creds incomplete")
		}
		return []string{
			"exec", "-i", container,
			"mongorestore", "--archive", "--drop",
			"--username=" + user,
			"--password=" + pw,
			"--authenticationDatabase=admin",
		}, nil
	}
	return nil, fmt.Errorf("unsupported engine: %s", engine)
}
