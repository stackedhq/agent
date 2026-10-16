package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// Docker-backed tests for the DB op paths (STACKED_DOCKER_TESTS=1). Each
// starts a throwaway engine container and removes it.

func startDBContainer(t *testing.T, image string, env map[string]string, ready []string, cmdArgs ...string) string {
	t.Helper()
	requireDocker(t)
	name := "stk-test-db-" + randSuffix(t)
	args := []string{"run", "-d", "--name", name}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, image)
	args = append(args, cmdArgs...)
	dockerOut(t, "", nil, args...)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() })
	deadline := time.Now().Add(90 * time.Second)
	for {
		probe := append([]string{"exec", name}, ready...)
		if exec.Command("docker", probe...).Run() == nil {
			return name
		}
		if time.Now().After(deadline) {
			out, _ := exec.Command("docker", "logs", "--tail", "30", name).CombinedOutput()
			t.Fatalf("%s not ready:\n%s", image, out)
		}
		time.Sleep(time.Second)
	}
}

func execIn(t *testing.T, container string, args ...string) string {
	t.Helper()
	return dockerOut(t, "", nil, append([]string{"exec", container}, args...)...)
}

func roundTrip(t *testing.T, engine, container string, creds map[string]string, mutate func()) {
	t.Helper()
	streamer := logs.NewStreamer(nil, "op")
	path, size, sum, err := dumpToFile(streamer, engine, container, creds, t.TempDir())
	if err != nil {
		t.Fatalf("%s dump: %v", engine, err)
	}
	if size == 0 {
		t.Fatalf("%s dump is empty", engine)
	}
	if err := verifyBackupFile(path, sum, sum); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := verifyBackupFile(path, sum, strings.Repeat("0", 64)); err == nil {
		t.Fatalf("checksum mismatch not detected")
	}
	mutate()
	if err := resetTarget(streamer, engine, container, creds); err != nil {
		t.Fatalf("%s reset: %v", engine, err)
	}
	if err := restoreFromFile(streamer, engine, container, creds, path); err != nil {
		t.Fatalf("%s restore: %v", engine, err)
	}
}

func TestDockerPostgresOps(t *testing.T) {
	pg := startDBContainer(t, "postgres:16-alpine",
		map[string]string{"POSTGRES_USER": "app", "POSTGRES_PASSWORD": testPw, "POSTGRES_DB": "appdb"},
		[]string{"psql", "-U", "app", "-d", "appdb", "-c", "select 1"})
	creds := testCreds()
	execIn(t, pg, "psql", "-U", "app", "-d", "appdb", "-c", "create table t(id int); insert into t values (1),(2);")

	// Read-only console.
	res, err := runReadOnlyQuery(pg, "app", "appdb", "SELECT id FROM t ORDER BY id")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows := res["rows"].([][]interface{}); len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	for _, q := range []string{
		"SELECT 1) TO STDOUT \\g\nCOMMIT \\g\nDROP TABLE t \\g\n",
		"SELECT 1 \\! id",
	} {
		if _, err := runReadOnlyQuery(pg, "app", "appdb", q); err == nil || !strings.Contains(err.Error(), "backslash") {
			t.Fatalf("meta-command query %q not rejected: %v", q, err)
		}
	}
	if _, err := runReadOnlyQuery(pg, "app", "appdb", "SELECT 1) TO PROGRAM 'id' --"); err == nil {
		t.Fatalf("comment-swallowing COPY TO PROGRAM was not rejected")
	}
	if _, err := runReadOnlyQuery(pg, "app", "appdb", "SELECT id FROM t FOR UPDATE"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("expected read-only rejection, got %v", err)
	}
	if out := execIn(t, pg, "psql", "-At", "-U", "app", "-d", "appdb", "-c", "select count(*) from t"); strings.TrimSpace(out) != "2" {
		t.Fatalf("table changed by console: %q", out)
	}

	// Backup -> reset -> restore.
	roundTrip(t, "postgres", pg, creds, func() {
		execIn(t, pg, "psql", "-U", "app", "-d", "appdb", "-c", "delete from t")
	})
	if out := execIn(t, pg, "psql", "-At", "-U", "app", "-d", "appdb", "-c", "select count(*) from t"); strings.TrimSpace(out) != "2" {
		t.Fatalf("restore lost rows: %q", out)
	}

	// Password rotation (verified over TCP, which needs a password).
	newPw := "n3w'pw\\x$y"
	if err := alterPassword(pg, "postgres", creds, map[string]string{"password": newPw}, logs.NewStreamer(nil, "op"), &Executor{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	cmd := exec.Command("docker", "exec", "-e", "PGPASSWORD", pg, "sh", "-c", `psql -h "$(hostname -i)" -U app -d appdb -Atc 'select 1'`)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+newPw)
	if out, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("login with rotated password failed: %v %s", err, out)
	}
}

func TestDockerRedisRotate(t *testing.T) {
	r := startDBContainer(t, "redis:7-alpine", nil, []string{"redis-cli", "-a", testPw, "--no-auth-warning", "ping"},
		"redis-server", "--requirepass", testPw)
	streamer := logs.NewStreamer(nil, "op")
	if err := alterPassword(r, "redis", map[string]string{"password": "wrong"}, map[string]string{"password": "x"}, streamer, &Executor{}); err == nil {
		t.Fatalf("rotation with a wrong old password must fail (redis-cli exits 0)")
	}
	if err := alterPassword(r, "redis", map[string]string{"password": testPw}, map[string]string{"password": testNewPw}, streamer, &Executor{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	cmd := exec.Command("docker", "exec", "-e", "REDISCLI_AUTH", r, "redis-cli", "ping")
	cmd.Env = append(os.Environ(), "REDISCLI_AUTH="+testNewPw)
	if out, _ := cmd.CombinedOutput(); strings.TrimSpace(string(out)) != "PONG" {
		t.Fatalf("new password not active: %s", out)
	}
}

func TestDockerMongoOps(t *testing.T) {
	m := startDBContainer(t, "mongo:7",
		map[string]string{"MONGO_INITDB_ROOT_USERNAME": "app", "MONGO_INITDB_ROOT_PASSWORD": testPw},
		[]string{"mongosh", "--quiet", "--eval", "db.adminCommand('ping')"})
	creds := testCreds()
	mongo := func(pw, js string) string {
		cmd := exec.Command("docker", "exec", "-e", "PW", m, "sh", "-c", `mongosh --quiet -u app -p "$PW" --authenticationDatabase admin appdb --eval "$1"`, "sh", js)
		cmd.Env = append(os.Environ(), "PW="+pw)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("mongosh: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	mongo(testPw, `db.t.insertMany([{a:1},{a:2}])`)

	roundTrip(t, "mongo", m, creds, func() { mongo(testPw, `db.t.deleteMany({})`) })
	if got := mongo(testPw, `db.t.countDocuments()`); got != "2" {
		t.Fatalf("restore lost docs: %q", got)
	}
	if out := execIn(t, m, "sh", "-c", "ls /tmp | grep stacked-mongo || true"); strings.TrimSpace(out) != "" {
		t.Fatalf("mongo config file left behind: %q", out)
	}

	if err := alterPassword(m, "mongo", creds, map[string]string{"password": testNewPw}, logs.NewStreamer(nil, "op"), &Executor{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := mongo(testNewPw, `db.t.countDocuments()`); got != "2" {
		t.Fatalf("login with rotated password: %q", got)
	}
}

func TestDockerMariaDBOps(t *testing.T) {
	md := startDBContainer(t, "mariadb:11",
		map[string]string{"MARIADB_ROOT_PASSWORD": testRootPw, "MARIADB_DATABASE": "appdb", "MARIADB_USER": "app", "MARIADB_PASSWORD": testPw},
		[]string{"sh", "-c", `mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e 'select 1' appdb`})
	// mariadb:11 dropped the mysql* compatibility names. The dump side
	// falls back to mariadb-dump on its own (and must be detected as
	// MariaDB so --set-gtid-purged is left out); restore/reset/rotate
	// still call the client as `mysql`.
	execIn(t, md, "sh", "-c", "ln -sf /usr/bin/mariadb /usr/local/bin/mysql")
	if tool, err := detectMySQLDumpTool(md); err != nil || !tool.mariaDB {
		t.Fatalf("detectMySQLDumpTool(mariadb:11) = %+v, %v", tool, err)
	}
	creds := testCreds()
	sql := func(pw, q string) string {
		cmd := exec.Command("docker", "exec", "-e", "MYSQL_PWD", md, "mariadb", "-uroot", "-N", "-e", q, "appdb")
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+pw)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("mariadb: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	sql(testRootPw, "create table t(id int); insert into t values (1),(2);")
	roundTrip(t, "mariadb", md, creds, func() { sql(testRootPw, "delete from t") })
	if got := sql(testRootPw, "select count(*) from t"); got != "2" {
		t.Fatalf("restore lost rows: %q", got)
	}
	newRoot := testNewPw + "-root"
	if err := alterPassword(md, "mysql", creds, map[string]string{"password": testNewPw, "rootPassword": newRoot}, logs.NewStreamer(nil, "op"), &Executor{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := sql(newRoot, "select 1"); got != "1" {
		t.Fatalf("root login with rotated password: %q", got)
	}
}

func TestDockerMySQLOps(t *testing.T) {
	my := startDBContainer(t, "mysql:8.4",
		map[string]string{"MYSQL_ROOT_PASSWORD": testRootPw, "MYSQL_DATABASE": "appdb", "MYSQL_USER": "app", "MYSQL_PASSWORD": testPw},
		// TCP only answers once the entrypoint's init server (which runs
		// with --skip-networking) has been replaced by the real one.
		[]string{"sh", "-c", `mysql -h127.0.0.1 -uroot -p"$MYSQL_ROOT_PASSWORD" -e 'select 1' appdb`})
	if tool, err := detectMySQLDumpTool(my); err != nil || tool.name != "mysqldump" || tool.mariaDB {
		t.Fatalf("detectMySQLDumpTool(mysql:8.4) = %+v, %v", tool, err)
	}
	creds := testCreds()
	sql := func(pw, q string) string {
		cmd := exec.Command("docker", "exec", "-e", "MYSQL_PWD", my, "mysql", "-uroot", "-N", "-e", q, "appdb")
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+pw)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("mysql: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	sql(testRootPw, "create table t(id int); insert into t values (1),(2);")
	roundTrip(t, "mysql", my, creds, func() { sql(testRootPw, "delete from t") })
	if got := sql(testRootPw, "select count(*) from t"); got != "2" {
		t.Fatalf("restore lost rows: %q", got)
	}
	newRoot := testNewPw + "-root"
	if err := alterPassword(my, "mysql", creds, map[string]string{"password": testNewPw, "rootPassword": newRoot}, logs.NewStreamer(nil, "op"), &Executor{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := sql(newRoot, "select 1"); got != "1" {
		t.Fatalf("root login with rotated password: %q", got)
	}
	cmd := exec.Command("docker", "exec", "-e", "MYSQL_PWD", my, "mysql", "-h127.0.0.1", "-uapp", "-N", "-e", "select 1", "appdb")
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+testNewPw)
	if out, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("app login with rotated password failed: %v %s", err, out)
	}
}

// Volume migration: the helper container refuses symlinked source
// components and copies files and directories with ownership preserved.
func TestDockerVolumeMigrateScript(t *testing.T) {
	requireDocker(t)
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	for _, d := range []string{filepath.Join(src, "data", "nested"), dst} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "data", "nested", "f.txt"), []byte("hello"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "single.conf"), []byte("conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(src, "evil")); err != nil {
		t.Fatal(err)
	}

	run := func(rel, name string) (string, error) {
		out, err := exec.Command("docker", volumeMigrateDockerArgs(src, rel, dst, name)...).CombinedOutput()
		return string(out), err
	}
	if out, err := run("data", "vol"); err != nil {
		t.Fatalf("dir copy: %v %s", err, out)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "vol", "nested", "f.txt")); err != nil || string(b) != "hello" {
		t.Fatalf("dir copy content: %q %v", b, err)
	}
	if out, err := run("single.conf", "file.conf"); err != nil {
		t.Fatalf("file copy: %v %s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "file.conf")); string(b) != "conf" {
		t.Fatalf("file copy content: %q", b)
	}
	if out, err := run("evil", "x"); err == nil || !strings.Contains(out, "symlink") {
		t.Fatalf("symlink source not refused: %v %s", err, out)
	}
	if out, err := run("evil/passwd", "x"); err == nil || !strings.Contains(out, "symlink") {
		t.Fatalf("symlink component not refused: %v %s", err, out)
	}
	if out, err := run("missing", "x"); err == nil || !strings.Contains(out, "does not exist") {
		t.Fatalf("missing source: %v %s", err, out)
	}
}

// PR 0.8: a restore whose backup can't be fetched (or fails verification)
// must abort before the target database is reset.
func TestDockerRestoreAbortsBeforeResetOnBadDownload(t *testing.T) {
	pg := startDBContainer(t, "postgres:16-alpine",
		map[string]string{"POSTGRES_USER": "app", "POSTGRES_PASSWORD": testPw, "POSTGRES_DB": "appdb"},
		[]string{"psql", "-U", "app", "-d", "appdb", "-c", "select 1"})
	execIn(t, pg, "psql", "-U", "app", "-d", "appdb", "-c", "create table t(id int); insert into t values (1),(2);")
	useTempBackupDir(t)

	for _, tc := range []struct {
		name   string
		status int
		body   []byte
	}{
		{"missing object", 404, []byte("NoSuchKey")},
		{"corrupt object", 200, []byte("not a gzip stream")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/backup-credentials/"):
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
						"engine": "postgres", "containerName": pg, "creds": testCreds(),
					}})
				case strings.HasSuffix(r.URL.Path, "/download-url"):
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{"url": srv.URL + "/object", "key": "k"}})
				case r.URL.Path == "/object":
					w.WriteHeader(tc.status)
					_, _ = w.Write(tc.body)
				case strings.HasSuffix(r.URL.Path, "/upload-url"):
					t.Errorf("safety backup started before the download was verified")
					http.Error(w, "no", 500)
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()

			e := New(client.New(srv.URL, "tok"))
			err := e.Restore(client.Operation{ID: "op", Payload: map[string]interface{}{
				"databaseId": "11111111-1111-1111-1111-111111111111", "restoreBackupId": "b1", "safetyBackupId": "b2",
			}})
			if err == nil || !strings.Contains(err.Error(), "live data untouched") {
				t.Fatalf("expected abort before reset, got %v", err)
			}
			if out := execIn(t, pg, "psql", "-At", "-U", "app", "-d", "appdb", "-c", "select count(*) from t"); strings.TrimSpace(out) != "2" {
				t.Fatalf("database was modified: %q", out)
			}
		})
	}
}
