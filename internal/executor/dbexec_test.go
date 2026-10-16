package executor

import (
	"strings"
	"testing"
)

const (
	testPw     = "s3cret-Pw'\"$x\\y"
	testRootPw = "r00t-Pw'\"$x\\y"
	testNewPw  = "n3w-Pw'\"$x\\y"
)

func testCreds() map[string]string {
	return map[string]string{"user": "app", "password": testPw, "rootPassword": testRootPw, "dbName": "appdb"}
}

func assertNoSecretInArgv(t *testing.T, label string, args []string, secrets ...string) {
	t.Helper()
	joined := strings.Join(args, "\x00")
	for _, s := range secrets {
		if s != "" && strings.Contains(joined, s) {
			t.Fatalf("%s: secret %q found in argv %q", label, s, args)
		}
	}
	for _, a := range args {
		if strings.Contains(a, "=") && (strings.HasPrefix(a, "PGPASSWORD") || strings.HasPrefix(a, "MYSQL_PWD") || strings.HasPrefix(a, "REDISCLI_AUTH")) {
			t.Fatalf("%s: env assignment in argv: %q", label, a)
		}
	}
}

func envHas(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func TestNewDockerExecPassesSecretsByName(t *testing.T) {
	d := newDockerExec(true, "c1", map[string]string{"PGPASSWORD": testPw, "A_SECOND": "v"}, "psql", "-U", "app")
	want := []string{"exec", "-i", "-e", "A_SECOND", "-e", "PGPASSWORD", "c1", "psql", "-U", "app"}
	if strings.Join(d.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %q, want %q", d.Args, want)
	}
	env := d.Env()
	if !envHas(env, "PGPASSWORD="+testPw) || !envHas(env, "A_SECOND=v") {
		t.Fatalf("secrets missing from CLI env")
	}
	if newDockerExec(false, "c1", nil, "true").Env() != nil {
		t.Fatalf("no secrets should inherit env (nil)")
	}
}

func TestBackupAndRestoreArgsKeepPasswordsOutOfArgv(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo"} {
		dump, err := buildBackupDumpArgs(engine, "db1", testCreds(), "/tmp/stacked-mongo-x.yaml", mysqlDumpTool{})
		if err != nil {
			t.Fatalf("%s dump: %v", engine, err)
		}
		assertNoSecretInArgv(t, engine+" dump", dump.Args, testPw, testRootPw)
		restore, err := buildBackupRestoreArgs(engine, "db1", testCreds(), "/tmp/stacked-mongo-x.yaml")
		if err != nil {
			t.Fatalf("%s restore: %v", engine, err)
		}
		assertNoSecretInArgv(t, engine+" restore", restore.Args, testPw, testRootPw)
		if restore.Args[1] != "-i" {
			t.Fatalf("%s restore must read stdin: %q", engine, restore.Args)
		}
		switch engine {
		case "postgres":
			if !envHas(dump.Env(), "PGPASSWORD="+testPw) {
				t.Fatalf("postgres dump: PGPASSWORD not in CLI env")
			}
		case "mysql", "mariadb":
			if !envHas(restore.Env(), "MYSQL_PWD="+testRootPw) {
				t.Fatalf("%s restore: MYSQL_PWD not in CLI env", engine)
			}
		case "mongo":
			if !strings.Contains(strings.Join(dump.Args, " "), "--config=/tmp/stacked-mongo-x.yaml") {
				t.Fatalf("mongo dump must use --config: %q", dump.Args)
			}
		}
	}
	if _, err := buildBackupDumpArgs("mongo", "db1", testCreds(), "", mysqlDumpTool{}); err == nil {
		t.Fatalf("mongo dump without a config file must fail rather than prompt")
	}
}

func TestMigrationPipeAndResetKeepPasswordsOutOfArgv(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql", "mongo"} {
		dump, restore, err := buildPipeArgs(engine, "src", "tgt", testCreds(), testCreds(), "/tmp/a.yaml", "/tmp/b.yaml", mysqlDumpTool{})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		assertNoSecretInArgv(t, engine+" pipe dump", dump.Args, testPw, testRootPw)
		assertNoSecretInArgv(t, engine+" pipe restore", restore.Args, testPw, testRootPw)
		if dump.Args[len(dump.Args)-1] == "" || restore.Args[1] != "-i" {
			t.Fatalf("%s: unexpected args %q / %q", engine, dump.Args, restore.Args)
		}
	}
}

func TestAlterPasswordKeepsPasswordsOutOfArgv(t *testing.T) {
	oldCreds := testCreds()
	newCreds := map[string]string{"password": testNewPw, "rootPassword": testNewPw + "-root"}
	for _, engine := range []string{"postgres", "mysql", "mongo", "redis"} {
		step, err := buildAlterPassword("db1", engine, oldCreds, newCreds)
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		assertNoSecretInArgv(t, engine, step.exec.Args, testPw, testRootPw, testNewPw)
		env := strings.Join(step.exec.Env(), "\n")
		switch engine {
		case "postgres":
			if !strings.Contains(step.stdin, `WITH PASSWORD 'n3w-Pw''"$x\y'`) {
				t.Fatalf("postgres stdin = %q", step.stdin)
			}
			if !strings.Contains(step.stdin, `ALTER USER "app"`) {
				t.Fatalf("postgres user not quoted: %q", step.stdin)
			}
		case "mysql":
			if !strings.Contains(env, "MYSQL_PWD="+testRootPw) || !strings.Contains(step.stdin, `IDENTIFIED BY 'n3w-Pw''"$x\\y'`) {
				t.Fatalf("mysql: env/stdin wrong: %q", step.stdin)
			}
		case "mongo":
			if !strings.Contains(env, "STACKED_MONGO_OLD_PASSWORD="+testPw) || !strings.Contains(env, "STACKED_MONGO_NEW_PASSWORD="+testNewPw) {
				t.Fatalf("mongo: passwords not in CLI env")
			}
		case "redis":
			if !strings.Contains(env, "REDISCLI_AUTH="+testPw) || step.stdin != testNewPw || step.expectOutput != "OK" {
				t.Fatalf("redis: env/stdin/expect wrong")
			}
		}
	}
}

func TestMongoConfigYAMLQuotesPassword(t *testing.T) {
	got := mongoConfigYAML("a\"b\\c\nd: e")
	if got != `password: "a\"b\\c\nd: e"`+"\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMySQLDumpToolArgv(t *testing.T) {
	mysql := strings.Join(mysqlDumpTool{}.argv("appdb"), " ")
	if mysql != "mysqldump -u root --single-transaction --routines --triggers --set-gtid-purged=OFF appdb" {
		t.Fatalf("mysql argv = %q", mysql)
	}
	for _, tool := range []mysqlDumpTool{{name: "mysqldump", mariaDB: true}, {name: "mariadb-dump", mariaDB: true}} {
		got := tool.argv("appdb")
		if strings.Contains(strings.Join(got, " "), "gtid") {
			t.Fatalf("MariaDB dump must not get --set-gtid-purged: %q", got)
		}
		if got[0] != tool.name || got[len(got)-1] != "appdb" {
			t.Fatalf("argv = %q", got)
		}
	}
	dump, err := buildBackupDumpArgs("mariadb", "db1", testCreds(), "", mysqlDumpTool{name: "mariadb-dump", mariaDB: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(dump.Args, " "), "gtid") || !strings.Contains(strings.Join(dump.Args, " "), "db1 mariadb-dump") {
		t.Fatalf("mariadb dump args = %q", dump.Args)
	}
}

func TestIsMariaDBVersion(t *testing.T) {
	cases := map[string]bool{
		"mysqldump  Ver 10.19 Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)":   true,
		"mariadb-dump from 11.4.2-MariaDB, client 10.19 for debian-linux-gnu (aarch64)": true,
		"mysqldump  Ver 8.4.2 for Linux on x86_64 (MySQL Community Server - GPL)":       false,
	}
	for banner, want := range cases {
		if got := isMariaDBVersion(banner); got != want {
			t.Errorf("isMariaDBVersion(%q) = %v, want %v", banner, got, want)
		}
	}
}

func TestSanitizeAlterPasswordOutput(t *testing.T) {
	out := strings.Join([]string{
		`ERROR:  syntax error at or near "WITH"`,
		`LINE 2: ALTER USER "app" WITH PASSWORD 'n3w-secret';`,
		`                         ^`,
		`mysql: [Warning] could not use n3w-secret here`,
		`ERROR 1045 (28000): Access denied for user 'root'@'localhost'`,
	}, "\n")
	got := sanitizeAlterPasswordOutput(out, map[string]string{"user": "app", "password": "old-secret"}, map[string]string{"password": "n3w-secret"})
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "n3w-secret") || strings.Contains(joined, "ALTER USER") {
		t.Fatalf("password leaked into log output:\n%s", joined)
	}
	if strings.Contains(joined, "^") {
		t.Fatalf("caret marker for the dropped LINE should be dropped too:\n%s", joined)
	}
	if !strings.Contains(joined, "syntax error") || !strings.Contains(joined, "Access denied") {
		t.Fatalf("non-secret lines must be kept:\n%s", joined)
	}
	// The user name is not a secret and stays readable.
	if !strings.Contains(joined, "'root'@'localhost'") {
		t.Fatalf("unexpected masking:\n%s", joined)
	}
}
