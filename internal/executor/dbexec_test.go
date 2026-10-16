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
		dump, err := buildBackupDumpArgs(engine, "db1", testCreds(), "/tmp/stacked-mongo-x.yaml")
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
	if _, err := buildBackupDumpArgs("mongo", "db1", testCreds(), ""); err == nil {
		t.Fatalf("mongo dump without a config file must fail rather than prompt")
	}
}

func TestMigrationPipeAndResetKeepPasswordsOutOfArgv(t *testing.T) {
	for _, engine := range []string{"postgres", "mysql", "mongo"} {
		dump, restore, err := buildPipeArgs(engine, "src", "tgt", testCreds(), testCreds(), "/tmp/a.yaml", "/tmp/b.yaml")
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
