package opschema

import (
	"strings"
	"testing"
)

const (
	svc = "11111111-1111-4111-8111-111111111111"
	db  = "22222222-2222-4222-8222-222222222222"
	id3 = "33333333-3333-4333-8333-333333333333"
)

func validDeploy() map[string]interface{} {
	return map[string]interface{}{
		"serviceId":     svc,
		"dockerImage":   "ghcr.io/stackedhq/app:1.2.3",
		"restartPolicy": "unless-stopped",
		"cpuLimit":      float64(1000),
		"memoryLimitMb": float64(512),
	}
}

func TestDecode_EveryOpTypeHappyPath(t *testing.T) {
	cases := []struct {
		typ     string
		payload map[string]interface{}
	}{
		{"deploy", validDeploy()},
		{"release_command", map[string]interface{}{"serviceId": svc, "releaseCommand": "bun db:migrate", "dockerImage": "nginx:1.25"}},
		{"cron_run", map[string]interface{}{"serviceId": svc, "command": "node job.js"}},
		{"cron_run", map[string]interface{}{"mode": "http", "httpUrl": "https://example.com/cron", "httpMethod": "POST"}},
		{"stop", map[string]interface{}{"serviceId": svc}},
		{"restart", map[string]interface{}{"serviceId": svc}},
		{"service_destroy", map[string]interface{}{"serviceId": svc, "removeVolumes": false}},
		{"setup", map[string]interface{}{}},
		{"proxy_config", map[string]interface{}{"domains": []interface{}{
			map[string]interface{}{"domain": "app.example.com", "serviceId": svc, "port": float64(3000)},
		}}},
		{"ssl_check", map[string]interface{}{"domains": []interface{}{map[string]interface{}{"domain": "app.example.com"}}}},
		{"self_update", map[string]interface{}{"targetVersion": "0.9.0"}},
		{"db_provision", map[string]interface{}{
			"databaseId": db, "dbType": "postgres", "port": float64(5432),
			"containerName": "db-app", "dockerImage": "postgres:16",
			"credentials": map[string]interface{}{"user": "u", "password": "p", "dbName": "d"},
		}},
		{"db_start", map[string]interface{}{"databaseId": db}},
		{"db_stop", map[string]interface{}{"databaseId": db}},
		{"db_destroy", map[string]interface{}{"databaseId": db}},
		{"db_extension_enable", map[string]interface{}{
			"databaseId": db, "containerName": "db-app", "extensionName": "pg_trgm",
			"dbUser": "app", "dbName": "app",
		}},
		{"db_extension_disable", map[string]interface{}{
			"databaseId": db, "containerName": "db-app", "extensionName": "pg_trgm",
			"dbUser": "app", "dbName": "app",
		}},
		{"db_set_access", map[string]interface{}{
			"databaseId": db, "dbType": "postgres", "containerName": "db-app",
			"port": float64(5432), "accessMode": "internal",
		}},
		{"db_rotate_password", map[string]interface{}{
			"databaseId": db, "dbType": "redis", "containerName": "db-redis",
			"dockerImage":    "redis:7",
			"oldCredentials": map[string]interface{}{"password": "old"},
			"newCredentials": map[string]interface{}{"password": "new"},
		}},
		{"db_migrate", map[string]interface{}{"migrationTargetId": id3, "dbType": "mysql"}},
		{"volume_migrate", map[string]interface{}{
			"migrationTargetId": id3,
			"sourceVolumePath":  "/var/lib/dokploy/data",
			"targetVolumePath":  "/opt/stacked/data/services/" + svc + "/data",
		}},
		{"volume_migrate", map[string]interface{}{"migrationTargetId": id3}},
		{"cron_run", map[string]interface{}{"mode": "http", "httpUrl": "https://example.com/cron", "httpAllowPrivate": false, "httpAllowLoopback": true}},
		{"self_update", map[string]interface{}{"targetVersion": "0.9.0", "allowDowngrade": true}},
		{"db_backup", map[string]interface{}{"databaseId": db, "backupId": id3}},
		{"db_restore", map[string]interface{}{"databaseId": db, "restoreBackupId": id3, "safetyBackupId": svc}},
		{"db_query", map[string]interface{}{}},
		{"tailscale_setup", map[string]interface{}{"hostname": "my-vps"}},
		{"tailscale_disable", map[string]interface{}{}},
		{"dokploy_takeover_probe", map[string]interface{}{"containerNames": []interface{}{"app-web"}}},
		{"dokploy_traefik_stop", map[string]interface{}{}},
		{"dokploy_traefik_start", map[string]interface{}{}},
		{"dokploy_caddy_attach_network", map[string]interface{}{"network": "dokploy-network"}},
		{"dokploy_caddy_detach_network", map[string]interface{}{"network": "dokploy-network"}},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			p, err := Decode(c.typ, c.payload)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if p.OpType() != c.typ {
				t.Fatalf("OpType = %q", p.OpType())
			}
		})
	}
}

func TestDecode_MalformedEveryOpType(t *testing.T) {
	type tc struct {
		name    string
		typ     string
		payload map[string]interface{}
		want    string
	}
	cases := []tc{
		{"deploy bad uuid", "deploy", map[string]interface{}{"serviceId": "not-a-uuid"}, "UUID"},
		{"deploy bad image", "deploy", map[string]interface{}{"serviceId": svc, "dockerImage": "nginx; rm -rf /"}, "image"},
		{"deploy bad restart", "deploy", map[string]interface{}{"serviceId": svc, "restartPolicy": "forever"}, "restartPolicy"},
		{"deploy bad path", "deploy", map[string]interface{}{"serviceId": svc, "volumes": []interface{}{
			map[string]interface{}{"hostPath": "/tmp/../etc", "containerPath": "/data"},
		}}, "invalid"},
		{"deploy unknown field", "deploy", map[string]interface{}{"serviceId": svc, "pwn": "1"}, "unknown"},
		{"release missing uuid", "release_command", map[string]interface{}{"releaseCommand": "true"}, "UUID"},
		{"cron bad url", "cron_run", map[string]interface{}{"mode": "http", "httpUrl": "javascript:alert(1)"}, "httpUrl"},
		{"cron bad method", "cron_run", map[string]interface{}{"mode": "http", "httpUrl": "https://x.com", "httpMethod": "TRACE"}, "httpMethod"},
		{"cron command injection image", "cron_run", map[string]interface{}{"serviceId": svc, "command": "x", "dockerImage": "x\nimage: evil"}, "image"},
		{"stop bad id", "stop", map[string]interface{}{"serviceId": "../etc"}, "UUID"},
		{"restart extra field", "restart", map[string]interface{}{"serviceId": svc, "force": true}, "unknown"},
		{"destroy bad flag", "service_destroy", map[string]interface{}{"serviceId": svc, "removeVolumes": "yes"}, "boolean"},
		{"setup extra", "setup", map[string]interface{}{"root": true}, "unknown"},
		{"proxy bad domain", "proxy_config", map[string]interface{}{"domains": []interface{}{
			map[string]interface{}{"domain": "not a host", "serviceId": svc, "port": float64(80)},
		}}, "invalid"},
		{"proxy bad path", "proxy_config", map[string]interface{}{"domains": []interface{}{
			map[string]interface{}{"domain": "a.com", "serviceId": svc, "path": "/../admin"},
		}}, "invalid"},
		{"proxy bad port", "proxy_config", map[string]interface{}{"domains": []interface{}{
			map[string]interface{}{"domain": "a.com", "host": "127.0.0.1", "port": float64(70000)},
		}}, "port"},
		{"ssl bad domain", "ssl_check", map[string]interface{}{"domains": []interface{}{
			map[string]interface{}{"domain": "foo; rm"},
		}}, "invalid"},
		{"self_update bad version", "self_update", map[string]interface{}{"targetVersion": "../x"}, "targetVersion"},
		{"self_update http url", "self_update", map[string]interface{}{"targetVersion": "1.0.0", "downloadUrl": "http://evil.test/agent"}, "downloadUrl"},
		{"db_provision bad image", "db_provision", map[string]interface{}{
			"databaseId": db, "dbType": "postgres", "port": float64(5432),
			"containerName": "db", "dockerImage": "postgres:16\n  privileged: true",
		}, "image"},
		{"db_provision bad type", "db_provision", map[string]interface{}{
			"databaseId": db, "dbType": "sqlite", "port": float64(1),
			"containerName": "db", "dockerImage": "postgres:16",
		}, "dbType"},
		{"db_start bad id", "db_start", map[string]interface{}{"databaseId": "db-1"}, "UUID"},
		{"db_stop extra", "db_stop", map[string]interface{}{"databaseId": db, "signal": "KILL"}, "unknown"},
		{"db_destroy extra", "db_destroy", map[string]interface{}{"databaseId": db, "force": true}, "unknown"},
		{"ext bad name", "db_extension_enable", map[string]interface{}{
			"databaseId": db, "containerName": "db", "extensionName": `x"; DROP TABLE`,
			"dbUser": "u", "dbName": "d",
		}, "extensionName"},
		{"ext disable bad user", "db_extension_disable", map[string]interface{}{
			"databaseId": db, "containerName": "db", "extensionName": "citext",
			"dbUser": "u;id", "dbName": "d",
		}, "dbUser"},
		{"set_access bad mode", "db_set_access", map[string]interface{}{
			"databaseId": db, "dbType": "postgres", "containerName": "db",
			"port": float64(5432), "accessMode": "world",
		}, "accessMode"},
		{"rotate bad container", "db_rotate_password", map[string]interface{}{
			"databaseId": db, "dbType": "postgres", "containerName": "-bad",
			"dockerImage":    "postgres:16",
			"oldCredentials": map[string]interface{}{"password": "a"},
			"newCredentials": map[string]interface{}{"password": "b"},
		}, "container"},
		{"migrate bad type", "db_migrate", map[string]interface{}{"migrationTargetId": id3, "dbType": "cassandra"}, "dbType"},
		{"volume_migrate relative", "volume_migrate", map[string]interface{}{
			"migrationTargetId": id3, "sourceVolumePath": "etc/passwd",
		}, "invalid"},
		{"volume_migrate missing id", "volume_migrate", map[string]interface{}{
			"sourceVolumePath": "/var/lib/dokploy/data", "targetVolumePath": "/opt/stacked/data/services/x",
		}, "UUID"},
		{"cron unknown http flag", "cron_run", map[string]interface{}{
			"mode": "http", "httpUrl": "https://example.com", "httpAllowLan": true,
		}, "unknown"},
		{"self_update allowDowngrade type", "self_update", map[string]interface{}{
			"targetVersion": "0.9.0", "allowDowngrade": "yes",
		}, "boolean"},
		{"deploy yaml capAdd", "deploy", map[string]interface{}{
			"serviceId": svc, "capAdd": []interface{}{"SYS_ADMIN\n    volumes:"},
		}, "capAdd"},
		{"backup bad ids", "db_backup", map[string]interface{}{"databaseId": "x", "backupId": "y"}, "UUID"},
		{"restore missing restore id", "db_restore", map[string]interface{}{"databaseId": db}, "UUID"},
		{"db_query extra", "db_query", map[string]interface{}{"sql": "select 1"}, "unknown"},
		{"tailscale bad host", "tailscale_setup", map[string]interface{}{"hostname": "foo.bar"}, "hostname"},
		{"tailscale_disable extra", "tailscale_disable", map[string]interface{}{"purge": true}, "unknown"},
		{"probe bad name", "dokploy_takeover_probe", map[string]interface{}{"containerNames": []interface{}{"$(id)"}}, "invalid"},
		{"traefik stop extra", "dokploy_traefik_stop", map[string]interface{}{"container": "x"}, "unknown"},
		{"traefik start extra", "dokploy_traefik_start", map[string]interface{}{"container": "x"}, "unknown"},
		{"attach bad net", "dokploy_caddy_attach_network", map[string]interface{}{"network": "net; rm"}, "network"},
		{"detach bad net", "dokploy_caddy_detach_network", map[string]interface{}{"network": "/overlay"}, "network"},
		{"unknown type", "rm_rf", map[string]interface{}{}, "unknown operation type"},
		{"schema version", "setup", map[string]interface{}{"schemaVersion": float64(99)}, "schemaVersion"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.typ, c.payload)
			if err == nil {
				t.Fatalf("expected error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.want)
			}
		})
	}
}

func TestDecode_ProxyPortBoundAndPath(t *testing.T) {
	p, err := Decode("proxy_config", map[string]interface{}{
		"domains": []interface{}{
			map[string]interface{}{
				"domain":      "api.example.com",
				"host":        "127.0.0.1",
				"port":        float64(8080),
				"scheme":      "http",
				"path":        "/api",
				"stripPrefix": true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := p.(ProxyConfig)
	if !cfg.Domains[0].IsPortBound() || cfg.Domains[0].EffectivePath() != "/api" {
		t.Fatalf("%+v", cfg.Domains[0])
	}
}
