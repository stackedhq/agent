package opschema

import "fmt"

// SchemaVersion is the closed payload contract. Current servers omit the
// field (legacy). When present it must be 1. Newer versions fail closed
// until this agent learns them.
const SchemaVersion = 1

// Payload is a decoded, validated operation body. Handlers and renderers
// consume these types instead of map[string]interface{}.
type Payload interface {
	OpType() string
}

// Decode is the single validation entry point. It must run before any
// status transition or side effect.
func Decode(opType string, raw map[string]interface{}) (Payload, error) {
	if raw == nil {
		raw = map[string]interface{}{}
	}
	if err := checkSchemaVersion(raw); err != nil {
		return nil, err
	}
	switch opType {
	case "deploy":
		return decodeServiceDeploy(opType, raw, false)
	case "release_command":
		return decodeServiceDeploy(opType, raw, true)
	case "cron_run":
		return decodeCronRun(raw)
	case "stop", "restart":
		return decodeServiceRef(opType, raw)
	case "service_destroy":
		return decodeServiceDestroy(raw)
	case "setup", "tailscale_disable", "db_query",
		"dokploy_traefik_stop", "dokploy_traefik_start":
		return decodeEmpty(opType, raw)
	case "proxy_config":
		return decodeProxyConfig(raw)
	case "ssl_check":
		return decodeSSLCheck(raw)
	case "self_update":
		return decodeSelfUpdate(raw)
	case "db_provision":
		return decodeDBProvision(raw)
	case "db_start", "db_stop", "db_destroy":
		return decodeDatabaseRef(opType, raw)
	case "db_extension_enable", "db_extension_disable":
		return decodeDBExtension(opType, raw)
	case "db_set_access":
		return decodeDBSetAccess(raw)
	case "db_rotate_password":
		return decodeDBRotatePassword(raw)
	case "db_migrate":
		return decodeDBMigrate(raw)
	case "volume_migrate":
		return decodeVolumeMigrate(raw)
	case "db_backup":
		return decodeDBBackup(raw)
	case "db_restore":
		return decodeDBRestore(raw)
	case "tailscale_setup":
		return decodeTailscaleSetup(raw)
	case "dokploy_takeover_probe":
		return decodeDokployProbe(raw)
	case "dokploy_caddy_attach_network", "dokploy_caddy_detach_network":
		return decodeDokployNetwork(opType, raw)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", opType)
	}
}

func checkSchemaVersion(raw map[string]interface{}) error {
	v, ok := raw["schemaVersion"]
	if !ok || v == nil {
		return nil
	}
	n, err := asInt(v, "schemaVersion")
	if err != nil {
		return err
	}
	if n != SchemaVersion {
		return fmt.Errorf("unsupported payload schemaVersion %d", n)
	}
	return nil
}

func withSchema(keys ...string) map[string]struct{} {
	m := map[string]struct{}{"schemaVersion": {}}
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}
