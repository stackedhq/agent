package opschema

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Empty is a closed payload with no operation-specific fields.
type Empty struct{ Type string }

func (p Empty) OpType() string { return p.Type }

func decodeEmpty(opType string, raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(), opType); err != nil {
		return nil, err
	}
	return Empty{Type: opType}, nil
}

// ServiceRef is used by stop/restart.
type ServiceRef struct {
	Type      string
	ServiceID string
}

func (p ServiceRef) OpType() string { return p.Type }

func decodeServiceRef(opType string, raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("serviceId"), opType); err != nil {
		return nil, err
	}
	id, err := asString(raw["serviceId"], "serviceId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("serviceId", id); err != nil {
		return nil, err
	}
	return ServiceRef{Type: opType, ServiceID: id}, nil
}

// ServiceDestroy tears down a service.
type ServiceDestroy struct {
	ServiceID     string
	RemoveVolumes bool
}

func (ServiceDestroy) OpType() string { return "service_destroy" }

func decodeServiceDestroy(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("serviceId", "removeVolumes"), "service_destroy"); err != nil {
		return nil, err
	}
	id, err := asString(raw["serviceId"], "serviceId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("serviceId", id); err != nil {
		return nil, err
	}
	remove := true
	if _, ok := raw["removeVolumes"]; ok {
		remove, err = asBool(raw["removeVolumes"], "removeVolumes")
		if err != nil {
			return nil, err
		}
	}
	return ServiceDestroy{ServiceID: id, RemoveVolumes: remove}, nil
}

// Volume is one host bind mount from a deploy payload.
type Volume struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
	Mode          string
}

// FileMountMeta is metadata only — plaintext is fetched separately.
type FileMountMeta struct {
	ID            string
	ContainerPath string
}

// Limits are per-container CPU/memory caps and the restart policy.
type Limits struct {
	CPUMillicores int
	MemoryMB      int
	RestartPolicy string
}

// ServiceDeploy is the typed body for deploy and release_command.
type ServiceDeploy struct {
	Type                  string
	ServiceID             string
	DockerImage           string
	DeployStrategy        string
	GitBranch             string
	CommitSHA             string
	BuildCommand          string
	StartCommand          string
	GitRepo               string
	ReleaseCommand        string
	HealthCheckPath       string
	HealthCheckTimeoutSec int
	StopGraceSec          int
	CPULimit              int
	MemoryLimitMB         int
	RestartPolicy         string
	Volumes               []Volume
	FileMounts            []FileMountMeta
	HasFileMounts         bool
}

func (p ServiceDeploy) OpType() string { return p.Type }

func (p ServiceDeploy) Limits() Limits {
	rp := p.RestartPolicy
	if rp == "" {
		rp = "unless-stopped"
	}
	return Limits{
		CPUMillicores: p.CPULimit,
		MemoryMB:      p.MemoryLimitMB,
		RestartPolicy: rp,
	}
}

func (p ServiceDeploy) DockerCommandOverride() string {
	if p.DockerImage == "" {
		return ""
	}
	return strings.TrimSpace(p.StartCommand)
}

func decodeServiceDeploy(opType string, raw map[string]interface{}, release bool) (Payload, error) {
	allowed := withSchema(
		"serviceId", "dockerImage", "deployStrategy",
		"gitBranch", "commitSha", "buildCommand", "startCommand", "gitRepo",
		"releaseCommand", "healthCheckPath", "healthCheckTimeoutSec", "stopGraceSec",
		"cpuLimit", "memoryLimitMb", "restartPolicy", "volumes", "fileMounts",
		"isolationRelaxed", "allowPrivilegeEscalation", "privileged", "readOnlyRoot",
		"capAdd", "capDrop", "pidsLimit", "tmpfs",
		"networkIsolation", "linkedServiceIds", "linkedDatabaseIds",
	)
	if err := rejectUnknown(raw, allowed, opType); err != nil {
		return nil, err
	}
	p := ServiceDeploy{Type: opType}
	var err error
	if p.ServiceID, err = asString(raw["serviceId"], "serviceId"); err != nil {
		return nil, err
	}
	if err := requireUUID("serviceId", p.ServiceID); err != nil {
		return nil, err
	}
	if p.DockerImage, err = asString(raw["dockerImage"], "dockerImage"); err != nil {
		return nil, err
	}
	if err := optionalImage("dockerImage", p.DockerImage); err != nil {
		return nil, err
	}
	if p.DeployStrategy, err = asString(raw["deployStrategy"], "deployStrategy"); err != nil {
		return nil, err
	}
	if !validDeployStrategy(p.DeployStrategy) {
		return nil, fmt.Errorf("deployStrategy is invalid")
	}
	if p.GitBranch, err = asString(raw["gitBranch"], "gitBranch"); err != nil {
		return nil, err
	}
	if p.GitBranch != "" && (!gitBranchRe.MatchString(p.GitBranch) || strings.Contains(p.GitBranch, "..") || len(p.GitBranch) > 256) {
		return nil, fmt.Errorf("gitBranch is invalid")
	}
	if p.CommitSHA, err = asString(raw["commitSha"], "commitSha"); err != nil {
		return nil, err
	}
	if p.CommitSHA != "" && !commitSHARe.MatchString(p.CommitSHA) {
		return nil, fmt.Errorf("commitSha is invalid")
	}
	if p.BuildCommand, err = asString(raw["buildCommand"], "buildCommand"); err != nil {
		return nil, err
	}
	if err := optionalBounded("buildCommand", p.BuildCommand, maxCommand); err != nil {
		return nil, err
	}
	if p.StartCommand, err = asString(raw["startCommand"], "startCommand"); err != nil {
		return nil, err
	}
	if err := optionalBounded("startCommand", p.StartCommand, maxCommand); err != nil {
		return nil, err
	}
	if p.GitRepo, err = asString(raw["gitRepo"], "gitRepo"); err != nil {
		return nil, err
	}
	if err := optionalBounded("gitRepo", p.GitRepo, maxURL); err != nil {
		return nil, err
	}
	if p.ReleaseCommand, err = asString(raw["releaseCommand"], "releaseCommand"); err != nil {
		return nil, err
	}
	if err := optionalBounded("releaseCommand", p.ReleaseCommand, maxCommand); err != nil {
		return nil, err
	}
	if release && strings.TrimSpace(p.ReleaseCommand) == "" {
		// Server should not enqueue this, but a no-op release is valid.
	}
	if p.HealthCheckPath, err = asString(raw["healthCheckPath"], "healthCheckPath"); err != nil {
		return nil, err
	}
	if p.HealthCheckPath != "" && !validRoutePath(p.HealthCheckPath) {
		return nil, fmt.Errorf("healthCheckPath is invalid")
	}
	if p.HealthCheckTimeoutSec, err = asInt(raw["healthCheckTimeoutSec"], "healthCheckTimeoutSec"); err != nil {
		return nil, err
	}
	if p.HealthCheckTimeoutSec == 0 {
		p.HealthCheckTimeoutSec = 60
	} else if p.HealthCheckTimeoutSec < 1 || p.HealthCheckTimeoutSec > maxTimeoutSec {
		return nil, fmt.Errorf("healthCheckTimeoutSec is out of range")
	}
	if p.StopGraceSec, err = asInt(raw["stopGraceSec"], "stopGraceSec"); err != nil {
		return nil, err
	}
	if p.StopGraceSec == 0 {
		p.StopGraceSec = 10
	} else if p.StopGraceSec < 1 || p.StopGraceSec > maxGraceSec {
		return nil, fmt.Errorf("stopGraceSec is out of range")
	}
	if p.CPULimit, err = asInt(raw["cpuLimit"], "cpuLimit"); err != nil {
		return nil, err
	}
	if p.CPULimit < 0 || p.CPULimit > maxCPUMilli {
		return nil, fmt.Errorf("cpuLimit is out of range")
	}
	if p.MemoryLimitMB, err = asInt(raw["memoryLimitMb"], "memoryLimitMb"); err != nil {
		return nil, err
	}
	if p.MemoryLimitMB < 0 || p.MemoryLimitMB > maxMemoryMB {
		return nil, fmt.Errorf("memoryLimitMb is out of range")
	}
	if p.RestartPolicy, err = asString(raw["restartPolicy"], "restartPolicy"); err != nil {
		return nil, err
	}
	if p.RestartPolicy != "" && !validRestartPolicy(p.RestartPolicy) {
		return nil, fmt.Errorf("restartPolicy is invalid")
	}
	vols, err := asObjectSlice(raw["volumes"], "volumes", maxVolumes)
	if err != nil {
		return nil, err
	}
	p.Volumes = make([]Volume, 0, len(vols))
	for i, obj := range vols {
		if err := rejectUnknown(obj, map[string]struct{}{
			"hostPath": {}, "containerPath": {}, "readOnly": {}, "mode": {},
		}, fmt.Sprintf("volumes[%d]", i)); err != nil {
			return nil, err
		}
		vol, err := decodeVolume(obj, i)
		if err != nil {
			return nil, err
		}
		p.Volumes = append(p.Volumes, vol)
	}
	if raw["fileMounts"] != nil {
		metas, err := asObjectSlice(raw["fileMounts"], "fileMounts", maxFileMounts)
		if err != nil {
			return nil, err
		}
		p.HasFileMounts = len(metas) > 0
		for i, obj := range metas {
			if err := rejectUnknown(obj, map[string]struct{}{
				"id": {}, "containerPath": {},
			}, fmt.Sprintf("fileMounts[%d]", i)); err != nil {
				return nil, err
			}
			id, err := asString(obj["id"], "fileMounts.id")
			if err != nil {
				return nil, err
			}
			if id != "" {
				if err := requireUUID("fileMounts.id", id); err != nil {
					return nil, err
				}
			}
			cp, err := asString(obj["containerPath"], "fileMounts.containerPath")
			if err != nil {
				return nil, err
			}
			if cp != "" && !validAbsPath(cp) {
				return nil, fmt.Errorf("fileMounts[%d].containerPath is invalid", i)
			}
			p.FileMounts = append(p.FileMounts, FileMountMeta{ID: id, ContainerPath: cp})
		}
	}
	if err := validateIsolationFields(raw); err != nil {
		return nil, err
	}
	return p, nil
}

func decodeVolume(obj map[string]interface{}, i int) (Volume, error) {
	host, err := asString(obj["hostPath"], "hostPath")
	if err != nil {
		return Volume{}, err
	}
	container, err := asString(obj["containerPath"], "containerPath")
	if err != nil {
		return Volume{}, err
	}
	if !validAbsPath(host) || !validAbsPath(container) {
		return Volume{}, fmt.Errorf("volumes[%d] paths are invalid", i)
	}
	ro, err := asBool(obj["readOnly"], "readOnly")
	if err != nil {
		return Volume{}, err
	}
	mode, err := asString(obj["mode"], "mode")
	if err != nil {
		return Volume{}, err
	}
	if mode != "" && mode != "managed" && mode != "custom" {
		return Volume{}, fmt.Errorf("volumes[%d].mode is invalid", i)
	}
	return Volume{HostPath: host, ContainerPath: container, ReadOnly: ro, Mode: mode}, nil
}

// CronRun is a scheduled job.
type CronRun struct {
	Mode        string
	ServiceID   string
	Command     string
	DockerImage string
	RunID       string
	HTTPURL     string
	HTTPMethod  string
	HTTPBody    string
	HTTPHeaders string
}

func (CronRun) OpType() string { return "cron_run" }

func decodeCronRun(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(
		"mode", "serviceId", "command", "dockerImage", "runId",
		"httpUrl", "httpMethod", "httpBody", "httpHeaders",
		"httpAllowPrivate", "httpAllowLoopback",
		"isolationRelaxed", "allowPrivilegeEscalation", "privileged", "readOnlyRoot",
		"capAdd", "capDrop", "pidsLimit", "tmpfs",
		"networkIsolation", "linkedServiceIds", "linkedDatabaseIds",
	), "cron_run"); err != nil {
		return nil, err
	}
	p := CronRun{}
	var err error
	if p.Mode, err = asString(raw["mode"], "mode"); err != nil {
		return nil, err
	}
	if p.Mode == "" {
		p.Mode = "command"
	}
	if p.Mode != "http" && p.Mode != "command" {
		return nil, fmt.Errorf("mode is invalid")
	}
	if p.ServiceID, err = asString(raw["serviceId"], "serviceId"); err != nil {
		return nil, err
	}
	if p.Command, err = asString(raw["command"], "command"); err != nil {
		return nil, err
	}
	if p.DockerImage, err = asString(raw["dockerImage"], "dockerImage"); err != nil {
		return nil, err
	}
	if p.RunID, err = asString(raw["runId"], "runId"); err != nil {
		return nil, err
	}
	if p.HTTPURL, err = asString(raw["httpUrl"], "httpUrl"); err != nil {
		return nil, err
	}
	if p.HTTPMethod, err = asString(raw["httpMethod"], "httpMethod"); err != nil {
		return nil, err
	}
	if p.HTTPBody, err = asString(raw["httpBody"], "httpBody"); err != nil {
		return nil, err
	}
	if p.HTTPHeaders, err = asString(raw["httpHeaders"], "httpHeaders"); err != nil {
		return nil, err
	}
	if p.Mode == "http" {
		if !validHTTPURL(p.HTTPURL) {
			return nil, fmt.Errorf("httpUrl is invalid")
		}
		if p.HTTPMethod == "" {
			p.HTTPMethod = "GET"
		}
		if !httpMethodRe.MatchString(p.HTTPMethod) {
			return nil, fmt.Errorf("httpMethod is invalid")
		}
		if err := optionalBounded("httpBody", p.HTTPBody, maxBody); err != nil {
			return nil, err
		}
		if p.HTTPHeaders != "" {
			if len(p.HTTPHeaders) > maxHeadersJSON {
				return nil, fmt.Errorf("httpHeaders exceeds max length")
			}
			var hdrs map[string]string
			if err := json.Unmarshal([]byte(p.HTTPHeaders), &hdrs); err != nil {
				return nil, fmt.Errorf("httpHeaders must be a JSON object")
			}
		}
	} else {
		if err := requireUUID("serviceId", p.ServiceID); err != nil {
			return nil, err
		}
		if strings.TrimSpace(p.Command) == "" || !validBounded(p.Command, maxCommand) {
			return nil, fmt.Errorf("command is invalid")
		}
		if err := optionalImage("dockerImage", p.DockerImage); err != nil {
			return nil, err
		}
		if err := optionalUUID("runId", p.RunID); err != nil {
			return nil, err
		}
	}
	if _, err := asBool(raw["httpAllowPrivate"], "httpAllowPrivate"); err != nil {
		return nil, err
	}
	if _, err := asBool(raw["httpAllowLoopback"], "httpAllowLoopback"); err != nil {
		return nil, err
	}
	if err := validateIsolationFields(raw); err != nil {
		return nil, err
	}
	return p, nil
}

// Domain is one proxy_config / ssl_check row.
type Domain struct {
	Domain               string
	ServiceID            string
	Port                 int
	Host                 string
	Scheme               string
	Path                 string
	StripPrefix          *bool
	OnDemandTLS          bool
	AuthGateMode         string
	AuthGateUsername     string
	AuthGatePasswordHash string
	ServiceName          string
}

func (d Domain) EffectivePath() string {
	if d.Path == "" {
		return "/"
	}
	return d.Path
}

func (d Domain) IsPortBound() bool {
	return d.ServiceID == "" && d.Host != "" && d.Port > 0
}

func (d Domain) Validate() error {
	if !validHostname(d.Domain) {
		return fmt.Errorf("domain %q is invalid", d.Domain)
	}
	if d.Path != "" && !validRoutePath(d.Path) {
		return fmt.Errorf("path %q is invalid", d.Path)
	}
	if d.Port != 0 && !validPort(d.Port) {
		return fmt.Errorf("port %d is invalid", d.Port)
	}
	if d.ServiceID != "" && !ValidComposeServiceName(d.ServiceID) {
		return fmt.Errorf("serviceId is invalid")
	}
	if d.Host != "" {
		if err := validUpstreamHost(d.Host); err != nil {
			return fmt.Errorf("host: %w", err)
		}
	}
	if d.Scheme != "" && d.Scheme != "http" && d.Scheme != "https" {
		return fmt.Errorf("scheme is invalid")
	}
	if err := optionalBounded("authGateMode", d.AuthGateMode, 32); err != nil {
		return err
	}
	if d.AuthGateMode != "" && !identRe.MatchString(d.AuthGateMode) {
		return fmt.Errorf("authGateMode is invalid")
	}
	if err := optionalBounded("authGateUsername", d.AuthGateUsername, 256); err != nil {
		return err
	}
	if err := optionalBounded("authGatePasswordHash", d.AuthGatePasswordHash, 256); err != nil {
		return err
	}
	if err := optionalBounded("serviceName", d.ServiceName, 256); err != nil {
		return err
	}
	if d.ServiceID == "" && (d.Host == "" || d.Port == 0) {
		return fmt.Errorf("domain %q is neither service-backed nor port-bound", d.Domain)
	}
	return nil
}

// ProxyConfig is the full desired proxy state.
type ProxyConfig struct {
	Domains []Domain
}

func (ProxyConfig) OpType() string { return "proxy_config" }

func decodeProxyConfig(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("domains", "payloadVersion"), "proxy_config"); err != nil {
		return nil, err
	}
	if _, ok := raw["domains"]; !ok {
		return nil, fmt.Errorf("proxy_config requires domains")
	}
	if _, ok := raw["payloadVersion"]; ok {
		if _, err := asInt(raw["payloadVersion"], "payloadVersion"); err != nil {
			return nil, err
		}
	}
	objs, err := asObjectSlice(raw["domains"], "domains", maxArray)
	if err != nil {
		return nil, err
	}
	domains := make([]Domain, 0, len(objs))
	for i, obj := range objs {
		d, err := decodeDomain(obj, i, true)
		if err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return ProxyConfig{Domains: domains}, nil
}

func decodeDomain(obj map[string]interface{}, i int, requireShape bool) (Domain, error) {
	if err := rejectUnknown(obj, map[string]struct{}{
		"domain": {}, "serviceId": {}, "port": {}, "host": {}, "scheme": {},
		"path": {}, "stripPrefix": {}, "onDemandTls": {},
		"authGateMode": {}, "authGateUsername": {}, "authGatePasswordHash": {},
		"serviceName": {},
	}, fmt.Sprintf("domains[%d]", i)); err != nil {
		return Domain{}, err
	}
	d := Domain{}
	var err error
	if d.Domain, err = asString(obj["domain"], "domain"); err != nil {
		return Domain{}, err
	}
	if d.ServiceID, err = asString(obj["serviceId"], "serviceId"); err != nil {
		return Domain{}, err
	}
	if d.Host, err = asString(obj["host"], "host"); err != nil {
		return Domain{}, err
	}
	if d.Scheme, err = asString(obj["scheme"], "scheme"); err != nil {
		return Domain{}, err
	}
	if d.Path, err = asString(obj["path"], "path"); err != nil {
		return Domain{}, err
	}
	if d.AuthGateMode, err = asString(obj["authGateMode"], "authGateMode"); err != nil {
		return Domain{}, err
	}
	if d.AuthGateUsername, err = asString(obj["authGateUsername"], "authGateUsername"); err != nil {
		return Domain{}, err
	}
	if d.AuthGatePasswordHash, err = asString(obj["authGatePasswordHash"], "authGatePasswordHash"); err != nil {
		return Domain{}, err
	}
	if d.ServiceName, err = asString(obj["serviceName"], "serviceName"); err != nil {
		return Domain{}, err
	}
	if obj["port"] != nil {
		if d.Port, err = asInt(obj["port"], "port"); err != nil {
			return Domain{}, err
		}
	}
	if obj["onDemandTls"] != nil {
		if d.OnDemandTLS, err = asBool(obj["onDemandTls"], "onDemandTls"); err != nil {
			return Domain{}, err
		}
	}
	if obj["stripPrefix"] != nil {
		sp, err := asBool(obj["stripPrefix"], "stripPrefix")
		if err != nil {
			return Domain{}, err
		}
		d.StripPrefix = &sp
	}
	if requireShape {
		if d.ServiceID != "" {
			if err := requireUUID("serviceId", d.ServiceID); err != nil {
				return Domain{}, fmt.Errorf("domains[%d]: %w", i, err)
			}
		}
		if err := d.Validate(); err != nil {
			return Domain{}, fmt.Errorf("domains[%d]: %w", i, err)
		}
		if d.ServiceID != "" && d.Port == 0 {
			d.Port = 3000
		}
		if d.Host != "" && d.Scheme == "" {
			d.Scheme = "http"
		}
	} else {
		if d.Domain == "" || !validHostname(d.Domain) {
			return Domain{}, fmt.Errorf("domains[%d].domain is invalid", i)
		}
	}
	return d, nil
}

// SSLCheck inspects certs for a list of hostnames.
type SSLCheck struct {
	Domains []string
}

func (SSLCheck) OpType() string { return "ssl_check" }

func decodeSSLCheck(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("domains"), "ssl_check"); err != nil {
		return nil, err
	}
	if _, ok := raw["domains"]; !ok {
		return nil, fmt.Errorf("ssl_check requires domains")
	}
	objs, err := asObjectSlice(raw["domains"], "domains", maxArray)
	if err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(objs))
	for i, obj := range objs {
		if err := rejectUnknown(obj, map[string]struct{}{"domain": {}}, fmt.Sprintf("domains[%d]", i)); err != nil {
			return nil, err
		}
		d, err := asString(obj["domain"], "domain")
		if err != nil {
			return nil, err
		}
		if !validHostname(d) {
			return nil, fmt.Errorf("domains[%d].domain is invalid", i)
		}
		domains = append(domains, d)
	}
	return SSLCheck{Domains: domains}, nil
}

// SelfUpdate downloads a new agent binary.
type SelfUpdate struct {
	TargetVersion string
	DownloadURL   string
}

func (SelfUpdate) OpType() string { return "self_update" }

func decodeSelfUpdate(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("targetVersion", "downloadUrl", "allowDowngrade"), "self_update"); err != nil {
		return nil, err
	}
	ver, err := asString(raw["targetVersion"], "targetVersion")
	if err != nil {
		return nil, err
	}
	if !semverishRe.MatchString(ver) {
		return nil, fmt.Errorf("targetVersion is invalid")
	}
	u, err := asString(raw["downloadUrl"], "downloadUrl")
	if err != nil {
		return nil, err
	}
	if u != "" && !validHTTPSURL(u) {
		return nil, fmt.Errorf("downloadUrl is invalid")
	}
	if _, err := asBool(raw["allowDowngrade"], "allowDowngrade"); err != nil {
		return nil, err
	}
	return SelfUpdate{TargetVersion: ver, DownloadURL: u}, nil
}

// DatabaseRef is used by db_start/stop/destroy.
type DatabaseRef struct {
	Type       string
	DatabaseID string
}

func (p DatabaseRef) OpType() string { return p.Type }

func decodeDatabaseRef(opType string, raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("databaseId"), opType); err != nil {
		return nil, err
	}
	id, err := asString(raw["databaseId"], "databaseId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", id); err != nil {
		return nil, err
	}
	return DatabaseRef{Type: opType, DatabaseID: id}, nil
}

// DBProvision brings up a managed database.
type DBProvision struct {
	DatabaseID    string
	DBType        string
	Port          int
	ContainerName string
	DockerImage   string
	AccessMode    string
	TailscaleIP   string
	Credentials   map[string]string
}

func (DBProvision) OpType() string { return "db_provision" }

func decodeDBProvision(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(
		"databaseId", "dbType", "port", "containerName", "dockerImage",
		"accessMode", "tailscaleIp", "credentials",
	), "db_provision"); err != nil {
		return nil, err
	}
	p := DBProvision{}
	var err error
	if p.DatabaseID, err = asString(raw["databaseId"], "databaseId"); err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", p.DatabaseID); err != nil {
		return nil, err
	}
	if p.DBType, err = asString(raw["dbType"], "dbType"); err != nil {
		return nil, err
	}
	if !validDBType(p.DBType) {
		return nil, fmt.Errorf("dbType is invalid")
	}
	if p.Port, err = asInt(raw["port"], "port"); err != nil {
		return nil, err
	}
	if !validPort(p.Port) {
		return nil, fmt.Errorf("port is invalid")
	}
	if p.ContainerName, err = asString(raw["containerName"], "containerName"); err != nil {
		return nil, err
	}
	if err := requireDockerName("containerName", p.ContainerName); err != nil {
		return nil, err
	}
	if p.DockerImage, err = asString(raw["dockerImage"], "dockerImage"); err != nil {
		return nil, err
	}
	if !validImageRef(p.DockerImage) {
		return nil, fmt.Errorf("dockerImage is not a valid image reference")
	}
	if p.AccessMode, err = asString(raw["accessMode"], "accessMode"); err != nil {
		return nil, err
	}
	if p.AccessMode == "" {
		p.AccessMode = "internal"
	}
	if !validAccessMode(p.AccessMode) {
		return nil, fmt.Errorf("accessMode is invalid")
	}
	if p.TailscaleIP, err = asString(raw["tailscaleIp"], "tailscaleIp"); err != nil {
		return nil, err
	}
	if p.TailscaleIP != "" && !validIP(p.TailscaleIP) {
		return nil, fmt.Errorf("tailscaleIp is invalid")
	}
	if p.Credentials, err = asStringMap(raw["credentials"], "credentials", credKeys()); err != nil {
		return nil, err
	}
	return p, nil
}

// DBExtension enables or disables a Postgres extension.
type DBExtension struct {
	Type          string
	DatabaseID    string
	ContainerName string
	ExtensionName string
	DBUser        string
	DBName        string
}

func (p DBExtension) OpType() string { return p.Type }

func decodeDBExtension(opType string, raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(
		"databaseId", "containerName", "extensionName", "dbUser", "dbName",
	), opType); err != nil {
		return nil, err
	}
	p := DBExtension{Type: opType}
	var err error
	if p.DatabaseID, err = asString(raw["databaseId"], "databaseId"); err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", p.DatabaseID); err != nil {
		return nil, err
	}
	if p.ContainerName, err = asString(raw["containerName"], "containerName"); err != nil {
		return nil, err
	}
	if err := requireDockerName("containerName", p.ContainerName); err != nil {
		return nil, err
	}
	if p.ExtensionName, err = asString(raw["extensionName"], "extensionName"); err != nil {
		return nil, err
	}
	if !extensionNameRe.MatchString(p.ExtensionName) {
		return nil, fmt.Errorf("extensionName is invalid")
	}
	if p.DBUser, err = asString(raw["dbUser"], "dbUser"); err != nil {
		return nil, err
	}
	if !identRe.MatchString(p.DBUser) {
		return nil, fmt.Errorf("dbUser is invalid")
	}
	if p.DBName, err = asString(raw["dbName"], "dbName"); err != nil {
		return nil, err
	}
	if !identRe.MatchString(p.DBName) {
		return nil, fmt.Errorf("dbName is invalid")
	}
	return p, nil
}

// DBSetAccess reconciles a database's network binding.
type DBSetAccess struct {
	DatabaseID    string
	DBType        string
	ContainerName string
	DockerImage   string
	Port          int
	AccessMode    string
	TailscaleIP   string
	Credentials   map[string]string
}

func (DBSetAccess) OpType() string { return "db_set_access" }

func decodeDBSetAccess(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(
		"databaseId", "dbType", "containerName", "dockerImage", "port",
		"accessMode", "tailscaleIp", "credentials",
	), "db_set_access"); err != nil {
		return nil, err
	}
	p := DBSetAccess{}
	var err error
	if p.DatabaseID, err = asString(raw["databaseId"], "databaseId"); err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", p.DatabaseID); err != nil {
		return nil, err
	}
	if p.DBType, err = asString(raw["dbType"], "dbType"); err != nil {
		return nil, err
	}
	if !validDBType(p.DBType) {
		return nil, fmt.Errorf("dbType is invalid")
	}
	if p.ContainerName, err = asString(raw["containerName"], "containerName"); err != nil {
		return nil, err
	}
	if err := requireDockerName("containerName", p.ContainerName); err != nil {
		return nil, err
	}
	if p.DockerImage, err = asString(raw["dockerImage"], "dockerImage"); err != nil {
		return nil, err
	}
	if p.DockerImage != "" && !validImageRef(p.DockerImage) {
		return nil, fmt.Errorf("dockerImage is not a valid image reference")
	}
	if p.Port, err = asInt(raw["port"], "port"); err != nil {
		return nil, err
	}
	if !validPort(p.Port) {
		return nil, fmt.Errorf("port is invalid")
	}
	if p.AccessMode, err = asString(raw["accessMode"], "accessMode"); err != nil {
		return nil, err
	}
	if !validAccessMode(p.AccessMode) {
		return nil, fmt.Errorf("accessMode is invalid")
	}
	if p.TailscaleIP, err = asString(raw["tailscaleIp"], "tailscaleIp"); err != nil {
		return nil, err
	}
	if p.AccessMode == "tailnet" && !validIP(p.TailscaleIP) {
		return nil, fmt.Errorf("tailnet mode requires a valid tailscaleIp")
	}
	if p.TailscaleIP != "" && !validIP(p.TailscaleIP) {
		return nil, fmt.Errorf("tailscaleIp is invalid")
	}
	if p.Credentials, err = asStringMap(raw["credentials"], "credentials", credKeys()); err != nil {
		return nil, err
	}
	return p, nil
}

// DBRotatePassword rotates engine credentials then rewrites compose.
type DBRotatePassword struct {
	DatabaseID     string
	DBType         string
	ContainerName  string
	DockerImage    string
	Port           int
	AccessMode     string
	TailscaleIP    string
	OldCredentials map[string]string
	NewCredentials map[string]string
}

func (DBRotatePassword) OpType() string { return "db_rotate_password" }

func decodeDBRotatePassword(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema(
		"databaseId", "dbType", "containerName", "dockerImage", "port",
		"accessMode", "tailscaleIp", "oldCredentials", "newCredentials",
	), "db_rotate_password"); err != nil {
		return nil, err
	}
	p := DBRotatePassword{}
	var err error
	if p.DatabaseID, err = asString(raw["databaseId"], "databaseId"); err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", p.DatabaseID); err != nil {
		return nil, err
	}
	if p.DBType, err = asString(raw["dbType"], "dbType"); err != nil {
		return nil, err
	}
	if !validDBType(p.DBType) {
		return nil, fmt.Errorf("dbType is invalid")
	}
	if p.ContainerName, err = asString(raw["containerName"], "containerName"); err != nil {
		return nil, err
	}
	if err := requireDockerName("containerName", p.ContainerName); err != nil {
		return nil, err
	}
	if p.DockerImage, err = asString(raw["dockerImage"], "dockerImage"); err != nil {
		return nil, err
	}
	if !validImageRef(p.DockerImage) {
		return nil, fmt.Errorf("dockerImage is not a valid image reference")
	}
	if raw["port"] != nil {
		if p.Port, err = asInt(raw["port"], "port"); err != nil {
			return nil, err
		}
		if p.Port != 0 && !validPort(p.Port) {
			return nil, fmt.Errorf("port is invalid")
		}
	}
	if p.AccessMode, err = asString(raw["accessMode"], "accessMode"); err != nil {
		return nil, err
	}
	if p.AccessMode != "" && !validAccessMode(p.AccessMode) {
		return nil, fmt.Errorf("accessMode is invalid")
	}
	if p.TailscaleIP, err = asString(raw["tailscaleIp"], "tailscaleIp"); err != nil {
		return nil, err
	}
	if p.TailscaleIP != "" && !validIP(p.TailscaleIP) {
		return nil, fmt.Errorf("tailscaleIp is invalid")
	}
	if p.OldCredentials, err = asStringMap(raw["oldCredentials"], "oldCredentials", credKeys()); err != nil {
		return nil, err
	}
	if p.NewCredentials, err = asStringMap(raw["newCredentials"], "newCredentials", credKeys()); err != nil {
		return nil, err
	}
	if len(p.OldCredentials) == 0 || len(p.NewCredentials) == 0 {
		return nil, fmt.Errorf("oldCredentials and newCredentials are required")
	}
	return p, nil
}

// DBMigrate copies a Dokploy database into a Stacked target.
type DBMigrate struct {
	MigrationTargetID string
	DBType            string
}

func (DBMigrate) OpType() string { return "db_migrate" }

func decodeDBMigrate(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("migrationTargetId", "dbType"), "db_migrate"); err != nil {
		return nil, err
	}
	id, err := asString(raw["migrationTargetId"], "migrationTargetId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("migrationTargetId", id); err != nil {
		return nil, err
	}
	dbType, err := asString(raw["dbType"], "dbType")
	if err != nil {
		return nil, err
	}
	if !validDBType(dbType) {
		return nil, fmt.Errorf("dbType is invalid")
	}
	return DBMigrate{MigrationTargetID: id, DBType: dbType}, nil
}

// VolumeMigrate copies a host path into the managed volume namespace.
type VolumeMigrate struct {
	MigrationTargetID   string
	SourceVolumePath    string
	TargetVolumePath    string
	SourceContainerName string
}

func (VolumeMigrate) OpType() string { return "volume_migrate" }

func decodeVolumeMigrate(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("migrationTargetId", "sourceVolumePath", "targetVolumePath", "sourceContainerName"), "volume_migrate"); err != nil {
		return nil, err
	}
	id, err := asString(raw["migrationTargetId"], "migrationTargetId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("migrationTargetId", id); err != nil {
		return nil, err
	}
	src, err := asString(raw["sourceVolumePath"], "sourceVolumePath")
	if err != nil {
		return nil, err
	}
	tgt, err := asString(raw["targetVolumePath"], "targetVolumePath")
	if err != nil {
		return nil, err
	}
	if src != "" && !validAbsPath(src) {
		return nil, fmt.Errorf("sourceVolumePath is invalid")
	}
	if tgt != "" && !validAbsPath(tgt) {
		return nil, fmt.Errorf("targetVolumePath is invalid")
	}
	container, err := asString(raw["sourceContainerName"], "sourceContainerName")
	if err != nil {
		return nil, err
	}
	if container != "" {
		if err := requireDockerName("sourceContainerName", container); err != nil {
			return nil, err
		}
	}
	return VolumeMigrate{
		MigrationTargetID:   id,
		SourceVolumePath:    src,
		TargetVolumePath:    tgt,
		SourceContainerName: container,
	}, nil
}

func validateIsolationFields(raw map[string]interface{}) error {
	for _, key := range []string{"isolationRelaxed", "allowPrivilegeEscalation", "privileged", "readOnlyRoot", "networkIsolation"} {
		if _, err := asBool(raw[key], key); err != nil {
			return err
		}
	}
	if n, err := asInt(raw["pidsLimit"], "pidsLimit"); err != nil {
		return err
	} else if n < 0 || n > 1_000_000 {
		return fmt.Errorf("pidsLimit is out of range")
	}
	caps, err := asStringSlice(raw["capAdd"], "capAdd", 32)
	if err != nil {
		return err
	}
	for i, c := range caps {
		if !validLinuxCapability(c) {
			return fmt.Errorf("capAdd[%d] is invalid", i)
		}
	}
	drops, err := asStringSlice(raw["capDrop"], "capDrop", 32)
	if err != nil {
		return err
	}
	for i, c := range drops {
		if !validLinuxCapability(c) {
			return fmt.Errorf("capDrop[%d] is invalid", i)
		}
	}
	tmpfs, err := asStringSlice(raw["tmpfs"], "tmpfs", 16)
	if err != nil {
		return err
	}
	for i, p := range tmpfs {
		if !validAbsPath(p) {
			return fmt.Errorf("tmpfs[%d] is invalid", i)
		}
	}
	for _, key := range []string{"linkedServiceIds", "linkedDatabaseIds"} {
		ids, err := asStringSlice(raw[key], key, 64)
		if err != nil {
			return err
		}
		for i, id := range ids {
			if err := requireUUID(fmt.Sprintf("%s[%d]", key, i), id); err != nil {
				return err
			}
		}
	}
	return nil
}

// DBBackup dumps a database to object storage.
type DBBackup struct {
	DatabaseID string
	BackupID   string
}

func (DBBackup) OpType() string { return "db_backup" }

func decodeDBBackup(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("databaseId", "backupId"), "db_backup"); err != nil {
		return nil, err
	}
	dbID, err := asString(raw["databaseId"], "databaseId")
	if err != nil {
		return nil, err
	}
	backupID, err := asString(raw["backupId"], "backupId")
	if err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", dbID); err != nil {
		return nil, err
	}
	if err := requireUUID("backupId", backupID); err != nil {
		return nil, err
	}
	return DBBackup{DatabaseID: dbID, BackupID: backupID}, nil
}

// DBRestore restores a dump, taking a safety backup first.
type DBRestore struct {
	DatabaseID      string
	RestoreBackupID string
	SafetyBackupID  string
}

func (DBRestore) OpType() string { return "db_restore" }

func decodeDBRestore(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("databaseId", "restoreBackupId", "safetyBackupId"), "db_restore"); err != nil {
		return nil, err
	}
	p := DBRestore{}
	var err error
	if p.DatabaseID, err = asString(raw["databaseId"], "databaseId"); err != nil {
		return nil, err
	}
	if p.RestoreBackupID, err = asString(raw["restoreBackupId"], "restoreBackupId"); err != nil {
		return nil, err
	}
	if p.SafetyBackupID, err = asString(raw["safetyBackupId"], "safetyBackupId"); err != nil {
		return nil, err
	}
	if err := requireUUID("databaseId", p.DatabaseID); err != nil {
		return nil, err
	}
	if err := requireUUID("restoreBackupId", p.RestoreBackupID); err != nil {
		return nil, err
	}
	if err := optionalUUID("safetyBackupId", p.SafetyBackupID); err != nil {
		return nil, err
	}
	return p, nil
}

// TailscaleSetup starts the interactive auth-URL flow.
type TailscaleSetup struct {
	Hostname string
}

func (TailscaleSetup) OpType() string { return "tailscale_setup" }

func decodeTailscaleSetup(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("hostname"), "tailscale_setup"); err != nil {
		return nil, err
	}
	h, err := asString(raw["hostname"], "hostname")
	if err != nil {
		return nil, err
	}
	if !validHostname(h) || strings.Contains(h, ".") || len(h) > 63 {
		return nil, fmt.Errorf("hostname is invalid")
	}
	return TailscaleSetup{Hostname: h}, nil
}

// DokployProbe inspects named containers.
type DokployProbe struct {
	ContainerNames []string
}

func (DokployProbe) OpType() string { return "dokploy_takeover_probe" }

func decodeDokployProbe(raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("containerNames"), "dokploy_takeover_probe"); err != nil {
		return nil, err
	}
	names, err := asStringSlice(raw["containerNames"], "containerNames", maxArray)
	if err != nil {
		return nil, err
	}
	for i, name := range names {
		if !validDockerName(strings.TrimSpace(name)) {
			return nil, fmt.Errorf("containerNames[%d] is invalid", i)
		}
		names[i] = strings.TrimSpace(name)
	}
	return DokployProbe{ContainerNames: names}, nil
}

// DokployNetwork attaches or detaches Caddy from an overlay.
type DokployNetwork struct {
	Type    string
	Network string
}

func (p DokployNetwork) OpType() string { return p.Type }

func decodeDokployNetwork(opType string, raw map[string]interface{}) (Payload, error) {
	if err := rejectUnknown(raw, withSchema("network"), opType); err != nil {
		return nil, err
	}
	n, err := asString(raw["network"], "network")
	if err != nil {
		return nil, err
	}
	n = strings.TrimSpace(n)
	if n != "" && !validDockerName(n) {
		return nil, fmt.Errorf("network is invalid")
	}
	return DokployNetwork{Type: opType, Network: n}, nil
}

// ValidImageRef reports whether s is safe to interpolate into compose / docker args.
func ValidImageRef(s string) bool { return validImageRef(s) }

// ValidComposeServiceName reports whether s is safe as a compose service/container name.
func ValidComposeServiceName(s string) bool {
	return validUUID(s) || validDockerName(s)
}

// ValidRestartPolicy reports whether s is a docker restart policy.
func ValidRestartPolicy(s string) bool { return validRestartPolicy(s) }

// ValidNetworkAlias reports whether s is a DNS label suitable for compose aliases.
func ValidNetworkAlias(s string) bool { return validNetworkAlias(s) }
