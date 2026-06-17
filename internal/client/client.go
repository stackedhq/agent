package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	server     string
	token      string
	httpClient *http.Client
}

func New(server, token string) *Client {
	return &Client{
		server: server,
		token:  token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// --- Request types ---

type HeartbeatRequest struct {
	AgentVersion string            `json:"agentVersion"`
	CPUUsage     float64           `json:"cpuUsage"`
	MemoryUsage  float64           `json:"memoryUsage"`
	DiskUsage    float64           `json:"diskUsage"`
	CPUCores     int               `json:"cpuCores,omitempty"`
	MemoryMb     int               `json:"memoryMb,omitempty"`
	DiskGb       int               `json:"diskGb,omitempty"`
	OS           string            `json:"os,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	Containers   []ContainerStatus `json:"containers,omitempty"`
	// Optional tailnet snapshot. Omitted entirely when Tailscale is
	// not installed on this VPS — the server then knows to leave the
	// machine's tailscale_* columns untouched. See heartbeat/tailscale.go.
	Tailscale *TailscaleStatus `json:"tailscale,omitempty"`

	// --- Resource investigation ("what's eating my box") ---
	//
	// All four sections below are strictly optional. The server treats
	// missing sections as "this agent doesn't report that yet" and
	// preserves whatever was last written for the machine — newer
	// fields can land in any release without breaking older sibling
	// agents that share a machine row. See agent.ts buildResourceSnapshot.
	OtherContainers      []OtherContainer `json:"otherContainers,omitempty"`
	TopProcessesByCPU    []ProcessStat    `json:"topProcessesByCpu,omitempty"`
	TopProcessesByMemory []ProcessStat    `json:"topProcessesByMemory,omitempty"`
	DiskBreakdown        *DiskBreakdown   `json:"diskBreakdown,omitempty"`
}

// OtherContainer describes a Docker container running on the box that
// is *not* managed by Stacked (no `com.stacked.kind=service` label).
// Surfaced so the user can answer "why is my box at 90% CPU" when the
// culprit is something they're running outside Stacked.
type OtherContainer struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Image         string  `json:"image"`
	State         string  `json:"state"`
	CPUPercent    float64 `json:"cpuPercent,omitempty"`
	MemoryPercent float64 `json:"memoryPercent,omitempty"`
	MemoryBytes   uint64  `json:"memoryBytes,omitempty"`
}

// ProcessStat is one row of `ps`-derived top-N data. PIDs are
// deliberately omitted — the UI surfaces process names so the user
// can investigate, without inviting a "kill this PID" button we
// don't want to ship as a destructive op.
type ProcessStat struct {
	Command       string  `json:"command"`
	CPUPercent    float64 `json:"cpuPercent"`
	MemoryPercent float64 `json:"memoryPercent"`
}

// DiskBreakdown carries two complementary sources of disk-usage
// attribution: Docker's `system df` totals, and `du`-based sizes for
// /opt/stacked/{services,volumes}. Both are independent and may be
// nil if collection failed (du can be slow on large volumes — the
// collector applies a hard timeout and drops the section rather than
// blocking the heartbeat).
type DiskBreakdown struct {
	Docker  *DockerDiskUsage  `json:"docker,omitempty"`
	Stacked *StackedDiskUsage `json:"stacked,omitempty"`
}

type DockerDiskUsage struct {
	ImagesBytes      uint64 `json:"imagesBytes"`
	ContainersBytes  uint64 `json:"containersBytes"`
	VolumesBytes     uint64 `json:"volumesBytes"`
	BuildCacheBytes  uint64 `json:"buildCacheBytes"`
	ReclaimableBytes uint64 `json:"reclaimableBytes"`
}

type StackedDiskUsage struct {
	ServicesBytes uint64 `json:"servicesBytes"`
	VolumesBytes  uint64 `json:"volumesBytes"`
}

// TailscaleStatus is the subset of `tailscale status --json` the agent
// reports on each heartbeat. Status values are mapped agent-side from
// Tailscale's BackendState enum into a small set the dashboard switch
// on directly — see internal/heartbeat/tailscale.go.
type TailscaleStatus struct {
	// One of: "connected", "expired" (reserved — currently agents
	// only emit "needs_login" for expired keys), "needs_login",
	// "stopped", "starting".
	Status       string `json:"status"`
	IPv4         string `json:"ipv4,omitempty"`
	IPv6         string `json:"ipv6,omitempty"`
	MagicDNSName string `json:"magicDnsName,omitempty"`
	NodeID       string `json:"nodeId,omitempty"`
	LoginName    string `json:"loginName,omitempty"`
	TailnetName  string `json:"tailnetName,omitempty"`
}

type ContainerStatus struct {
	ServiceID        string  `json:"serviceId"`
	Status           string  `json:"status"`
	Uptime           float64 `json:"uptime,omitempty"`
	CPUPercent       float64 `json:"cpuPercent,omitempty"`
	MemoryPercent    float64 `json:"memoryPercent,omitempty"`
	MemoryBytes      uint64  `json:"memoryBytes,omitempty"`
	MemoryLimitBytes uint64  `json:"memoryLimitBytes,omitempty"`
}

type StatusUpdate struct {
	Status string                 `json:"status"`
	Result map[string]interface{} `json:"result,omitempty"`
}

type LogBatch struct {
	Lines    []string `json:"lines"`
	Progress *int     `json:"progress,omitempty"`
}

type ServiceLogBatch struct {
	Lines []string `json:"lines"`
}

// --- Response types ---

type Operation struct {
	ID           string                 `json:"id"`
	MachineID    string                 `json:"machineId"`
	DeploymentID *string                `json:"deploymentId"`
	ServiceID    *string                `json:"serviceId"`
	Type         string                 `json:"type"`
	Payload      map[string]interface{} `json:"payload"`
	Status       string                 `json:"status"`
	CreatedAt    string                 `json:"createdAt"`
}

type OperationsResponse struct {
	Data []Operation `json:"data"`
}

type Credentials struct {
	GitCloneUrl   string            `json:"gitCloneUrl"`
	RegistryToken string            `json:"registryToken"`
	EnvVars       map[string]string `json:"envVars"`
	// Port is the user-configured upstream port that Caddy forwards to
	// (services.port, default 3000). The deploy health probe targets it.
	// Pointer so we can tell "absent" (older server — fall back to 3000)
	// from an explicit 0, which the server sends for worker services
	// (no exposed port) to signal "skip the TCP probe entirely".
	Port *int `json:"port,omitempty"`
	// NetworkAliases are human-readable internal DNS names (slugs of the
	// service's display name, current + retained-from-renames) the agent
	// attaches to the container as additional `--network-alias` values on
	// the `stacked` network. The permanent `<serviceID>` alias is always
	// emitted separately and is not included here. Empty/absent on older
	// servers — the service is still reachable by its UUID.
	NetworkAliases []string `json:"networkAliases,omitempty"`
}

// CredentialsErrorBody is the server-side error envelope returned
// alongside `Data` when the credentials endpoint cannot mint a usable
// token (e.g. GitHub App not installed for the repo's owner, or token
// mint failed). The agent surfaces `Message` verbatim to the user via
// the deploy log so they get an actionable next step instead of a
// generic `git clone` failure.
type CredentialsErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CredentialsResponse struct {
	Data  Credentials           `json:"data"`
	Error *CredentialsErrorBody `json:"error,omitempty"`
}

// CredentialsError is returned by GetCredentials when the server
// responded with a typed error envelope. Distinct from transport
// errors so callers can format it differently in the deploy log
// (we don't want "get credentials: <stack trace>" — we want the
// server's human message rendered as-is).
type CredentialsError struct {
	Code    string
	Message string
}

func (e *CredentialsError) Error() string {
	return e.Message
}

// --- API methods ---

func (c *Client) Heartbeat(req *HeartbeatRequest) error {
	_, err := c.doJSON("POST", "/api/agent/heartbeat", req)
	return err
}

func (c *Client) PollOperations() ([]Operation, error) {
	body, err := c.doJSON("GET", "/api/agent/operations", nil)
	if err != nil {
		return nil, err
	}

	var resp OperationsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode operations: %w", err)
	}
	return resp.Data, nil
}

func (c *Client) UpdateStatus(operationID string, update *StatusUpdate) error {
	_, err := c.doJSON("POST", "/api/agent/operations/"+operationID+"/status", update)
	return err
}

func (c *Client) SendLogs(operationID string, lines []string, progress *int) error {
	data, err := json.Marshal(&LogBatch{Lines: lines, Progress: progress})
	if err != nil {
		return fmt.Errorf("failed to marshal log batch: %w", err)
	}
	_, err = c.doRequest("POST", "/api/agent/operations/"+operationID+"/logs", bytes.NewReader(data))
	return err
}

// SendServiceLogs forwards a batch of runtime container log lines for a
// service. Used by the runtimelogs forwarder, distinct from SendLogs which
// targets per-operation deploy logs.
func (c *Client) SendServiceLogs(serviceID string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	data, err := json.Marshal(&ServiceLogBatch{Lines: lines})
	if err != nil {
		return fmt.Errorf("failed to marshal service log batch: %w", err)
	}
	_, err = c.doRequest("POST", "/api/agent/logs/"+serviceID, bytes.NewReader(data))
	return err
}

// SendDatabaseLogs is the database equivalent of SendServiceLogs. Used by
// the databaselogs forwarder to push `docker logs -f` output up to the
// dashboard's Console tab. Endpoint is distinct so the server's Redis
// ring buffer / SSE channel separation is preserved.
func (c *Client) SendDatabaseLogs(databaseID string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	data, err := json.Marshal(&ServiceLogBatch{Lines: lines})
	if err != nil {
		return fmt.Errorf("failed to marshal database log batch: %w", err)
	}
	_, err = c.doRequest("POST", "/api/agent/logs/db/"+databaseID, bytes.NewReader(data))
	return err
}

// --- Log archive request/response ---

type LogArchiveURL struct {
	URL       string `json:"url"`
	Key       string `json:"key"`
	ExpiresAt string `json:"expiresAt"`
}

type logArchiveURLResponse struct {
	Data LogArchiveURL `json:"data"`
}

type LogArchiveConfirm struct {
	Key       string `json:"key"`
	SizeBytes int    `json:"sizeBytes"`
	LineCount int    `json:"lineCount"`
	FromTs    string `json:"fromTs,omitempty"`
	ToTs      string `json:"toTs,omitempty"`
}

// ErrArchivalDisabled signals that the server has the log-archival
// feature flag turned off (R2_LOGS_BUCKET unset). The archiver uses this
// to permanently disable itself for the rest of the process lifetime
// rather than spamming requests every minute.
var ErrArchivalDisabled = fmt.Errorf("log archival disabled on server")

// RequestLogArchiveURL asks the server for a presigned PUT URL the agent
// can use to upload a gzipped NDJSON chunk directly to R2.
func (c *Client) RequestLogArchiveURL(serviceID string) (*LogArchiveURL, error) {
	body, err := c.doRequest("POST", "/api/agent/logs/"+serviceID+"/archive-url", nil)
	if err != nil {
		// Surface ARCHIVAL_DISABLED as a typed error. The body of a 503
		// response is folded into err.Error() by doRequest — a string
		// match is enough since this is an internal API contract.
		if strings.Contains(err.Error(), "ARCHIVAL_DISABLED") {
			return nil, ErrArchivalDisabled
		}
		return nil, err
	}
	var resp logArchiveURLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode archive URL: %w", err)
	}
	return &resp.Data, nil
}

// ConfirmLogArchive records a successful R2 upload in the server's
// manifest. Idempotent on the server side; safe to retry on transient
// network errors.
func (c *Client) ConfirmLogArchive(serviceID string, confirm *LogArchiveConfirm) error {
	data, err := json.Marshal(confirm)
	if err != nil {
		return fmt.Errorf("marshal archive confirm: %w", err)
	}
	_, err = c.doRequest("POST", "/api/agent/logs/"+serviceID+"/archive-confirm", bytes.NewReader(data))
	if err != nil && strings.Contains(err.Error(), "ARCHIVAL_DISABLED") {
		return ErrArchivalDisabled
	}
	return err
}

// --- Migration credentials ---

// MigrationDBCreds holds the source + target credentials and container
// names for a `db_migrate` op. Populated server-side from the
// dokploy_migration_targets row + the encrypted source creds blob.
type MigrationDBCreds struct {
	ContainerName string            `json:"containerName"`
	Creds         map[string]string `json:"creds"`
}

type MigrationCredentials struct {
	Kind       string            `json:"kind"` // "database" | "volume"
	Engine     string            `json:"engine,omitempty"`
	Source     *MigrationDBCreds `json:"source,omitempty"`
	Target     *MigrationDBCreds `json:"target,omitempty"`
	SourcePath string            `json:"sourcePath,omitempty"`
	TargetPath string            `json:"targetPath,omitempty"`
}

type migrationCredentialsResponse struct {
	Data MigrationCredentials `json:"data"`
}

// GetMigrationCredentials fetches decrypted source + target creds for a
// dokploy_migration_targets row. Mirrors `GetCredentials` for services.
func (c *Client) GetMigrationCredentials(targetID string) (*MigrationCredentials, error) {
	body, err := c.doJSON("GET", "/api/agent/migration-credentials/"+targetID, nil)
	if err != nil {
		return nil, err
	}
	var resp migrationCredentialsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode migration credentials: %w", err)
	}
	return &resp.Data, nil
}

// --- Database backups ---

// ErrBackupsDisabled signals that the server has the backup feature flag
// turned off (R2_BACKUPS_BUCKET unset). Surfaced as a typed error so the
// op fails with a clear message instead of a generic transport error.
var ErrBackupsDisabled = fmt.Errorf("backups disabled on server")

// BackupCredentials are the decrypted DB creds + container name the agent
// needs to dump/restore. Fetched on-demand so plaintext creds never sit in
// the operations.payload column (mirrors MigrationCredentials).
type BackupCredentials struct {
	Engine        string            `json:"engine"`
	ContainerName string            `json:"containerName"`
	Creds         map[string]string `json:"creds"`
}

type backupCredentialsResponse struct {
	Data BackupCredentials `json:"data"`
}

type BackupUploadURL struct {
	URL       string `json:"url"`
	Key       string `json:"key"`
	ExpiresAt string `json:"expiresAt"`
}

type backupUploadURLResponse struct {
	Data BackupUploadURL `json:"data"`
}

type BackupDownloadURL struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

type backupDownloadURLResponse struct {
	Data BackupDownloadURL `json:"data"`
}

type BackupConfirm struct {
	// int64 so dumps >2 GiB report correctly on 32-bit agent builds
	// (Go `int` is 32-bit there).
	SizeBytes int64  `json:"sizeBytes"`
	Sha256    string `json:"sha256,omitempty"`
}

// GetBackupCredentials fetches decrypted DB creds + container name for a
// db_backup / db_restore op.
func (c *Client) GetBackupCredentials(databaseID string) (*BackupCredentials, error) {
	body, err := c.doJSON("GET", "/api/agent/backup-credentials/"+databaseID, nil)
	if err != nil {
		return nil, err
	}
	var resp backupCredentialsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode backup credentials: %w", err)
	}
	return &resp.Data, nil
}

// RequestBackupUploadURL asks the server for a presigned PUT URL for a
// backup row's (server-owned) key. Marks the backup row running.
func (c *Client) RequestBackupUploadURL(backupID string) (*BackupUploadURL, error) {
	body, err := c.doRequest("POST", "/api/agent/backups/"+backupID+"/upload-url", nil)
	if err != nil {
		if strings.Contains(err.Error(), "BACKUPS_DISABLED") {
			return nil, ErrBackupsDisabled
		}
		return nil, err
	}
	var resp backupUploadURLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode backup upload URL: %w", err)
	}
	return &resp.Data, nil
}

// ConfirmBackup records a successful upload (size + sha) in the server
// manifest. Idempotent server-side.
func (c *Client) ConfirmBackup(backupID string, confirm *BackupConfirm) error {
	data, err := json.Marshal(confirm)
	if err != nil {
		return fmt.Errorf("marshal backup confirm: %w", err)
	}
	_, err = c.doRequest("POST", "/api/agent/backups/"+backupID+"/confirm", bytes.NewReader(data))
	if err != nil && strings.Contains(err.Error(), "BACKUPS_DISABLED") {
		return ErrBackupsDisabled
	}
	return err
}

// RequestBackupDownloadURL asks the server for a presigned GET URL to
// stream a stored backup back into the container during a restore.
func (c *Client) RequestBackupDownloadURL(backupID string) (*BackupDownloadURL, error) {
	body, err := c.doRequest("POST", "/api/agent/backups/"+backupID+"/download-url", nil)
	if err != nil {
		if strings.Contains(err.Error(), "BACKUPS_DISABLED") {
			return nil, ErrBackupsDisabled
		}
		return nil, err
	}
	var resp backupDownloadURLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode backup download URL: %w", err)
	}
	return &resp.Data, nil
}

func (c *Client) GetCredentials(serviceID string) (*Credentials, error) {
	body, err := c.doJSON("GET", "/api/agent/credentials/"+serviceID, nil)
	if err != nil {
		return nil, err
	}

	var resp CredentialsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}
	if resp.Error != nil {
		return nil, &CredentialsError{
			Code:    resp.Error.Code,
			Message: resp.Error.Message,
		}
	}
	return &resp.Data, nil
}

// --- HTTP helpers ---

func (c *Client) doJSON(method, path string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		body, err := c.doRequest(method, path, bodyReader)
		if err == nil {
			return body, nil
		}
		lastErr = err

		// Re-create reader for retry if we had a body
		if payload != nil {
			data, _ := json.Marshal(payload)
			bodyReader = bytes.NewReader(data)
		}
	}
	return nil, fmt.Errorf("after 3 attempts: %w", lastErr)
}

func (c *Client) doRequest(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, c.server+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
