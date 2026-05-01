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
	Port int `json:"port,omitempty"`
}

type CredentialsResponse struct {
	Data Credentials `json:"data"`
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

func (c *Client) GetCredentials(serviceID string) (*Credentials, error) {
	body, err := c.doJSON("GET", "/api/agent/credentials/"+serviceID, nil)
	if err != nil {
		return nil, err
	}

	var resp CredentialsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
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
