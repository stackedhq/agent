package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	CPUUsage     float64           `json:"cpuUsage,omitempty"`
	MemoryUsage  float64           `json:"memoryUsage,omitempty"`
	DiskUsage    float64           `json:"diskUsage,omitempty"`
	CPUCores     int               `json:"cpuCores,omitempty"`
	MemoryMb     int               `json:"memoryMb,omitempty"`
	DiskGb       int               `json:"diskGb,omitempty"`
	OS           string            `json:"os,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	Containers   []ContainerStatus `json:"containers,omitempty"`
}

type ContainerStatus struct {
	ServiceID string  `json:"serviceId"`
	Status    string  `json:"status"`
	Uptime    float64 `json:"uptime,omitempty"`
}

type StatusUpdate struct {
	Status string                 `json:"status"`
	Result map[string]interface{} `json:"result,omitempty"`
}

type LogBatch struct {
	Lines    []string `json:"lines"`
	Progress *int     `json:"progress,omitempty"`
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
	_, err := c.doJSON("POST", "/api/agent/operations/"+operationID+"/logs", &LogBatch{Lines: lines, Progress: progress})
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
