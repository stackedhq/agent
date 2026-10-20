package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/logs"
)

// RunJob handles the `cron_run` op type — a scheduled job. Runs the user's
// command in a one-shot container (`docker run --rm`) built from the
// service's *already-deployed* local image, before any traffic concerns.
//
// Unlike `release_command`, a cron run never rebuilds or re-pulls: it runs
// the image left on the host by the last successful deploy
// (`stacked-<serviceID>` for git services, or the pinned `dockerImage`).
// This keeps runs cheap and guarantees a job runs the same code that's
// currently serving, not freshly-fetched source. If no image exists yet
// (the service was never deployed) the run fails with a clear message.
//
// Env vars are fetched on-demand via the same credentials endpoint the
// deploy/release paths use, so the op payload holds no secrets.
//
// On success the result carries `{exitCode: 0}` so the server records the
// run's exit code. A non-zero exit returns an error (the exit status is in
// the message); the server marks the run failed.
func (e *Executor) RunJob(op client.Operation) (map[string]interface{}, error) {
	mode := getStringPayload(op.Payload, "mode")
	if mode == "http" {
		return e.runHTTPJob(op)
	}
	return e.runCommandJob(op)
}

// runHTTPJob makes an HTTP request from the agent host. The agent itself
// isn't attached to the `stacked` network, so the client dials through
// stackedNetworkDialer: container names and network aliases (e.g.
// http://<serviceID>:3000/api/cron) resolve to the container's bridge IP,
// and anything else falls back to normal DNS.
func (e *Executor) runHTTPJob(op client.Operation) (map[string]interface{}, error) {
	jobURL := getStringPayload(op.Payload, "httpUrl")
	if jobURL == "" {
		return nil, fmt.Errorf("cron_run http mode requires httpUrl")
	}
	method := getStringPayload(op.Payload, "httpMethod")
	if method == "" {
		method = "GET"
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) (map[string]interface{}, error) {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return nil, err
	}

	streamer.SetProgress(0)
	streamer.AddLine(fmt.Sprintf("HTTP job: %s %s", method, jobURL))
	streamer.Flush()

	var bodyReader io.Reader
	if body := getStringPayload(op.Payload, "httpBody"); body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(currentOpContext(), method, jobURL, bodyReader)
	if err != nil {
		return fail(fmt.Errorf("build request: %w", err))
	}

	// Parse JSON headers from payload if present.
	if hdrs := getStringPayload(op.Payload, "httpHeaders"); hdrs != "" {
		parsed := parseJSONHeaders(hdrs)
		for k, v := range parsed {
			req.Header.Set(k, v)
		}
	}

	httpClient := newJobHTTPClient(func(host string, ips []string) {
		streamer.AddLine(fmt.Sprintf("Resolved %s on the stacked network: %s", host, strings.Join(ips, ", ")))
	})
	streamer.SetProgress(50)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fail(fmt.Errorf("request failed: %w", err))
	}
	defer resp.Body.Close()

	// Read a snippet of the body for logs (cap at 4KB).
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	snippet := string(bodyBytes)

	streamer.AddLine(fmt.Sprintf("Response: %d %s", resp.StatusCode, resp.Status))
	if snippet != "" {
		streamer.AddLine(snippet)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		streamer.SetProgress(100)
		streamer.AddLine("HTTP job completed successfully.")
		streamer.Flush()
		return map[string]interface{}{"exitCode": 0}, nil
	}

	streamer.Flush()
	return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(snippet))
}

func (e *Executor) runCommandJob(op client.Operation) (map[string]interface{}, error) {
	serviceID := getStringPayload(op.Payload, "serviceId")
	if serviceID == "" {
		return nil, fmt.Errorf("cron_run requires serviceId in payload")
	}

	command := getStringPayload(op.Payload, "command")
	if strings.TrimSpace(command) == "" {
		return nil, fmt.Errorf("cron_run requires a command")
	}

	streamer := logs.NewStreamer(e.Client, op.ID)
	fail := func(err error) (map[string]interface{}, error) {
		streamer.AddLine("ERROR: " + err.Error())
		streamer.Flush()
		return nil, err
	}

	streamer.SetProgress(0)
	streamer.AddLine("Scheduled job: resolving image...")
	streamer.Flush()

	// Resolve the image without rebuilding. Pinned dockerImage wins; else
	// the git-build image name the deploy path produced.
	dockerImage := getStringPayload(op.Payload, "dockerImage")
	imageName := dockerImage
	if dockerImage != "" {
		if err := validateImageReference(dockerImage); err != nil {
			return fail(err)
		}
	}
	if imageName == "" {
		imageName = "stacked-" + serviceID
	}

	// Verify the image exists locally — a never-deployed service has none,
	// and `docker run` would otherwise try (and fail) to pull a non-image.
	if out, err := runCommandSilent("", "docker", "image", "inspect", imageName); err != nil {
		_ = out
		return fail(fmt.Errorf(
			"image %s not found on host; deploy the service before running jobs",
			imageName,
		))
	}

	dir := serviceDir(serviceID)
	if err := ensureDir(dir); err != nil {
		return fail(fmt.Errorf("create service dir: %w", err))
	}

	creds, err := e.Client.GetCredentials(serviceID)
	if err != nil {
		var credErr *client.CredentialsError
		if errors.As(err, &credErr) {
			return fail(fmt.Errorf("%s", credErr.Message))
		}
		return fail(fmt.Errorf("get credentials: %w", err))
	}

	// Same env plumbing as the release and rolling paths: single-line
	// values in stacked.env (0600), multi-line values through the docker
	// CLI's process env with `-e KEY`, never argv.
	env, envWarnings := serviceEnv(creds.EnvVars)
	addEnvWarnings(streamer, envWarnings)
	runEnv, envPath, err := writeServiceEnvFile(dir, env)
	if err != nil {
		return fail(err)
	}

	// Make sure the stacked network exists — the job may need to reach the
	// user's database container, which sits on it.
	_, _ = runCommandSilent("", "docker", "network", "create", "stacked")

	streamer.SetProgress(50)
	streamer.AddLine("Running job: " + command)
	streamer.Flush()

	runID := getStringPayload(op.Payload, "runId")
	containerName := serviceID + "-cron"
	if isUUID(runID) {
		// Short suffix keeps concurrent manual + scheduled runs from
		// colliding on the container name.
		suffix := runID
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}
		containerName = serviceID + "-cron-" + suffix
	}

	timeout := CronJobTimeout(op.Payload)
	args := []string{
		"run", "--rm",
		"--network=stacked",
	}
	args = append(args, runEnv.Args(envPath)...)
	args = append(args, "--name", containerName)
	args = append(args, jobLabelArgs("cron")...)
	args = append(args, jobResourceArgs(op.Payload, defaultCronMemoryMB)...)
	args = append(args, imageName, "sh", "-lc", command)
	if err := runJobContainer(streamer, dir, runEnv.CommandEnv(), containerName, timeout, args); err != nil {
		return fail(fmt.Errorf("job command failed: %w", err))
	}

	streamer.SetProgress(100)
	streamer.AddLine("Job completed successfully.")
	streamer.Flush()
	return map[string]interface{}{"exitCode": 0}, nil
}

// newJobHTTPClient builds the client HTTP-mode jobs use: the default
// transport settings with a dialer that understands `stacked` network
// names. Proxy env vars still apply to public URLs, but never to network
// names: an outbound proxy can't resolve those either.
func newJobHTTPClient(onResolve func(host string, ips []string)) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		host := req.URL.Hostname()
		if net.ParseIP(host) == nil {
			if ips, err := resolveDockerHost(host, "stacked"); err == nil && len(ips) > 0 {
				return nil, nil
			}
		}
		return http.ProxyFromEnvironment(req)
	}
	transport.DialContext = stackedNetworkDialer("stacked", onResolve)
	return &http.Client{Timeout: 5 * time.Minute, Transport: transport}
}

// parseJSONHeaders parses a JSON object string into a flat string map.
// Returns empty map on any parse error — headers are best-effort.
func parseJSONHeaders(raw string) map[string]string {
	out := map[string]string{}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return out
	}
	for k, v := range parsed {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
