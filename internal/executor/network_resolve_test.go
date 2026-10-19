package executor

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const testServiceID = "0f04f8aa-7981-46a2-a789-8306f51b56ba"

func netInspectLine(id, name, endpoint string) string {
	return id + "\t" + name + "\t" + endpoint
}

func TestMatchNetworkHost(t *testing.T) {
	out := strings.Join([]string{
		// Recreate-mode service: container name is the service ID.
		netInspectLine("aaaaaaaaaaaa1111", "/"+testServiceID,
			`{"Aliases":["`+testServiceID+`"],"IPAddress":"172.18.0.5","GlobalIPv6Address":""}`),
		// Blue/green slots share the bare alias, plus a friendly alias.
		netInspectLine("bbbbbbbbbbbb2222", "/svc2-blue",
			`{"Aliases":["svc2-blue","svc2","my-api"],"IPAddress":"172.18.0.6"}`),
		netInspectLine("cccccccccccc3333", "/svc2-green",
			`{"Aliases":null,"DNSNames":["svc2-green","svc2","cccccccccccc"],"IPAddress":"172.18.0.7","GlobalIPv6Address":"fd00::7"}`),
		// Not on the network / garbage lines are skipped.
		netInspectLine("dddddddddddd4444", "/other", "null"),
		"not a valid line",
	}, "\n")

	cases := []struct {
		host string
		want []string
	}{
		{testServiceID, []string{"172.18.0.5"}},
		{strings.ToUpper(testServiceID), []string{"172.18.0.5"}},
		{testServiceID + ".", []string{"172.18.0.5"}},
		{"svc2", []string{"172.18.0.6", "172.18.0.7", "fd00::7"}},
		{"my-api", []string{"172.18.0.6"}},
		{"svc2-green", []string{"172.18.0.7", "fd00::7"}},
		{"aaaaaaaaaaaa", []string{"172.18.0.5"}},
		{"example.com", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got := matchNetworkHost(out, tc.host)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("matchNetworkHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestResolveOnDockerNetwork(t *testing.T) {
	origList, origInspect := listNetworkContainers, inspectContainers
	t.Cleanup(func() { listNetworkContainers, inspectContainers = origList, origInspect })

	var gotFormat string
	var gotIDs []string
	listNetworkContainers = func(network string) ([]string, error) {
		if network != "stacked" {
			t.Fatalf("network = %q", network)
		}
		return []string{"id1", "id2"}, nil
	}
	inspectContainers = func(format string, ids []string) (string, error) {
		gotFormat, gotIDs = format, ids
		return netInspectLine("id1aaaaaaaaaaaa", "/"+testServiceID, `{"IPAddress":"172.18.0.9"}`), nil
	}

	ips, err := resolveOnDockerNetwork(testServiceID, "stacked")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ips, []string{"172.18.0.9"}) {
		t.Fatalf("ips = %v", ips)
	}
	if !strings.Contains(gotFormat, `"stacked"`) || !reflect.DeepEqual(gotIDs, []string{"id1", "id2"}) {
		t.Fatalf("inspect called with format=%q ids=%v", gotFormat, gotIDs)
	}

	// No containers on the network: no inspect call, no match.
	listNetworkContainers = func(string) ([]string, error) { return nil, nil }
	inspectContainers = func(string, []string) (string, error) {
		t.Fatal("inspect should not run with no containers")
		return "", nil
	}
	if ips, err := resolveOnDockerNetwork(testServiceID, "stacked"); err != nil || len(ips) != 0 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

// stubDockerHost makes resolveDockerHost map `name` to 127.0.0.1 (where
// the httptest server listens) and everything else to "no match".
func stubDockerHost(t *testing.T, name string, err error) *int {
	t.Helper()
	orig := resolveDockerHost
	t.Cleanup(func() { resolveDockerHost = orig })
	calls := 0
	resolveDockerHost = func(host, network string) ([]string, error) {
		calls++
		if err != nil {
			return nil, err
		}
		if host == name && network == "stacked" {
			return []string{"127.0.0.1"}, nil
		}
		return nil, nil
	}
	return &calls
}

func TestJobHTTPClientResolvesNetworkNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok "+r.URL.Path)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	stubDockerHost(t, testServiceID, nil)
	// A proxy env var must not swallow internal names.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")

	var resolved []string
	client := newJobHTTPClient(func(host string, ips []string) {
		resolved = append(resolved, host+"="+strings.Join(ips, ","))
	})
	resp, err := client.Get("http://" + testServiceID + ":" + port + "/api/cron/purge-deleted-accounts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok /api/cron/purge-deleted-accounts" {
		t.Fatalf("body = %q", body)
	}
	if len(resolved) == 0 || resolved[0] != testServiceID+"=127.0.0.1" {
		t.Fatalf("onResolve = %v", resolved)
	}
}

func TestJobHTTPClientFallsBackForUnknownHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "public")
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"no match", nil},
		{"docker unavailable", errors.New("docker ps: cannot connect")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubDockerHost(t, "some-other-service", tc.err)
			client := newJobHTTPClient(nil)
			// "localhost" resolves via the system resolver and skips docker.
			resp, err := client.Get("http://localhost:" + port + "/")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			// The proxy hook asks docker once; the dialer short-circuits
			// localhost without asking.
			if *calls != 1 {
				t.Fatalf("docker lookups = %d, want 1", *calls)
			}
		})
	}
}

func TestStackedDialerReportsContainerOnFailure(t *testing.T) {
	// Grab a free port, then close it so the dial is refused.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()

	stubDockerHost(t, testServiceID, nil)
	dial := stackedNetworkDialer("stacked", nil)
	_, err = dial(t.Context(), "tcp", net.JoinHostPort(testServiceID, port))
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), `container on "stacked" network at 127.0.0.1`) {
		t.Fatalf("err = %v", err)
	}
}
