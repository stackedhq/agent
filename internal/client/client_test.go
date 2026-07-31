package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetFileMountsUsesAuthenticatedOperationEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/agent/operations/op-123/file-mounts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"11111111-1111-4111-8111-111111111111","containerPath":"/config","content":"value"}]}`))
	}))
	defer server.Close()

	mounts, err := New(server.URL, "test-token").GetFileMounts("op-123")
	if err != nil {
		t.Fatalf("GetFileMounts: %v", err)
	}
	if len(mounts) != 1 || mounts[0].Content != "value" || mounts[0].ContainerPath != "/config" {
		t.Fatalf("unexpected mounts: %+v", mounts)
	}
}
