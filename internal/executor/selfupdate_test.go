package executor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
	"github.com/stackedapp/stacked/agent/internal/releaseverify"
)

func testKeyPEM(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), priv
}

func signedRelease(t *testing.T, priv ed25519.PrivateKey, body []byte) (sums, sig []byte) {
	t.Helper()
	name := releaseverify.OfficialBinaryName(runtime.GOARCH)
	sum := sha256.Sum256(body)
	sums = []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return sums, ed25519.Sign(priv, sums)
}

func startReleaseServer(t *testing.T, version string, files map[string][]byte) *httptest.Server {
	t.Helper()
	prefix := "/stackedhq/agent/releases/download/v" + version + "/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme == "http" && strings.HasPrefix(r.URL.Path, "/https-downgrade/") {
			http.Redirect(w, r, "http://example.com/evil", http.StatusFound)
			return
		}
		name, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	prevScheme, prevHost, prevPrefix := releaseScheme, releaseHost, releasePrefix
	releaseScheme = "http"
	releaseHost = u.Host
	releasePrefix = "/stackedhq/agent/releases/download"
	t.Cleanup(func() {
		releaseScheme, releaseHost, releasePrefix = prevScheme, prevHost, prevPrefix
	})
	return srv
}

func updateOp(version string, extra map[string]interface{}) client.Operation {
	p := map[string]interface{}{"targetVersion": version}
	for k, v := range extra {
		p[k] = v
	}
	return client.Operation{ID: "op-1", Type: "self_update", Payload: p}
}

func TestInstallUpdateSuccessLeavesNoTmp(t *testing.T) {
	pub, priv := testKeyPEM(t)
	restore := releaseverify.UsePublicKeyPEM(pub)
	defer restore()

	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	if err := os.WriteFile(agentBinaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	body := []byte("new-agent-binary")
	sums, sig := signedRelease(t, priv, body)
	startReleaseServer(t, "0.9.0", map[string][]byte{
		releaseverify.OfficialBinaryName(runtime.GOARCH): body,
		releaseverify.ChecksumsName:                      sums,
		releaseverify.SignatureName:                      sig,
	})

	e := &Executor{}
	if err := e.installUpdate(updateOp("0.9.0", nil), "0.8.0"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(agentBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("binary not replaced: %q", got)
	}
	if _, err := os.Stat(agentBinaryPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file should be gone")
	}
}

func TestInstallUpdateVerificationFailureLeavesExisting(t *testing.T) {
	pub, priv := testKeyPEM(t)
	restore := releaseverify.UsePublicKeyPEM(pub)
	defer restore()

	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	if err := os.WriteFile(agentBinaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	body := []byte("tampered-bytes")
	// Sign checksums for a different payload so the hash check fails.
	sums, sig := signedRelease(t, priv, []byte("honest-bytes"))
	startReleaseServer(t, "0.9.0", map[string][]byte{
		releaseverify.OfficialBinaryName(runtime.GOARCH): body,
		releaseverify.ChecksumsName:                      sums,
		releaseverify.SignatureName:                      sig,
	})

	e := &Executor{}
	err := e.installUpdate(updateOp("0.9.0", nil), "0.8.0")
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("want hash failure, got %v", err)
	}
	got, err := os.ReadFile(agentBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("existing binary was replaced: %q", got)
	}
}

func TestInstallUpdateBadSignatureLeavesExisting(t *testing.T) {
	pub, priv := testKeyPEM(t)
	restore := releaseverify.UsePublicKeyPEM(pub)
	defer restore()

	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	if err := os.WriteFile(agentBinaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	body := []byte("new-agent-binary")
	sums, sig := signedRelease(t, priv, body)
	sig[0] ^= 0x01
	startReleaseServer(t, "0.9.0", map[string][]byte{
		releaseverify.OfficialBinaryName(runtime.GOARCH): body,
		releaseverify.ChecksumsName:                      sums,
		releaseverify.SignatureName:                      sig,
	})

	e := &Executor{}
	err := e.installUpdate(updateOp("0.9.0", nil), "0.8.0")
	if err == nil || !strings.Contains(err.Error(), "not signed by the Stacked release key") {
		t.Fatalf("want signature failure, got %v", err)
	}
	got, _ := os.ReadFile(agentBinaryPath)
	if string(got) != "old-binary" {
		t.Fatalf("existing binary was replaced: %q", got)
	}
}

func TestInstallUpdateRejectsDowngrade(t *testing.T) {
	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	if err := os.WriteFile(agentBinaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	e := &Executor{}
	err := e.installUpdate(updateOp("0.7.0", nil), "0.8.0")
	if err == nil || !strings.Contains(err.Error(), "refusing downgrade") {
		t.Fatalf("want downgrade error, got %v", err)
	}
	got, _ := os.ReadFile(agentBinaryPath)
	if string(got) != "old-binary" {
		t.Fatal("binary changed on downgrade reject")
	}
}

func TestInstallUpdateAllowDowngrade(t *testing.T) {
	pub, priv := testKeyPEM(t)
	restore := releaseverify.UsePublicKeyPEM(pub)
	defer restore()

	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	if err := os.WriteFile(agentBinaryPath, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	body := []byte("older-but-signed")
	sums, sig := signedRelease(t, priv, body)
	startReleaseServer(t, "0.7.0", map[string][]byte{
		releaseverify.OfficialBinaryName(runtime.GOARCH): body,
		releaseverify.ChecksumsName:                      sums,
		releaseverify.SignatureName:                      sig,
	})

	e := &Executor{}
	if err := e.installUpdate(updateOp("0.7.0", map[string]interface{}{"allowDowngrade": true}), "0.8.0"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(agentBinaryPath)
	if string(got) != string(body) {
		t.Fatalf("got %q", got)
	}
}

func TestInstallUpdateRejectsArbitraryDownloadURL(t *testing.T) {
	e := &Executor{}
	err := e.installUpdate(updateOp("0.9.0", map[string]interface{}{
		"downloadUrl": "https://evil.example/agent",
	}), "0.8.0")
	if err == nil || !strings.Contains(err.Error(), "downloadUrl rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestInstallUpdateRejectsHTTPDownloadURL(t *testing.T) {
	e := &Executor{}
	name := releaseverify.OfficialBinaryName(runtime.GOARCH)
	err := e.installUpdate(updateOp("0.9.0", map[string]interface{}{
		"downloadUrl": "http://github.com/stackedhq/agent/releases/download/v0.9.0/" + name,
	}), "0.8.0")
	if err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("got %v", err)
	}
}

func TestDownloadReleaseFileSizeLimit(t *testing.T) {
	prev := releaseverify.MaxAssetBytes
	// Can't assign to const — test via a server that sends Content-Length over the limit.
	// The production limit is 64MiB; we assert the Content-Length short-circuit using
	// a crafted URL check + the existing constant by sending a small over-limit header
	// only if we could override. Instead, verify LimitReader path with a large body
	// is not necessary: unit-test the error string via Content-Length.
	_ = prev

	dir := t.TempDir()
	agentBinaryPath = filepath.Join(dir, "agent")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", releaseverify.MaxAssetBytes+1))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	releaseScheme, releaseHost, releasePrefix = "http", u.Host, "/"
	t.Cleanup(func() {
		releaseScheme, releaseHost, releasePrefix = "https", "github.com", "/stackedhq/agent/releases/download"
	})

	err := downloadReleaseFile(filepath.Join(dir, "out"), srv.URL+"/stackedhq/agent/releases/download/v1.0.0/x")
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

func TestValidateReleaseURL(t *testing.T) {
	arch := runtime.GOARCH
	name := releaseverify.OfficialBinaryName(arch)
	ok := "https://github.com/stackedhq/agent/releases/download/v1.2.3/" + name
	if err := validateReleaseURL(ok, "1.2.3", arch); err != nil {
		t.Fatal(err)
	}
	if err := validateReleaseURL("https://github.com/stackedhq/agent/releases/download/v1.2.3/"+name+"?x=1", "1.2.3", arch); err == nil {
		t.Fatal("query should fail")
	}
}

func TestCheckRedirectRejectsHTTPSDowngrade(t *testing.T) {
	c := releaseHTTPClient()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)
	err := c.CheckRedirect(req, []*http.Request{req})
	if err == nil || !strings.Contains(err.Error(), "HTTPS downgrade") {
		t.Fatalf("got %v", err)
	}
}
