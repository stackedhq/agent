package executor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackedapp/stacked/agent/internal/client"
)

type fakeRelease struct {
	version string
	sums    []byte
	sig     []byte
	binary  []byte
}

// serveRelease starts an httptest server laid out like GitHub releases
// (/v<version>/<file>) and points the self-update package vars at it.
func serveRelease(t *testing.T, rel fakeRelease, trusted ...ed25519.PublicKey) {
	t.Helper()
	mux := http.NewServeMux()
	prefix := "/v" + rel.version + "/"
	mux.HandleFunc(prefix+sumsFile, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(rel.sums) })
	mux.HandleFunc(prefix+sumsSigFile, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(rel.sig) })
	mux.HandleFunc(prefix+"stacked-agent-linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("release download carried an Authorization header")
		}
		_, _ = w.Write(rel.binary)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	oldBase, oldKeys := releaseBaseURL, releaseKeys
	releaseBaseURL = srv.URL
	releaseKeys = trusted
	t.Cleanup(func() { releaseBaseURL, releaseKeys = oldBase, oldKeys })
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sumsFor(binary []byte, name string) []byte {
	return []byte(fmt.Sprintf("%x  stacked-agent-linux-arm64\n%x  %s\n", sha256.Sum256([]byte("other")), sha256.Sum256(binary), name))
}

func newDest(t *testing.T) string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(dest, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	return dest
}

func assertUnchanged(t *testing.T, dest string) {
	t.Helper()
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-binary" {
		t.Fatalf("binary was replaced despite failed verification")
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestInstallVerifiedReleaseAcceptsValidSignature(t *testing.T) {
	pub, priv := genKey(t)
	bin := []byte("new-binary-contents")
	sums := sumsFor(bin, "stacked-agent-linux-amd64")
	serveRelease(t, fakeRelease{version: "1.2.3", sums: sums, sig: ed25519.Sign(priv, sums), binary: bin}, pub)

	dest := newDest(t)
	if err := installVerifiedRelease("1.2.3", "amd64", dest); err != nil {
		t.Fatalf("installVerifiedRelease: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, bin) {
		t.Fatalf("dest = %q, want new binary", got)
	}
	st, _ := os.Stat(dest)
	if st.Mode().Perm() != 0755 {
		t.Fatalf("mode = %v, want 0755", st.Mode().Perm())
	}
}

func TestInstallVerifiedReleaseAcceptsSecondTrustedKey(t *testing.T) {
	other, _ := genKey(t)
	pub, priv := genKey(t)
	bin := []byte("new-binary-contents")
	sums := sumsFor(bin, "stacked-agent-linux-amd64")
	serveRelease(t, fakeRelease{version: "1.2.3", sums: sums, sig: ed25519.Sign(priv, sums), binary: bin}, other, pub)

	if err := installVerifiedRelease("1.2.3", "amd64", newDest(t)); err != nil {
		t.Fatalf("installVerifiedRelease: %v", err)
	}
}

func TestInstallVerifiedReleaseRejects(t *testing.T) {
	bin := []byte("new-binary-contents")
	goodSums := sumsFor(bin, "stacked-agent-linux-amd64")

	tests := []struct {
		name    string
		build   func(t *testing.T) (fakeRelease, ed25519.PublicKey)
		wantErr string
	}{
		{
			name: "bad signature",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				sig := ed25519.Sign(priv, goodSums)
				sig[0] ^= 0xff
				return fakeRelease{sums: goodSums, sig: sig, binary: bin}, pub
			},
			wantErr: "signature check failed",
		},
		{
			name: "tampered sums",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				sig := ed25519.Sign(priv, goodSums)
				evil := []byte("evil")
				return fakeRelease{sums: sumsFor(evil, "stacked-agent-linux-amd64"), sig: sig, binary: evil}, pub
			},
			wantErr: "signature check failed",
		},
		{
			name: "wrong key",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, _ := genKey(t)
				_, attacker := genKey(t)
				return fakeRelease{sums: goodSums, sig: ed25519.Sign(attacker, goodSums), binary: bin}, pub
			},
			wantErr: "signature check failed",
		},
		{
			name: "truncated signature",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				return fakeRelease{sums: goodSums, sig: ed25519.Sign(priv, goodSums)[:63], binary: bin}, pub
			},
			wantErr: "signature check failed",
		},
		{
			name: "hash mismatch",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				return fakeRelease{sums: goodSums, sig: ed25519.Sign(priv, goodSums), binary: []byte("swapped-binary")}, pub
			},
			wantErr: "checksum mismatch",
		},
		{
			name: "missing entry",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				sums := sumsFor(bin, "stacked-agent-linux-riscv64")
				return fakeRelease{sums: sums, sig: ed25519.Sign(priv, sums), binary: bin}, pub
			},
			wantErr: "no entry for stacked-agent-linux-amd64",
		},
		{
			name: "duplicate entry",
			build: func(t *testing.T) (fakeRelease, ed25519.PublicKey) {
				pub, priv := genKey(t)
				sums := append(sumsFor(bin, "stacked-agent-linux-amd64"), []byte(fmt.Sprintf("%x  stacked-agent-linux-amd64\n", sha256.Sum256([]byte("evil"))))...)
				return fakeRelease{sums: sums, sig: ed25519.Sign(priv, sums), binary: bin}, pub
			},
			wantErr: "more than once",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, pub := tt.build(t)
			rel.version = "1.2.3"
			serveRelease(t, rel, pub)
			dest := newDest(t)
			err := installVerifiedRelease("1.2.3", "amd64", dest)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			assertUnchanged(t, dest)
		})
	}
}

func TestInstallVerifiedReleaseRejectsMissingRelease(t *testing.T) {
	pub, _ := genKey(t)
	serveRelease(t, fakeRelease{version: "9.9.9"}, pub)
	dest := newDest(t)
	err := installVerifiedRelease("1.2.3", "amd64", dest)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("err = %v, want HTTP 404", err)
	}
	assertUnchanged(t, dest)
}

func TestInstallVerifiedReleaseRejectsPathInVersion(t *testing.T) {
	if err := installVerifiedRelease("1.2.3/../../evil", "amd64", newDest(t)); err == nil {
		t.Fatal("expected invalid version error")
	}
}

func TestCheckUpgrade(t *testing.T) {
	tests := []struct {
		target, current string
		ok              bool
	}{
		{"0.9.0", "0.8.3", true},
		{"0.10.0", "0.9.9", true},
		{"1.0.0", "1.0.0-rc.1", true},
		{"1.0.0-rc.2", "1.0.0-rc.1", true},
		{"1.0.0-rc.10", "1.0.0-rc.9", true},
		{"0.9.0", "dev", true},
		{"0.8.3", "0.8.3", false},  // same version
		{"0.8.2", "0.8.3", false},  // downgrade
		{"0.9.9", "0.10.0", false}, // numeric, not lexical
		{"1.0.0-rc.1", "1.0.0", false},
		{"latest", "0.8.3", false},
		{"0.9.0", "garbage", false},
		{"0.9.0+build", "0.8.0", false},
	}
	for _, tt := range tests {
		err := checkUpgrade(tt.target, tt.current)
		if (err == nil) != tt.ok {
			t.Errorf("checkUpgrade(%q, %q) = %v, want ok=%v", tt.target, tt.current, err, tt.ok)
		}
	}
}

func TestSelfUpdateRefusesDowngradeBeforeDownloading(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	oldBase, oldVer := releaseBaseURL, currentAgentVersion
	releaseBaseURL = srv.URL
	currentAgentVersion = func() string { return "0.9.0" }
	defer func() { releaseBaseURL, currentAgentVersion = oldBase, oldVer }()

	e := &Executor{}
	err := e.SelfUpdate(client.Operation{ID: "op-1", Type: "self_update", Payload: map[string]interface{}{
		"targetVersion": "0.8.0",
		"downloadUrl":   srv.URL + "/evil",
	}})
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("err = %v, want downgrade refusal", err)
	}
	if hits != 0 {
		t.Fatalf("made %d HTTP requests before refusing", hits)
	}
}

func TestReleaseHTTPClientRefusesPlainHTTPRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/x", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := newReleaseHTTPClient().Get(redirector.URL)
	if err == nil || !strings.Contains(err.Error(), "non-https redirect") {
		t.Fatalf("err = %v, want non-https redirect refusal", err)
	}
}

func TestEmbeddedReleaseKeysParse(t *testing.T) {
	if len(trustedReleaseKeys) == 0 {
		t.Fatal("no trusted release keys")
	}
	for i, k := range trustedReleaseKeys {
		if len(k) != ed25519.PublicKeySize {
			t.Fatalf("key %d has length %d", i, len(k))
		}
	}
}
