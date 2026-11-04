package tsauth

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testProjectID = "01K78000000000000000000001"
	sentinel      = "SENTINEL-do-not-print"
)

// testSecrets are distinct valid secrets: three 32-byte keys, an API key and
// the project ID.
func testSecrets() map[string]string {
	secrets := map[string]string{EnvAPIKey: "tb_0123456789abcdefghijABCDEFGHIJ0123456789", EnvProjectID: testProjectID}
	for index, key := range Generated {
		secrets[key] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
	}
	return secrets
}

func probeServer(t *testing.T, health, ready int, healthBody, readyBody string) int {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case HealthPath:
			w.WriteHeader(health)
			_, _ = w.Write([]byte(healthBody))
		case ReadyPath:
			w.WriteHeader(ready)
			_, _ = w.Write([]byte(readyBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().(*net.TCPAddr).Port
}

func TestProbe(t *testing.T) {
	if err := Probe(t.Context(), probeServer(t, 200, 200, `{"status":"ok"}`, `{"status":"ready"}`)); err != nil {
		t.Fatal(err)
	}
	err := Probe(t.Context(), probeServer(t, 200, 503, `{"status":"ok"}`, `{"status":"not_ready"}`))
	if err == nil || !strings.Contains(err.Error(), ReadyPath) {
		t.Fatalf("not ready: %v", err)
	}

}

func writeRelease(t *testing.T, name string, content, summed []byte) (string, string) {
	dir := t.TempDir()
	binary := filepath.Join(dir, name)
	sum := sha256.Sum256(summed)
	if err := os.WriteFile(binary, content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return binary, binary + ".sha256"
}

func TestVerifyRelease(t *testing.T) {
	content, err := os.ReadFile("../terrabase/testdata/terrabase-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", content, content))
	if err != nil || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %q: %v", digest, err)
	}
	if _, err := VerifyRelease(writeRelease(t, "terrabase-linux-arm64", content, content)); err == nil {
		t.Fatal("accepted a TerraBase asset")
	}
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", content, []byte("\x7fELF other"))); err == nil {
		t.Fatal("accepted a checksum mismatch")
	}
	x86 := bytes.Clone(content)
	binary.LittleEndian.PutUint16(x86[18:20], uint16(elf.EM_X86_64))
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-arm64", x86, x86)); err == nil {
		t.Fatal("accepted x86-64 as an arm64 asset")
	}
	if _, err := VerifyRelease(writeRelease(t, "ts-auth-linux-amd64", x86, x86)); err != nil {
		t.Fatalf("amd64 asset: %v", err)
	}
}
