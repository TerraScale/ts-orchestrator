package rootsecret

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"golang.org/x/sys/unix"
)

// This exercises real signed SDK HTTP attempts and native atomic file delivery;
// the shared root IPC scenarios separately qualify process/session admission.
func TestCredentialSDKToMemoryDelivery(t *testing.T) {
	const value = "root-delivery-private-sentinel"
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.owned"
	digest := sha256.Sum256([]byte(value))
	reference := bootstrap.SecretReference{SecretOCID: id, VersionNumber: 7, SHA256: hex.EncodeToString(digest[:]), MaxBytes: 1024, TargetFile: "controller-a.creds"}
	var mode atomic.Int32
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/secretbundles/"+id) || request.URL.Query().Get("versionNumber") != "7" || !strings.HasPrefix(request.Header.Get("Authorization"), "Signature ") {
			t.Error("SDK request did not bind the exact signed secret version")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if mode.Load() == 1 {
			writer.WriteHeader(http.StatusTooManyRequests)
			_, _ = writer.Write([]byte(`{"code":"TooManyRequests","message":"retry"}`))
			return
		}
		version, contents, expires := int64(7), value, time.Now().Add(time.Hour)
		switch mode.Load() {
		case 2:
			version++
		case 3:
			contents = "wrong"
		case 4:
			expires = time.Now().Add(-time.Second)
		}
		if err := json.MarshalWrite(writer, map[string]any{"secretId": id, "versionNumber": version,
			"timeOfExpiry":        expires.UTC().Format(time.RFC3339Nano),
			"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(contents))}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 2, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&client.BaseClient, server.URL)
	client.HTTPClient = server.Client()
	ociclient.ConfigureRequestCancellation(&client.BaseClient)
	var guardCalls atomic.Int32
	client.HTTPClient = credentialDispatcher{next: client.HTTPClient, guard: func() error {
		if guardCalls.Add(1) > 1 && mode.Load() == 1 {
			return ErrDelivery
		}
		return nil
	}}
	body, expires, err := readExact(t.Context(), &client, reference)
	if err != nil || string(body) != value || !time.Now().Before(expires) {
		t.Fatal("SDK failed to return exact credential bytes with their expiry", err)
	}
	defer clear(body)
	directory, err := os.MkdirTemp("/dev/shm", "ts-root-delivery-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := vaultsecret.RequireMemoryFilesystem(directory); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, reference.TargetFile)); err != nil {
		t.Fatal(err)
	}
	if err := install(fd, reference.TargetFile, body, uint32(os.Geteuid()), uint32(os.Getegid()), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(filepath.Join(directory, reference.TargetFile))
	if err != nil || string(installed) != value {
		t.Fatal("memory credential was not installed")
	}
	clear(installed)
	untouched, err := os.ReadFile(outside)
	if err != nil || string(untouched) != "unchanged" {
		t.Fatal("atomic delivery followed the previous symlink")
	}
	info, err := os.Lstat(filepath.Join(directory, reference.TargetFile))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("installed credential is not an owner-only regular file")
	}
	for _, scenario := range []int32{2, 3, 4} {
		mode.Store(scenario)
		if _, _, err := readExact(t.Context(), &client, reference); !errors.Is(err, ErrDelivery) || strings.Contains(err.Error(), value) {
			t.Fatalf("provider version/hash/expiry scenario %d was accepted or exposed a value", scenario)
		}
	}
	mode.Store(1)
	guardCalls.Store(0)
	before := requests.Load()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, _, err := readExact(ctx, &client, reference); !errors.Is(err, ErrDelivery) || requests.Load()-before != 1 || guardCalls.Load() != 2 {
		t.Fatal("revoked credential admission reached an SDK retry", err)
	}
}
