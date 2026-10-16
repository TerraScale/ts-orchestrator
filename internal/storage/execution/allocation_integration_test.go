package execution

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// The allocation fixture uses signed OCI SDK requests, HTTP compare-and-swap,
// and persisted objects. It never fabricates a winning reservation envelope.
func statefulSequenceLocation(t *testing.T) release.SequenceLocation {
	t.Helper()
	directory := t.TempDir()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/n/fixture/b/gru-1-head/o/") || r.Header.Get("Authorization") == "" {
			http.Error(w, "invalid signed allocation request", http.StatusForbidden)
			return
		}
		name := filepath.Join(directory, fmt.Sprintf("%x", sha256.Sum256([]byte(r.URL.Path))))
		mu.Lock()
		defer mu.Unlock()
		current, err := os.ReadFile(name)
		found := err == nil
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(current))
		switch r.Method {
		case http.MethodGet:
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(current)
		case http.MethodPut:
			if r.Header.Get("If-None-Match") == "*" && found || r.Header.Get("If-Match") != "" && (!found || r.Header.Get("If-Match") != etag) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if r.Header.Get("If-Match") == "" && r.Header.Get("If-None-Match") == "" {
				http.Error(w, "missing compare-and-swap", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			if err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			if err := os.WriteFile(name, body, 0o600); err != nil {
				http.Error(w, "persist allocation", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil))
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	client.HTTPClient = statefulAllocationHTTPClient{server: server}
	policy := common.NoRetryPolicy()
	client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &policy})
	return release.SequenceLocation{Client: client, Namespace: "fixture", Bucket: "gru-1-head"}
}

type statefulAllocationHTTPClient struct{ server *httptest.Server }

func (client statefulAllocationHTTPClient) Do(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	address := *request.URL
	cloned.URL = &address
	cloned.URL.Scheme = "http"
	cloned.URL.Host = strings.TrimPrefix(client.server.URL, "http://")
	return client.server.Client().Do(cloned)
}
