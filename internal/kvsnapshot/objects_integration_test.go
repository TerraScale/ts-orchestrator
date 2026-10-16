package kvsnapshot

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	testNamespace    = "terrascale"
	testObjectBucket = "gru-1-head"
)

type storageFault struct {
	status int
	code   string
}

// objectStorageServer exercises the real SDK's HTTP, checksum and CAS boundaries.
// Object bodies live on disk, independently of the NATS stores rebuilt by tests.
type objectStorageServer struct {
	client     objectstorage.ObjectStorageClient
	dir        string
	mu         sync.Mutex
	etags      map[string]string
	generation int
	puts       int
	faults     map[string]*storageFault
	hook       func(http.ResponseWriter, *http.Request) bool
}

func newObjectStorage(t *testing.T) *objectStorageServer {
	t.Helper()
	storage := &objectStorageServer{dir: t.TempDir(), etags: map[string]string{}, faults: map[string]*storageFault{}}
	endpoint := httptest.NewServer(http.HandlerFunc(storage.serveHTTP))
	t.Cleanup(endpoint.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test-fingerprint", private, nil))
	if err != nil {
		t.Fatal(err)
	}
	client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: new(common.NoRetryPolicy())})
	client.Host = endpoint.URL
	client.HTTPClient = endpoint.Client()
	storage.client = client
	return storage
}

func (storage *objectStorageServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if storage.hook != nil && storage.hook(w, r) {
		return
	}
	storage.mu.Lock()
	defer storage.mu.Unlock()
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("opc-request-id", "integration-request")
		w.WriteHeader(status)
		data, _ := json.Marshal(map[string]string{"code": code, "message": code})
		_, _ = w.Write(data)
	}
	name, ok := strings.CutPrefix(r.URL.Path, "/n/"+testNamespace+"/b/"+testObjectBucket+"/o/")
	if !ok || !strings.HasPrefix(name, "kv-snapshot/v1/"+testCell+"/") || strings.Contains(name, "..") || r.Header.Get("Authorization") == "" {
		fail(http.StatusBadRequest, "InvalidRequest")
		return
	}
	if fault := storage.faults[r.Method]; fault != nil {
		fail(fault.status, fault.code)
		return
	}
	path := filepath.Join(storage.dir, name)
	etag, exists := storage.etags[name]
	switch r.Method {
	case http.MethodGet:
		if !exists {
			fail(http.StatusNotFound, "ObjectNotFound")
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fail(http.StatusInternalServerError, "ReadFailed")
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	case http.MethodPut:
		data, err := io.ReadAll(r.Body)
		if err != nil {
			fail(http.StatusBadRequest, "ReadFailed")
			return
		}
		digest := sha256.Sum256(data)
		if r.Header.Get("opc-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) || r.ContentLength != int64(len(data)) || r.Header.Get("opc-checksum-algorithm") != "SHA256" {
			fail(http.StatusBadRequest, "InvalidChecksum")
			return
		}
		if r.Header.Get("If-Match") != "" && !exists {
			fail(http.StatusNotFound, "ObjectNotFound")
			return
		}
		if r.Header.Get("If-None-Match") == "*" && exists || r.Header.Get("If-Match") != "" && r.Header.Get("If-Match") != etag {
			fail(http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			fail(http.StatusInternalServerError, "WriteFailed")
			return
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			fail(http.StatusInternalServerError, "WriteFailed")
			return
		}
		storage.generation++
		storage.etags[name] = fmt.Sprintf("etag-%d", storage.generation)
		storage.puts++
		w.Header().Set("ETag", storage.etags[name])
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func (storage *objectStorageServer) fail(method string, fault *storageFault) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.faults[method] = fault
}

func (storage *objectStorageServer) putCount() int {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.puts
}

func (storage *objectStorageServer) set(t *testing.T, document Document) {
	t.Helper()
	data, err := encodeDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	storage.setRaw(t, document.Bucket, data)
}

func (storage *objectStorageServer) setRaw(t *testing.T, bucket string, data []byte) {
	t.Helper()
	storage.mu.Lock()
	defer storage.mu.Unlock()
	name := objectName(testCell, bucket)
	path := filepath.Join(storage.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	storage.generation++
	storage.etags[name] = fmt.Sprintf("etag-%d", storage.generation)
}

func (storage *objectStorageServer) remove(t *testing.T, bucket string) {
	t.Helper()
	storage.mu.Lock()
	defer storage.mu.Unlock()
	name := objectName(testCell, bucket)
	if err := os.Remove(filepath.Join(storage.dir, name)); err != nil {
		t.Fatal(err)
	}
	delete(storage.etags, name)
}

func (storage *objectStorageServer) document(t *testing.T, bucket string) Document {
	t.Helper()
	document, _, found, err := objectsFor(storage).Get(t.Context(), bucket)
	if err != nil || !found {
		t.Fatalf("read stored document: found=%v, error=%v", found, err)
	}
	return document
}

func TestDiscoverObjectsUsesTheRegionalVersionedKMSBucket(t *testing.T) {
	for _, test := range []struct {
		name        string
		namespace   string
		field       string
		value       string
		failurePath string
		wantError   bool
	}{
		{name: "regional bucket", namespace: testNamespace},
		{name: "invalid namespace", namespace: "Terra Scale", wantError: true},
		{name: "missing namespace", namespace: "", wantError: true},
		{name: "namespace unavailable", failurePath: "/n", wantError: true},
		{name: "bucket unavailable", namespace: testNamespace, failurePath: "/n/" + testNamespace + "/b/" + testObjectBucket, wantError: true},
		{name: "other bucket", namespace: testNamespace, field: "name", value: "fra-1-head", wantError: true},
		{name: "other namespace", namespace: testNamespace, field: "namespace", value: "other", wantError: true},
		{name: "versioning disabled", namespace: testNamespace, field: "versioning", value: "Disabled", wantError: true},
		{name: "versioning suspended", namespace: testNamespace, field: "versioning", value: "Suspended", wantError: true},
		{name: "missing default KMS", namespace: testNamespace, field: "kmsKeyId", wantError: true},
		{name: "invalid default KMS", namespace: testNamespace, field: "kmsKeyId", value: "ocid1.vault.wrong", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			storage := newObjectStorage(t)
			storage.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/n" && r.URL.Path != "/n/"+testNamespace+"/b/"+testObjectBucket {
					return false
				}
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == test.failurePath {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"not available"}`))
					return true
				}
				var body any
				if r.URL.Path == "/n" {
					if test.namespace != "" {
						body = test.namespace
					}
				} else {
					bucket := map[string]string{"name": testObjectBucket, "namespace": testNamespace, "versioning": "Enabled", "kmsKeyId": "ocid1.key.oc1.sa-saopaulo-1.head"}
					if test.field != "" {
						bucket[test.field] = test.value
					}
					body = bucket
				}
				data, err := json.Marshal(body)
				if err != nil {
					panic(err)
				}
				_, _ = w.Write(data)
				return true
			}
			objects, err := discoverObjects(t.Context(), storage.client, "sa-saopaulo-1", testCell)
			if test.wantError {
				if err == nil {
					t.Fatal("unsafe bucket discovery was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if objects.Namespace != testNamespace || objects.Bucket != testObjectBucket || objects.Cell != testCell {
				t.Fatalf("discovered objects = %+v", objects)
			}
			js := startJetStream(t)
			put(t, openBucket(t, js, testBucket), "a", []byte("discovered bucket"))
			snapshotter := snapshotterFor(js, storage, testBucket)
			snapshotter.Objects = objects
			if _, err := snapshotter.SnapshotOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			if document := storage.document(t, testBucket); string(document.Entries[0].Value) != "discovered bucket" {
				t.Fatalf("discovered bucket snapshot = %+v", document)
			}
		})
	}
}
