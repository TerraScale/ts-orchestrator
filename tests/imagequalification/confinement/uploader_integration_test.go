package confinement

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

func TestGuardedSDKUploaderRechecksEveryMultipartDispatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..candidate", "sa-saopaulo-1", "fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	var dispatched, checks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validSignature(r, &key.PublicKey, "ocid1.tenancy.oc1..test/") {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		if dispatched.Add(1) != 1 || r.Method != http.MethodPost {
			t.Error("dispatch escaped changed confinement")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"uploadId":"exact-multipart","namespace":"qualification","bucket":"disposable","object":"image.qcow2"}`))
	}))
	defer server.Close()
	ociclient.PinHost(&objects.BaseClient, server.URL)
	changed := errors.New("observed confinement changed")
	previous := objects.Interceptor
	objects.Interceptor = func(request *http.Request) error {
		if checks.Add(1) > 1 {
			return changed
		}
		return previous(request)
	}
	path := filepath.Join(t.TempDir(), "image.qcow2")
	data := []byte("exact disposable image bytes")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	err = imageimport.NewObjectUploader(objects).UploadObject(t.Context(), imageimport.UploadRequest{Namespace: "qualification", Bucket: "disposable", Object: "image.qcow2", Path: path, SHA256: fmt.Sprintf("%x", digest), PartSize: 8, Parallelism: 2})
	if err == nil || !errors.Is(err, changed) {
		t.Fatalf("later multipart dispatch did not retain confinement failure: %v", err)
	}
	if dispatched.Load() != 1 || checks.Load() < 3 {
		t.Fatalf("dispatched=%d checks=%d; parts/abort must each recheck", dispatched.Load(), checks.Load())
	}
}
