package rootfoundation

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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestOriginalRequestHistoryPersistsBeforeConditionalRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "own-cell")
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned protected object SDK operation")
			w.WriteHeader(401)
			return
		}
		previous, readErr := os.ReadFile(path)
		etag := fmt.Sprintf("%x", sha256.Sum256(previous))
		if r.Method == http.MethodGet {
			if readErr != nil {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(previous)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("If-None-Match") == "*" && readErr == nil || r.Header.Get("If-Match") != "" && (readErr != nil || r.Header.Get("If-Match") != etag) {
			w.WriteHeader(412)
			return
		}
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%x", sha256.Sum256(wire)))
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	store, err := region.NewObjectFoundationStore(&client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	desired, err := ociresource.NewDesired(ociresource.Key{Region: "GRU", Kind: "nsg-rules", Name: "members"}, 1, ociresource.PolicyEnforce, struct {
		ID string `json:"id"`
	}{ID: "original"})
	if err != nil {
		t.Fatal(err)
	}
	desired, err = ociresource.OperationRecord(desired, 1, now, false)
	if err != nil {
		t.Fatal(err)
	}
	attempt := ociresource.RequestAttempt{Method: "PUT", URL: "https://iaas.example/owned", Body: []byte(`{"owned":true}`), RetryToken: "original", IfMatch: "etag", StartedAt: now, Deadline: now.Add(time.Minute)}
	desired.Operation.Requests = []ociresource.RequestAttempt{attempt}
	source := ociresource.ResourceSource{ControllerConfigSHA256: strings.Repeat("a", 64), GrantSHA256: strings.Repeat("b", 64)}
	record := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1, IntentDigest: strings.Repeat("c", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, OCIResources: &ociresource.ProtectedJournal{Revision: 1, Source: source, Resources: map[string]ociresource.ProtectedResource{desired.Key.String(): {Revision: 1, Source: source, Desired: desired}}}}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	loaded, etag, err := store.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	entry := loaded.OCIResources.Resources[desired.Key.String()]
	previous := *entry.Desired.Operation
	for _, field := range []string{"remove", "body", "token", "deadline", "target"} {
		t.Run(field, func(t *testing.T) {
			next := previous
			next.Requests = slices.Clone(previous.Requests)
			switch field {
			case "remove":
				next.Requests = nil
			case "body":
				next.Requests[0].Body = []byte(`{"owned":false}`)
			case "token":
				next.Requests[0].RetryToken = "new"
			case "deadline":
				next.Requests[0].Deadline = now.Add(time.Hour)
			case "target":
				next.Requests[0].URL += "/other"
			}
			if err := originalRequests(previous, next); err == nil {
				t.Fatal("persisted original history rewrite accepted before conditional commit")
			}
			_, currentETag, err := store.Load(t.Context(), "GRU")
			if err != nil || currentETag != etag {
				t.Fatalf("rejected revision changed protected disk record: %v", err)
			}
		})
	}
	next := previous
	next.Requests = slices.Clone(previous.Requests)
	next.Requests[0].Sent, next.Requests[0].Status, next.Requests[0].FinishedAt = true, 200, now.Add(time.Second)
	if err := originalRequests(previous, next); err != nil {
		t.Fatal(err)
	}
	entry.Desired.Operation = &next
	loaded.OCIResources.Resources[desired.Key.String()] = entry
	if _, err := store.CompareAndSwap(t.Context(), loaded, etag); err != nil {
		t.Fatal(err)
	}
	reopened, err := region.NewObjectFoundationStore(&client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	confirmed, _, err := reopened.Load(t.Context(), "GRU")
	if err != nil || confirmed.OCIResources.Resources[desired.Key.String()].Desired.Operation.Requests[0].Status != 200 {
		t.Fatalf("original outcome did not survive SDK/disk restart: %v", err)
	}
	// This disk/SDK scenario does not establish the sealed root Store or IPC authorizer.
}
