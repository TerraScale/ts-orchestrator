package capacityinventory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestAccountingReadsRestartedJournalAndPositiveSDKTerminalResources(t *testing.T) {
	config := natscell.Config{Cell: "lab", Instance: "accounting", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}}
	runtime, err := natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	journal, err := oci.OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	compartment := "ocid1.compartment.oc1..owned"
	retired, missing := "ocid1.volume.oc1.sa-saopaulo-1.retired", "ocid1.volume.oc1.sa-saopaulo-1.missing"
	unknownKey := ""
	for _, id := range []string{retired, missing, ""} {
		key := entityid.New()
		intent := oci.OperationIntent{Action: "volume-create", Key: key, CreateKey: key, Region: oci.RegionGRU, Generation: 1,
			Owner: "orchestrator", CreatedAt: time.Now().UTC().Add(-time.Hour), AvailabilityDomain: "AD-1", SizeGB: 50}
		if err := journal.RecordIntent(t.Context(), intent); err != nil {
			t.Fatal(err)
		}
		if id == "" {
			unknownKey = key
		}
		if err := journal.RecordResult(t.Context(), oci.OperationResult{Intent: intent, ResourceID: id, ETag: "v1", Unknown: id == ""}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	journal, err = oci.OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Method != http.MethodGet && r.URL.Path != "/20180409/resources" {
			t.Errorf("accounting attempted unsigned or mutating SDK request: %s %s", r.Method, r.URL)
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/20160918/instances", "/20160918/volumes", "/20160918/bootVolumes":
			fmt.Fprint(w, `[]`)
		case "/20180409/resources":
			fmt.Fprint(w, `{"items":[]}`)
		case "/20160918/volumes/" + retired:
			fmt.Fprintf(w, `{"id":%q,"compartmentId":%q,"lifecycleState":"TERMINATED"}`, retired, compartment)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"NotAuthorizedOrNotFound","message":"absent"}`)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := New(factory)
	if err != nil {
		t.Fatal(err)
	}
	reader.endpoint = server.URL
	scope := Scope{TenancyID: "ocid1.tenancy.oc1..test", SHA256: strings.Repeat("a", 64), Currency: "USD", ExpiresAt: time.Now().Add(-time.Minute),
		Regions: []RegionScope{{Cell: "GRU", OCIRegion: "sa-saopaulo-1", CompartmentIDs: []string{compartment}}}}
	snapshot, err := reader.ReadOwnedJournal(t.Context(), scope, journal)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 1 || snapshot.Resources[0].ID != retired || snapshot.Resources[0].LifecycleState != "TERMINATED" {
		t.Fatalf("positive terminal SDK evidence lost after broker restart: %+v", snapshot)
	}
	if !slices.ContainsFunc(snapshot.Pending, func(reason string) bool {
		return strings.Contains(reason, unknownKey) && strings.Contains(reason, "unresolved")
	}) ||
		!slices.ContainsFunc(snapshot.Pending, func(reason string) bool { return strings.Contains(reason, missing) }) {
		t.Fatalf("unknown operations or absent resources became free capacity: %+v", snapshot)
	}
	if snapshot.ValidateOwned(scope, time.Now()) == nil || snapshot.Validate(scope, time.Now()) == nil {
		t.Fatal("partial lifecycle facts became complete accounting or renewed expired authority")
	}
}
