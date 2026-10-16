package region

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
)

type recoveryAuthority struct{}

func (recoveryAuthority) Guard(context.Context, uint64) error { return nil }
func (recoveryAuthority) HomeWrite(ctx context.Context, _ uint64) (context.Context, func(), error) {
	return ctx, func() {}, nil
}

// Accepted creates cross the real signed OCI SDK and disk-backed conditional
// Object Storage boundary, then resume from a newly constructed owner.
func TestFoundationAcceptedCreateRecoversFromDurablePendingRequest(t *testing.T) {
	store, _, _ := foundationProtocolStore(t)
	plan, err := ociregion.LoadPlan(filepath.Join("..", "..", "deploy", "oci-region", "sfo-1-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	delete(plan, "_source_path")
	const resourceID = "ocid1.compartment.oc1..acceptedcontrol"
	var mu sync.Mutex
	var live map[string]any
	var token string
	posts, creates := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned foundation request")
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/20160918/tenancies/"):
			io.WriteString(w, `{"homeRegionKey":"FRA"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments":
			if live == nil {
				io.WriteString(w, `[]`)
			} else {
				json.MarshalWrite(w, []map[string]any{live})
			}
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments/"+resourceID:
			json.MarshalWrite(w, live)
		case r.Method == http.MethodPost && r.URL.Path == "/20160918/compartments":
			posts++
			if !strings.Contains(r.Host, "eu-frankfurt-1") {
				t.Errorf("IAM create addressed non-home host %s", r.Host)
			}
			if token != "" {
				if r.Header.Get("opc-retry-token") != token {
					t.Error("new owner changed accepted request token")
				}
				json.MarshalWrite(w, live)
				return
			}
			if err := json.UnmarshalRead(r.Body, &live); err != nil {
				t.Error(err)
			}
			creates++
			token = r.Header.Get("opc-retry-token")
			if token == "" {
				t.Error("accepted request omitted token")
			}
			live["id"], live["lifecycleState"] = resourceID, "ACTIVE"
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"InternalError","message":"accepted response lost"}`)
		default:
			t.Errorf("unexpected foundation request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(plan["tenancy_id"].(string), "ocid1.user.oc1..test", plan["region"].(string), "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: plan["region"].(string), Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	controller := &FoundationController{Store: store, Authority: recoveryAuthority{}}
	client := SDKFoundations{Factory: factory}
	intentWire, _ := json.Marshal(plan, json.Deterministic(true))
	intentHash := sha256.Sum256(intentWire)
	now := time.Now().UTC()
	record := FoundationRecord{SchemaVersion: 1, Cell: "SFO", OCIRegion: plan["region"].(string), TenancyID: plan["tenancy_id"].(string),
		ParentCompartmentID: plan["parent_compartment_id"].(string), SharedCompartmentID: plan["shared_compartment_id"].(string), Generation: 1,
		IntentDigest: hex.EncodeToString(intentHash[:]), GrantSHA256: strings.Repeat("a", 64), OperationID: entityid.Derive("regional-foundation", plan["tenancy_id"].(string), "SFO", "1"), Epoch: 1, LeaseID: entityid.New(), ExpiresAt: now.Add(foundationLease),
		Stage: "foundation", StartedAt: now, UpdatedAt: now, ResourceIDs: map[string]string{}, AuxiliaryIDs: map[string]string{}, PendingCreates: map[string]PendingFoundationCreate{}, ResourceProvenance: map[string]FoundationResourceProvenance{}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	newAttempt := func(record FoundationRecord, etag string) *foundationAttempt {
		_, cancel := context.WithCancelCause(t.Context())
		t.Cleanup(func() { cancel(nil) })
		return &foundationAttempt{controller: controller, record: record, etag: etag, leaseID: record.LeaseID, epoch: record.Epoch, cancel: cancel}
	}
	stop := errors.New("stop after recovered checkpoint")
	progress := func(attempt *foundationAttempt) FoundationProgress {
		return FoundationProgress{OperationID: attempt.record.OperationID, BeforeWrite: attempt.beforeWrite, AuxiliaryIDs: maps.Clone(attempt.record.AuxiliaryIDs),
			PrepareCreate: attempt.prepareCreate, CheckpointAuxiliary: attempt.checkpointAuxiliary, Checkpoint: func(ctx context.Context, key, id string) error {
				if err := attempt.checkpoint(ctx, key, id); err != nil {
					return err
				}
				return stop
			}}
	}
	first := newAttempt(record, etag)
	if _, err := client.ReconcileFoundation(t.Context(), plan, progress(first)); err == nil {
		t.Fatal("lost accepted response succeeded")
	}
	saved, etag, err := store.Load(t.Context(), "SFO")
	if err != nil || len(saved.ResourceIDs) != 0 || len(saved.PendingCreates) != 1 {
		t.Fatalf("accepted create was not durably prepared: record=%+v err=%v", saved, err)
	}
	saved.ResourceIDs, saved.AuxiliaryIDs = maps.Clone(saved.ResourceIDs), maps.Clone(saved.AuxiliaryIDs)
	saved.PendingCreates = maps.Clone(saved.PendingCreates)
	for _, invalid := range []string{"missing pending", "changed request", "expired token"} {
		t.Run(invalid, func(t *testing.T) {
			candidate := saved
			candidate.PendingCreates = maps.Clone(saved.PendingCreates)
			pending := candidate.PendingCreates["control_compartment"]
			switch invalid {
			case "missing pending":
				delete(candidate.PendingCreates, "control_compartment")
			case "changed request":
				pending.Request.RequestDigest = strings.Repeat("0", 64)
				candidate.PendingCreates["control_compartment"] = pending
			case "expired token":
				candidate.StartedAt = now.Add(-25 * time.Hour)
				pending.FirstAttemptAt = now.Add(-24 * time.Hour)
				candidate.PendingCreates["control_compartment"] = pending
			}
			candidate.Epoch, candidate.LeaseID = saved.Epoch+1, entityid.New()
			candidate.UpdatedAt, candidate.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(foundationLease)
			var err error
			etag, err = store.CompareAndSwap(t.Context(), candidate, etag)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ReconcileFoundation(t.Context(), plan, progress(newAttempt(candidate, etag))); err == nil || errors.Is(err, stop) {
				t.Fatalf("unsafe pending recovery succeeded: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if posts != 1 || creates != 1 {
				t.Fatalf("unsafe recovery reached provider mutation: posts=%d creates=%d", posts, creates)
			}
		})
	}
	originalPendingRequest := saved.PendingCreates["control_compartment"].Request
	recovered := saved
	recovered.Epoch, recovered.LeaseID = saved.Epoch+2, entityid.New()
	recovered.UpdatedAt, recovered.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(foundationLease)
	etag, err = store.CompareAndSwap(t.Context(), recovered, etag)
	if err != nil {
		t.Fatal(err)
	}
	second := newAttempt(recovered, etag)
	if _, err := client.ReconcileFoundation(t.Context(), plan, progress(second)); !errors.Is(err, stop) {
		t.Fatalf("new owner could not recover accepted create: %v", err)
	}
	got, _, err := store.Load(t.Context(), "SFO")
	if err != nil || got.ResourceIDs["control_compartment"] != resourceID || len(got.PendingCreates) != 0 {
		t.Fatalf("recovered identity not checkpointed: record=%+v err=%v", got, err)
	}
	proof := got.ResourceProvenance["control_compartment"]
	if proof.ResourceID != resourceID || proof.Generation != 1 || proof.GrantSHA256 != record.GrantSHA256 || proof.Create.Request != originalPendingRequest || proof.Create.OperationID != record.OperationID {
		t.Fatalf("completed create lost original authority: %+v", proof)
	}
	// Advancing authority preserves the original creation proof and retry token.
	got.Generation, got.GrantSHA256 = 2, strings.Repeat("b", 64)
	got.OperationID = entityid.Derive("regional-foundation", got.TenancyID, got.Cell, "2")
	got.IntentDigest = strings.Repeat("c", 64)
	got.UpdatedAt, got.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(foundationLease)
	_, currentETag, err := store.Load(t.Context(), "SFO")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(t.Context(), got, currentETag); err != nil {
		t.Fatalf("new generation replaced original ownership: %v", err)
	}
	advanced, _, err := store.Load(t.Context(), "SFO")
	if err != nil || advanced.ResourceProvenance["control_compartment"] != proof {
		t.Fatalf("new generation lost resource birth proof: %+v, %v", advanced, err)
	}
	if err := first.prepareCreate(t.Context(), originalPendingRequest, true); !errors.Is(err, ErrFoundationFenced) {
		t.Fatalf("old owner retained pending-create authority: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 2 || creates != 1 {
		t.Fatalf("recovery duplicated accepted resource: posts=%d creates=%d", posts, creates)
	}
}

func TestFoundationAuxiliaryIdentityCheckpointsPersistSeparately(t *testing.T) {
	for _, entry := range []struct{ cell, region, ocidRegion string }{
		{"GRU", "sa-saopaulo-1", "sa-saopaulo-1"},
		{"PHX", "us-phoenix-1", "phx"},
		{"IAD", "us-ashburn-1", "iad"},
	} {
		t.Run(entry.cell, func(t *testing.T) {
			store, _, _ := foundationProtocolStore(t)
			now := time.Now().UTC()
			request := foundation.CreateIdentity{Key: "ledger_bucket", Region: entry.region, RequestDigest: strings.Repeat("0", 64)}
			record := FoundationRecord{SchemaVersion: 1, Cell: entry.cell, OCIRegion: request.Region, TenancyID: "ocid1.tenancy.oc1..test",
				ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1,
				IntentDigest: strings.Repeat("0", 64), OperationID: entityid.New(), Epoch: 1, LeaseID: entityid.New(), ExpiresAt: now.Add(foundationLease),
				Stage: "foundation", StartedAt: now, UpdatedAt: now, ResourceIDs: map[string]string{}, AuxiliaryIDs: map[string]string{}, PendingCreates: map[string]PendingFoundationCreate{}}
			etag, err := store.CompareAndSwap(t.Context(), record, "")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			attempt := &foundationAttempt{controller: &FoundationController{Store: store, Authority: recoveryAuthority{}}, record: record,
				etag: etag, leaseID: record.LeaseID, epoch: record.Epoch, cancel: cancel}
			if err := attempt.prepareCreate(ctx, request, false); err != nil {
				t.Fatal(err)
			}
			if err := attempt.prepareCreate(ctx, request, true); err == nil {
				t.Fatal("untokened bucket create allowed unknown-result replay")
			}
			bucketID := "ocid1.bucket.oc1." + entry.ocidRegion + ".ledger"
			if err := attempt.checkpointAuxiliary(ctx, "ledger_bucket", bucketID); err != nil {
				t.Fatal(err)
			}
			got, _, err := store.Load(ctx, entry.cell)
			if err != nil || len(got.ResourceIDs) != 0 || got.AuxiliaryIDs["ledger_bucket"] != bucketID || len(got.PendingCreates) != 0 {
				t.Fatalf("auxiliary identity mixed into strict plan or lost: record=%+v err=%v", got, err)
			}
			for key, id := range map[string]string{"unknown_key": bucketID, "head_bucket": "ocid1.bucket.oc1.eu-frankfurt-1.foreign", "controller_usage_policy": bucketID} {
				if err := attempt.checkpointAuxiliary(ctx, key, id); err == nil {
					t.Fatalf("invalid auxiliary identity accepted: %s=%s", key, id)
				}
			}
		})
	}
}
