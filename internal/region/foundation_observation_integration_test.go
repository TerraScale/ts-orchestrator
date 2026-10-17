package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestFoundationObservationDurableProgress(t *testing.T) {
	store, client, write := foundationProtocolStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()}
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test",
		home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1, OCIRegion: foundationHomeRegion}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy,
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": foundationHomeRegion, "tenancy_id": reader.tenancy,
			"parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}}}}}
	publish := func() {
		t.Helper()
		payload, err := trust.EncodePayload(grant)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now.Add(-time.Minute), now.Add(time.Hour), private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(wire)
		reader.home.GrantSHA256 = hex.EncodeToString(digest[:])
		write("bootstrap/"+foundationGrantObject, wire)
	}
	publish()
	resolver := FoundationResolver{Footprint: reader, Store: store}
	if _, err := resolver.ObserveFoundation(t.Context(), "GRU"); !errors.Is(err, ErrFoundationMissing) {
		t.Fatalf("missing record = %v", err)
	}
	digest, err := FoundationIntentDigest(grant.Regions[0])
	if err != nil {
		t.Fatal(err)
	}
	started := now.Add(-10 * time.Minute)
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: foundationHomeRegion, TenancyID: reader.tenancy,
		ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1, IntentDigest: digest,
		GrantSHA256: reader.home.GrantSHA256, OperationID: entityid.Derive("regional-foundation", reader.tenancy, "GRU", "1"), Epoch: 1152921504606846977,
		LeaseID: entityid.New(), ExpiresAt: now.Add(foundationLease), Stage: "foundation", StartedAt: started, UpdatedAt: now,
		ResourceIDs:  map[string]string{"vault": "ocid1.vault.oc1.sa-saopaulo-1.owned", "backup_bucket": "ocid1.bucket.oc1.sa-saopaulo-1.primary"},
		AuxiliaryIDs: map[string]string{"backup_bucket": "ocid1.bucket.oc1.sa-saopaulo-1.owned"}}
	create := PendingFoundationCreate{OperationID: record.OperationID, IntentDigest: digest, FirstAttemptAt: started.Add(time.Minute),
		Request: foundation.CreateIdentity{Key: "key", Region: foundationHomeRegion, RequestDigest: strings.Repeat("c", 64), RetryToken: strings.Repeat("d", 64)}}
	record.PendingCreates = map[string]PendingFoundationCreate{"key": create}
	birth := create
	birth.Request.Key = "vault"
	record.ResourceProvenance = map[string]FoundationResourceProvenance{"vault": {Create: birth, ResourceID: record.ResourceIDs["vault"], Generation: 1, GrantSHA256: record.GrantSHA256}}
	// Both maps may retain the same key with different IDs; birth belongs to one.
	birth.Request.Key = "backup_bucket"
	record.ResourceProvenance["backup_bucket"] = FoundationResourceProvenance{Create: birth, ResourceID: record.ResourceIDs["backup_bucket"], Generation: 1, GrantSHA256: record.GrantSHA256}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	// Reopen the real SDK-backed store, so the observation cannot use writer memory.
	resolver.Store, err = NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("e", 40)
	server, err := observability.NewTokenServer(observability.Config{}, token, observability.ServerDeps{
		Registry: observability.NewRegistry(true), Health: new(observability.Health),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.HandleAuthenticated("GET /v1/regions/{region}/foundation", FoundationObservationHandler(resolver))
	listener := httptest.NewServer(server)
	t.Cleanup(listener.Close)
	for _, stage := range []string{"foundation", "blocked", "reconciled"} {
		t.Run(stage, func(t *testing.T) {
			if stage != "foundation" {
				record.Stage, record.LeaseID, record.ExpiresAt = stage, "", time.Time{}
				if stage == "blocked" {
					record.BlockedReason = "foundation-unavailable"
				} else {
					record.BlockedReason, record.CompletedAt, record.PendingCreates = "", now, nil
				}
				etag, err = store.CompareAndSwap(t.Context(), record, etag)
				if err != nil {
					t.Fatal(err)
				}
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/v1/regions/gru/foundation", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := listener.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			wire, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("observation HTTP = %d %s, %v", response.StatusCode, wire, err)
			}
			var view FoundationObservation
			err = json.Unmarshal(wire, &view, json.RejectUnknownMembers(true))
			if err != nil || view.Stage != stage || view.OperationID != record.OperationID || view.Generation != record.Generation || view.Epoch != record.Epoch ||
				view.Reason != record.BlockedReason || !view.StartedAt.Equal(started) || !view.UpdatedAt.Equal(now) || !view.CompletedAt.Equal(record.CompletedAt) {
				t.Fatalf("durable progress mismatch: %+v, %v", view, err)
			}
			if len(view.Checkpoints) != 3+len(record.PendingCreates) {
				t.Fatalf("checkpoint count = %d", len(view.Checkpoints))
			}
			for _, checkpoint := range view.Checkpoints {
				if checkpoint.Kind == "resource" || checkpoint.Kind == "pending-create" {
					if checkpoint.OperationID != record.OperationID || !checkpoint.FirstAttemptAt.Equal(create.FirstAttemptAt) || checkpoint.Generation != 1 {
						t.Fatalf("checkpoint source provenance lost: %+v", checkpoint)
					}
				} else if !checkpoint.FirstAttemptAt.IsZero() || checkpoint.OperationID != "" || checkpoint.Generation != 0 {
					t.Fatalf("unrelated resource birth metadata attached to auxiliary checkpoint: %+v", checkpoint)
				}
			}
			for _, forbidden := range []string{record.LeaseID, digest, reader.home.GrantSHA256, create.Request.RetryToken, create.Request.RequestDigest,
				"leaseId", "intentDigest", "tenancyId", "request", "grantSha256", "netbirdManager", "ready", "in-sync"} {
				if forbidden != "" && strings.Contains(string(wire), forbidden) {
					t.Fatalf("projection leaked excluded value or field %q", forbidden)
				}
			}
			if !strings.Contains(string(wire), `"epoch":1152921504606846977`) {
				t.Fatal("epoch lost integer precision")
			}
		})
	}
	if _, err := resolver.ObserveFoundation(t.Context(), "SFO"); err == nil {
		t.Fatal("unsigned region was exposed")
	}
	// Changing a signed field outside Plan must invalidate the old observation.
	grant.Regions[0].ReadAccess = &ReadAccessIntent{URLs: []string{"https://gru.example.test"},
		UsageToken: vaultsecret.Ref{Vault: "ocid1.vault.oc1.sa-saopaulo-1.owned", Name: "usage-token"}}
	publish()
	if _, err := resolver.ObserveFoundation(t.Context(), "GRU"); err == nil {
		t.Fatal("changed full intent was exposed")
	}
	grant.Regions[0].ReadAccess = nil
	publish()
	record.TenancyID = "ocid1.tenancy.oc1..foreign"
	record.ResourceProvenance = nil
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ObserveFoundation(t.Context(), "GRU"); err == nil {
		t.Fatal("foreign durable tenancy was exposed")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/v1/regions/gru/foundation", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := listener.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusServiceUnavailable || string(wire) != `{"schemaVersion":1,"state":"unavailable","reason":"foundation-observation-unavailable"}` {
		t.Fatalf("scope rejection must expose only a safe unavailable response: %d %s, %v", response.StatusCode, wire, err)
	}
}
