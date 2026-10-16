package region

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The simulator persists exact Object Storage bytes and conditional-write
// semantics on disk; clients use the actual signed OCI HTTP implementation.
func foundationProtocolStore(t *testing.T) (*ObjectFoundationStore, FoundationObjects, func(string, []byte)) {
	t.Helper()
	dir := t.TempDir()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned object operation")
			w.WriteHeader(401)
			return
		}
		key := sha256.Sum256([]byte(r.URL.Path))
		path := filepath.Join(dir, hex.EncodeToString(key[:]))
		old, readErr := os.ReadFile(path)
		etag := fmt.Sprintf("%x", sha256.Sum256(old))
		if r.Method == http.MethodGet {
			if readErr != nil {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
				return
			}
			w.Header().Set("etag", etag)
			w.Write(old)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("if-none-match") == "*" && readErr == nil || r.Header.Get("if-match") != "" && (readErr != nil || r.Header.Get("if-match") != etag) {
			w.WriteHeader(412)
			io.WriteString(w, `{"code":"PreconditionFailed","message":"changed"}`)
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
		w.Header().Set("etag", fmt.Sprintf("%x", sha256.Sum256(wire)))
	}))
	t.Cleanup(server.Close)
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
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	store, err := NewObjectFoundationStore(&client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, wire []byte) {
		mu.Lock()
		defer mu.Unlock()
		key := sha256.Sum256([]byte("/n/ns/b/heads/o/" + name))
		if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(key[:])), wire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return store, &client, write
}

func TestFoundationRecordsPersistAndFenceConcurrentWriters(t *testing.T) {
	store, client, _ := foundationProtocolStore(t)
	now := time.Now().UTC()
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test",
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared",
		Generation: 1, IntentDigest: fmt.Sprintf("%064d", 0), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now,
		ResourceIDs: map[string]string{"vault": "ocid1.vault.oc1.sa-saopaulo-1.test"}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	got, actual, err := restarted.Load(t.Context(), "GRU")
	if err != nil || actual != etag || got.ResourceIDs["vault"] != record.ResourceIDs["vault"] {
		t.Fatalf("read=%+v etag=%s err=%v", got, actual, err)
	}
	got.Epoch = 2
	if _, err := restarted.CompareAndSwap(t.Context(), got, actual); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, etag); err != ErrFoundationConflict {
		t.Fatalf("stale writer: %v", err)
	}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != ErrFoundationConflict {
		t.Fatalf("duplicate founder: %v", err)
	}
}

func TestSignedFoundationScopeRequiresExplicitBootstrapAuthority(t *testing.T) {
	_, client, write := foundationProtocolStore(t)
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
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.test"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test", home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	config := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru", DeploymentID: scope.DeploymentID, ClusterID: scope.Slot,
		SubnetCIDR: "10.251.0.0/24", ValidityHours: 24, Slots: []bootstrapmaterial.Slot{{Name: "controller-a", PrivateIP: "10.251.0.11"}, {Name: "controller-b", PrivateIP: "10.251.0.12"}, {Name: "controller-c", PrivateIP: "10.251.0.13"}}}
	configWire, _ := json.Marshal(config, json.Deterministic(true))
	digest := sha256.Sum256(configWire)
	reader.local = bootstrap.BootstrapAnchor{Cell: oci.RegionGRU, DeploymentID: config.DeploymentID, ClusterID: config.ClusterID}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: "ocid1.compartment.oc1..control", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.test", KMSKeyOCID: reader.storage.HeadKMSKeyOCID}
	material := &BootstrapMaterialIntent{InstallationID: entityid.New(), PlanSHA256: hex.EncodeToString(digest[:]), Config: config, SourceVaultTarget: target}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy, ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": reader.tenancy, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{"control_compartment": target.CompartmentOCID, "vault": target.VaultOCID, "key": target.KMSKeyOCID}}}}}
	publish := func(signedScope trust.Scope, expiry time.Time) {
		payload, err := trust.EncodePayload(grant)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, signedScope, now.Add(-time.Minute), expiry, private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		pin := sha256.Sum256(wire)
		reader.home.GrantSHA256 = hex.EncodeToString(pin[:])
		write("bootstrap/"+foundationGrantObject, wire)
	}
	publish(scope, now.Add(time.Hour))
	if _, err := reader.AuthorizedRegions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU"); err == nil {
		t.Fatal("foundation-only scope authorized root generation")
	}
	grant.Regions[0].BootstrapMaterial = material
	publish(scope, now.Add(time.Hour))
	verified, err := reader.AuthorizedBootstrapMaterial(t.Context(), "GRU")
	if err != nil || !verified.IsVerified() || verified.PlanDigest() != material.PlanSHA256 || verified.EscrowTarget() != target || !verified.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	for _, scenario := range []string{"wrong scope", "expired", "wrong tenancy", "no budget", "wrong digest", "wrong escrow", "wrong local cluster", "wrong pinned digest"} {
		t.Run(scenario, func(t *testing.T) {
			changed := grant
			changed.Regions = append([]FoundationIntent(nil), grant.Regions...)
			badMaterial := *material
			changed.Regions[0].BootstrapMaterial = &badMaterial
			grant = changed
			signedScope, expires := scope, now.Add(time.Hour)
			switch scenario {
			case "wrong scope":
				signedScope.Cell = "FRA"
			case "expired":
				expires = now.Add(-time.Second)
			case "wrong tenancy":
				grant.TenancyID = "ocid1.tenancy.oc1..foreign"
			case "no budget":
				grant.MonthlyLimitMinor = 0
			case "wrong escrow":
				badMaterial.SourceVaultTarget.VaultOCID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
			case "wrong local cluster":
				reader.local.ClusterID = entityid.New()
			case "wrong digest":
				badMaterial.PlanSHA256 = fmt.Sprintf("%064d", 0)
			}
			publish(signedScope, expires)
			if scenario == "wrong pinned digest" {
				reader.home.GrantSHA256 = fmt.Sprintf("%064d", 0)
			}
			if _, err := reader.AuthorizedBootstrapMaterial(context.Background(), "GRU"); err == nil {
				t.Fatal("unapproved bootstrap material admitted")
			}
			reader.local.ClusterID = config.ClusterID
			grant.TenancyID = reader.tenancy
			grant.MonthlyLimitMinor = 10000
			grant.Regions[0].BootstrapMaterial = material
		})
	}
}
