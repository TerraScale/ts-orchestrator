package controlaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestReadAccessCrossesSignedObjectFoundationAndCurrentVault(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	deployment, cluster, installation := entityid.New(), entityid.New(), entityid.New()
	tenancy, vault, key := "ocid1.tenancy.oc1..test", "ocid1.vault.oc1.sa-saopaulo-1.owned", "ocid1.key.oc1.sa-saopaulo-1.owned"
	intent := region.FoundationIntent{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy,
		"parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared",
		"resource_ids": map[string]any{"control_compartment": "ocid1.compartment.oc1..control", "vault": vault, "key": key}},
		ReadAccess: &region.ReadAccessIntent{URLs: []string{"https://gru.example.test"}, UsageToken: vaultsecret.Ref{Vault: vault, Name: "usage-token"}}}
	grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: tenancy,
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared",
		Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration", Regions: []region.FoundationIntent{intent}}
	grantPayload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	grantEnvelope, err := trust.Sign(grantPayload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "foundation", Slot: cluster}, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grantEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	storage := bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", LedgerBucket: "ledger", HeadKMSKeyOCID: key, LedgerKMSKeyOCID: key, Prefix: "bootstrap"}
	regionIntent, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	var capabilities []trust.Capability
	for _, domain := range bootstrap.BootstrapLedgerCapabilityDomains() {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "controller", Slots: []string{"seed-a"}, Actions: []string{"sign"}})
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedKey, Capabilities: capabilities}, now.Add(-time.Minute), now.Add(2*time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(wire []byte) string { sum := sha256.Sum256(wire); return hex.EncodeToString(sum[:]) }
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: 1, DeploymentID: deployment, Environment: "production", ClusterID: cluster,
		Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: storage, ControllerSlots: []string{"seed-a"}, LedgerDelegationWire: delegationWire,
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: digest(regionIntent), InitialRegionIntentWire: regionIntent,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: tenancy, OCIRegion: "sa-saopaulo-1", StorageDomain: storage, GrantGeneration: 1, GrantSHA256: digest(grantWire)}}
	anchorEnvelope, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(2*time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "grant"), grantWire, 0600); err != nil {
		t.Fatal(err)
	}
	intentDigest, err := region.FoundationIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	record := region.FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: tenancy,
		ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Generation: 1, IntentDigest: intentDigest, OperationID: entityid.New(), Epoch: 1,
		Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{"control_compartment": "ocid1.compartment.oc1..control", "vault": vault, "key": key}}
	recordWire, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "record"), recordWire, 0600); err != nil {
		t.Fatal(err)
	}
	var mode, reads, writes atomic.Int32
	token := strings.Repeat("secret", 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("OCI read lacked caller signature")
			w.WriteHeader(401)
			return
		}
		secretRead := strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName") && r.Method == http.MethodPost
		if r.Method != http.MethodGet && !secretRead {
			writes.Add(1)
			w.WriteHeader(405)
			return
		}
		if secretRead {
			reads.Add(1)
			if r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Get("vaultId") != vault || r.URL.Query().Get("secretName") != "usage-token" {
				t.Error("Vault request differed from exact signed CURRENT reference")
			}
			if mode.Load() == 1 {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"code":"NotAuthorizedOrNotFound","message":"absent"}`)
				return
			}
			value, secretRegion, version := token, "sa-saopaulo-1", 3
			switch mode.Load() {
			case 2:
				secretRegion = "eu-frankfurt-1"
			case 3:
				version = 0
			case 4:
				value += "\n"
			case 5:
				value = "short"
			case 6:
				<-r.Context().Done()
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"secretId":"ocid1.vaultsecret.oc1.%s.owned","versionNumber":%d,"secretBundleContent":{"contentType":"BASE64","content":"%s"}}`, secretRegion, version, base64.StdEncoding.EncodeToString([]byte(value)))
			return
		}
		name := "record"
		if strings.HasSuffix(r.URL.Path, "foundation-scope-v1.json") {
			name = "grant"
		}
		wire, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("etag", digest(wire))
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..test", "sa-saopaulo-1", "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&objects.BaseClient, server.URL)
	footprint, err := region.NewSignedFootprint(&objects, verified, roots, tenancy)
	if err != nil {
		t.Fatal(err)
	}
	store, err := region.NewObjectFoundationStore(&objects, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&secrets.BaseClient, server.URL)
	resolve := func(ctx context.Context, selector string) (Access, error) {
		return resolveCurrent(ctx, region.FoundationResolver{Footprint: footprint, Store: store}, selector, func(selected string) (vaultsecret.BundleClient, error) {
			if selected != "sa-saopaulo-1" {
				t.Error("Vault client region differed from signed access")
			}
			return secrets, nil
		})
	}
	access, err := resolve(t.Context(), "")
	if err != nil || access.Token != token || len(access.URLs) != 1 || access.URLs[0] != intent.ReadAccess.URLs[0] || reads.Load() != 1 {
		t.Fatalf("current signed access failed: %v", err)
	}
	wire, err := json.Marshal(access)
	if err != nil || strings.Contains(string(wire)+fmt.Sprintf("%v %#v %+v", access, access, access), token) {
		t.Fatal("access formatting exposed bearer")
	}
	for _, selector := range []string{"gru", "GRU", "sa-saopaulo-1"} {
		if _, err := resolve(t.Context(), selector); err != nil {
			t.Fatalf("catalog selector %s failed: %v", selector, err)
		}
	}
	for scenario := int32(1); scenario <= 6; scenario++ {
		mode.Store(scenario)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		before := reads.Load()
		_, err := resolve(ctx, "")
		cancel()
		if err == nil || scenario == 1 && !errors.Is(err, ErrPending) || scenario == 6 && (!errors.Is(err, context.DeadlineExceeded) || reads.Load() != before+1) {
			t.Fatalf("scenario %d accepted invalid/missing/canceled Vault delivery: %v", scenario, err)
		}
	}
	before := reads.Load()
	if err := os.Rename(filepath.Join(dir, "grant"), filepath.Join(dir, "missing-grant")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(t.Context(), ""); !errors.Is(err, ErrPending) || reads.Load() != before {
		t.Fatalf("absent signed source must stay pending without reading Vault: %v", err)
	}
	if writes.Load() != 0 {
		t.Fatal("read-access discovery attempted an OCI mutation")
	}
}
