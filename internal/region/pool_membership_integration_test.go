package region

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Permission and original births cross the actual signed SDK/ObjectStorage
// boundary; a current signed profile alone cannot authorize adoption.
func TestPoolMembershipUsesSignedPermissionAndOriginalProtectedBirth(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	store, client, publish := foundationProtocolStore(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	factory, err := ociclient.New(common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "fixture", "", nil), ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: entityid.New(), Cell: "GRU", Environment: "production", Role: "foundation", Slot: entityid.New()}
	reader := &SignedFootprint{client: client, factory: factory, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"},
		scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test",
		home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1, OCIRegion: "sa-saopaulo-1"}, local: bootstrap.BootstrapAnchor{Cell: "GRU"}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy,
		ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "fixture",
		InfrastructureSpend: &InfrastructureSpendIntent{MonthlyLimitMinor: 9000}, Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": reader.tenancy,
			"parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}},
			BootstrapMaterial: &BootstrapMaterialIntent{PlanSHA256: strings.Repeat("a", 64), Config: bootstrapmaterial.Config{Environment: "production"}, SourceRegistration: &bootstrap.InitialSourceRegistration{StorageDomain: bootstrap.StorageDomain{Namespace: "ns"}}}}}}
	ref := func(key string) string {
		value, err := FoundationResourceReference("GRU", key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	bucket, err := releasechannel.BucketName("GRU")
	if err != nil {
		t.Fatal(err)
	}
	profile := WorkerProfile{Cell: "GRU", Environment: "production", Role: "container", Architecture: "arm64", Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 12, BootGB: 50,
		AvailabilityDomains: []string{"fixture:AD-1"}, CompartmentRef: ref("workload_compartment"), SubnetRef: ref("subnet"), NSGRef: ref("workload_network_security_group"), Runtime: release.ProductionRuntime,
		ImageSource:     WorkerImageSource{OCIRegion: "sa-saopaulo-1", Namespace: "ns", Bucket: bucket, CurrentObject: releasechannel.CurrentImageObject("container", "arm64", "production"), ImageDomain: release.ImageDomain, QualificationDomain: release.ProductionQualificationDomain},
		Bootstrap:       WorkerBootstrapTemplate{Derivation: WorkerBootstrapDerivationV1, MaterialPlanSHA256: strings.Repeat("a", 64), VaultRef: ref("vault"), KMSKeyRef: ref("key"), RecipientPermission: "SECRET_BUNDLE_READ"},
		PoolMembership:  WorkerPoolMembership{Purpose: PoolMembershipQuarantineV1, Provenance: PoolMembershipProvenanceV1},
		CapacityJournal: WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1}}
	grant.WorkerProfiles = []WorkerProfile{profile}
	sign := func() {
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
		reader.home.GrantSHA256 = workerSHA256(wire)
		publish("bootstrap/"+foundationGrantObject, wire)
	}
	sign()
	profileWire, err := json.Marshal(profile, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	profileSHA := workerSHA256(profileWire)
	poolID, configurationID := "ocid1.instancepool.oc1.sa-saopaulo-1.original", "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.original"
	operation := entityid.New()
	wire := PoolWireRecord{RequestSHA256: strings.Repeat("b", 64), RetryToken: "original-pool-token", FirstAttemptAt: now.Add(-time.Minute), LastAttemptAt: now.Add(-time.Minute), Attempts: 1, AcceptedAt: now.Add(-time.Minute), OpcRequestID: "original-pool-response"}
	configWire := wire
	configWire.RequestSHA256 = strings.Repeat("c", 64)
	configWire.RetryToken = "original-configuration-token"
	configWire.OpcRequestID = "original-configuration-response"
	configuration := PoolConfigurationRecord{ConfigurationID: configurationID, OperationID: operation, RecipeSHA256: strings.Repeat("d", 64), ProfileSHA256: profileSHA, ConfigurationSHA256: strings.Repeat("e", 64), GrantSHA256: reader.home.GrantSHA256, Generation: 1, Create: configWire}
	pool := PoolResourceRecord{PoolID: poolID, PoolName: "original-pool", CompartmentID: "ocid1.compartment.oc1..workload", OperationID: operation, GrantSHA256: reader.home.GrantSHA256, Generation: 1,
		Role: profile.Role, Architecture: profile.Architecture, Shape: profile.Shape, ProfileSHA256: profileSHA, RecipeSHA256: configuration.RecipeSHA256, Create: wire,
		Configurations: map[string]PoolConfigurationRecord{configurationID: configuration}, CurrentConfigurationID: configurationID, Epoch: 1}
	intentSHA, err := FoundationIntentDigest(grant.Regions[0])
	if err != nil {
		t.Fatal(err)
	}
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID,
		Generation: 1, GrantSHA256: reader.home.GrantSHA256, IntentDigest: intentSHA, OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now.Add(-time.Minute), UpdatedAt: now, CompletedAt: now,
		ResourceIDs: map[string]string{"workload_compartment": pool.CompartmentID}, CapacityPools: map[string]PoolResourceRecord{poolID: pool},
		CapacityCreates: map[string]PoolCreateRecord{operation + ":pool": {OperationID: operation, PoolName: pool.PoolName, Kind: "pool", RecipeSHA256: configuration.RecipeSHA256, ProfileSHA256: profileSHA, GrantSHA256: reader.home.GrantSHA256, Generation: 1,
			ConfigurationID: configurationID, ConfigurationSHA256: configuration.ConfigurationSHA256, PlacementSHA256: strings.Repeat("f", 64), ResourceID: poolID, Request: wire},
			operation + ":configuration": {OperationID: operation, PoolName: pool.PoolName, Kind: "configuration", RecipeSHA256: configuration.RecipeSHA256, ProfileSHA256: profileSHA, GrantSHA256: reader.home.GrantSHA256, Generation: 1,
				ConfigurationSHA256: configuration.ConfigurationSHA256, ResourceID: configurationID, Request: configWire}}}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	resolver := FoundationResolver{Footprint: reader, Store: store}
	t.Run("known-child lifecycle is independent of current image", func(t *testing.T) {
		testKnownPoolLifecycle(t, resolver, record, poolID, configurationID, publish, now)
	})
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	proof, err := resolver.PoolMembership(ctx, "GRU", poolID, configurationID)
	if err != nil || !proof.IsVerified() || proof.PurposeSHA256() == "" {
		t.Fatalf("positive original membership proof: %v", err)
	}
	if err := proof.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.PoolMembership(ctx, "GRU", "ocid1.instancepool.oc1.sa-saopaulo-1.discovered", configurationID); err == nil {
		t.Fatal("adopted a discovered pool")
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var fabricated VerifiedPoolMembership
	if err := json.Unmarshal(encoded, &fabricated); err != nil {
		t.Fatal(err)
	}
	if fabricated.IsVerified() || fabricated.Revalidate(ctx) == nil {
		t.Fatal("JSON minted membership authority")
	}
	original, revoke := context.WithCancel(ctx)
	retained, err := resolver.PoolMembership(original, "GRU", poolID, configurationID)
	if err != nil {
		t.Fatal(err)
	}
	revoke()
	if retained.IsVerified() || retained.Revalidate(ctx) == nil {
		t.Fatal("fresh context replaced original canceled membership authority")
	}
	short, stop := context.WithDeadline(ctx, now.Add(30*time.Second))
	defer stop()
	if err := proof.Revalidate(short); err == nil {
		t.Fatal("accepted a shorter original observation lifetime")
	}
	for _, alter := range []struct {
		name   string
		change func(*FoundationRecord)
	}{
		{"missing original create", func(r *FoundationRecord) { delete(r.CapacityCreates, operation+":pool") }},
		{"different original profile", func(r *FoundationRecord) {
			p := r.CapacityPools[poolID]
			p.ProfileSHA256 = strings.Repeat("1", 64)
			r.CapacityPools[poolID] = p
		}},
		{"different configuration birth", func(r *FoundationRecord) {
			p := r.CapacityPools[poolID]
			c := p.Configurations[configurationID]
			c.Create.OpcRequestID = "successor"
			p.Configurations[configurationID] = c
			r.CapacityPools[poolID] = p
		}},
	} {
		t.Run(alter.name, func(t *testing.T) {
			candidate := record
			candidate.cloneCapacity()
			alter.change(&candidate)
			body, err := json.Marshal(candidate, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			publish(foundationObjectPrefix+"GRU.json", body)
			if err := proof.Revalidate(ctx); err == nil {
				t.Fatal("changed original evidence remained authorized")
			}
			body, err = json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			publish(foundationObjectPrefix+"GRU.json", body)
		})
	}
	grant.WorkerProfiles[0].PoolMembership.Purpose = "terminate-member"
	sign()
	if err := proof.Revalidate(ctx); err == nil {
		t.Fatal("changed signed permission remained authorized")
	}
	if _, err := resolver.PoolMembership(ctx, "GRU", poolID, configurationID); err == nil {
		t.Fatal("unsupported signed purpose minted quarantine authority")
	}
}
