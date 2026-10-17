package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The actual OCI SDK reads the signed root object from a persistent protocol
// server. An authentic grant still cannot manufacture current worker evidence.
func TestWorkerProfileAuthorityRequiresIndependentCurrentSources(t *testing.T) {
	_, client, publish := foundationProtocolStore(t)
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
	reader := &SignedFootprint{client: client, storage: bootstrap.StorageDomain{Namespace: "ns", HeadBucket: "heads", Prefix: "bootstrap"}, scope: scope, expires: now.Add(2 * time.Hour), roots: roots, tenancy: "ocid1.tenancy.oc1..test", home: bootstrap.FoundationScope{InstallationID: entityid.New(), GrantGeneration: 1}}
	grant := FoundationGrant{InstallationID: reader.home.InstallationID, SchemaVersion: 1, Generation: 1, TenancyID: reader.tenancy, ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "scenario",
		InfrastructureSpend: &InfrastructureSpendIntent{MonthlyLimitMinor: 9000}, Regions: []FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": reader.tenancy, "parent_compartment_id": "ocid1.compartment.oc1..parent", "shared_compartment_id": "ocid1.compartment.oc1..shared", "resource_ids": map[string]any{}}, BootstrapMaterial: &BootstrapMaterialIntent{PlanSHA256: strings.Repeat("a", 64), Config: bootstrapmaterial.Config{Environment: "production"}, SourceRegistration: &bootstrap.InitialSourceRegistration{StorageDomain: bootstrap.StorageDomain{Namespace: "ns"}}}}}}
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
	for _, role := range []string{"container", "wasm"} {
		for _, arch := range []string{"arm64", "amd64"} {
			grant.WorkerProfiles = append(grant.WorkerProfiles, WorkerProfile{Cell: "GRU", Environment: "production", Role: role, Architecture: arch, Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 12, BootGB: 50, AvailabilityDomains: []string{"test:AD-1"}, CompartmentRef: ref("workload_compartment"), SubnetRef: ref("subnet"), NSGRef: ref("workload_network_security_group"), Runtime: release.ProductionRuntime,
				PoolMembership:  WorkerPoolMembership{Purpose: PoolMembershipQuarantineV1, Provenance: PoolMembershipProvenanceV1},
				CapacityJournal: WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1},
				ImageSource:     WorkerImageSource{OCIRegion: "sa-saopaulo-1", Namespace: "ns", Bucket: bucket, CurrentObject: releasechannel.CurrentImageObject(role, arch, "production"), ImageDomain: release.ImageDomain, QualificationDomain: release.ProductionQualificationDomain}, Bootstrap: WorkerBootstrapTemplate{Derivation: WorkerBootstrapDerivationV1, MaterialPlanSHA256: strings.Repeat("a", 64), VaultRef: ref("vault"), KMSKeyRef: ref("key"), RecipientPermission: "SECRET_BUNDLE_READ"}})
		}
	}
	if err := ValidateWorkerProfiles(grant, grant.WorkerProfiles, roots, now); err != nil {
		t.Fatal(err)
	}
	write := func() {
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
	write()
	if _, err := reader.AuthorizedRegions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || !strings.Contains(err.Error(), "independently authenticated OCI source") {
		t.Fatalf("root profile manufactured current worker proof: %v", err)
	}
	spending := grant.InfrastructureSpend
	grant.InfrastructureSpend = nil
	write()
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || !strings.Contains(err.Error(), "bounded fleet spending") {
		t.Fatalf("worker profile bypassed numerical fleet authority: %v", err)
	}
	grant.InfrastructureSpend = spending
	original, _ := json.Marshal(grant.WorkerProfiles, json.Deterministic(true))
	for _, permission := range []WorkerCapacityJournal{
		{},
		{Purpose: "general-foundation-write", Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1},
		{Purpose: CapacityJournalPurposeV1, Principal: "current-regional-writer", Delta: CapacityJournalDeltaV1},
		{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: "replace-record"},
	} {
		if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
			t.Fatal(err)
		}
		grant.WorkerProfiles[0].CapacityJournal = permission
		write()
		if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || strings.Contains(err.Error(), "independently authenticated OCI source") {
			t.Fatalf("signed worker profile without exact HOME capacity purpose reached runtime source: %v", err)
		}
	}
	for _, alter := range []func(){func() { grant.WorkerProfiles[0].NSGRef = ref("network_security_group") }, func() { grant.WorkerProfiles[0].ImageSource.CurrentObject = "caller-selected" }, func() { grant.WorkerProfiles[0].Bootstrap.RecipientPermission = "MANAGE_SECRETS" }, func() { grant.WorkerProfiles[0].OCPUs = 4 }, func() { grant.WorkerProfiles[0].Bootstrap.MaterialPlanSHA256 = strings.Repeat("b", 64) }, func() { grant.WorkerProfiles[0].AvailabilityDomains = []string{"test:AD-1", "test:AD-1"} }} {
		if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
			t.Fatal(err)
		}
		alter()
		write()
		if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil || strings.Contains(err.Error(), "independently authenticated OCI source") {
			t.Fatalf("invalid root worker policy reached runtime source: %v", err)
		}
	}
	if err := json.Unmarshal(original, &grant.WorkerProfiles); err != nil {
		t.Fatal(err)
	}
	write()
	reader.home.GrantSHA256 = strings.Repeat("0", 64)
	if _, err := reader.WorkerProfiles(t.Context(), "GRU", "container"); err == nil {
		t.Fatal("worker reader accepted a different root-pinned grant")
	}
}
