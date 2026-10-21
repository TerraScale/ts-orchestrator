package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// These are declared remote fixture facts, not provisioning or production
// qualification. Every observation still crosses the actual signed OCI SDK.
// No pool, source actor, material producer, IAM writer or manager is created.
type genericReachabilityFixture struct {
	t        *testing.T
	base     foundationProvisionFixture
	prepared FoundationPreparation
	bundle   RetainedFoundation
	factory  *ociclient.Factory
	resolver FoundationResolver
	records  map[string]FoundationRecord
}

func cloneReachabilityPreparation(t *testing.T, prepared FoundationPreparation) FoundationPreparation {
	t.Helper()
	wire, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	var cloned FoundationPreparation
	if err := json.Unmarshal(wire, &cloned, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func newGenericReachabilityFixture(t *testing.T) *genericReachabilityFixture {
	t.Helper()
	f := &genericReachabilityFixture{t: t, base: newFoundationProvisionFixture(t), records: map[string]FoundationRecord{}}
	f.prepared = cloneReachabilityPreparation(t, f.base.prepared)
	for index := range f.prepared.Grant.WorkerProfiles {
		profile := &f.prepared.Grant.WorkerProfiles[index]
		profile.PoolMembership = WorkerPoolMembership{Purpose: PoolMembershipQuarantineV1, Provenance: PoolMembershipProvenanceV1}
		profile.CapacityJournal = WorkerCapacityJournal{Purpose: CapacityJournalPurposeV1, Principal: CapacityJournalPrincipalV1, Delta: CapacityJournalDeltaV1}
	}
	if f.prepared.Grant.SchemaVersion != 3 || len(f.prepared.Grant.WorkloadGenesis) != 9 {
		t.Fatal("fixture lacks complete original schema3")
	}
	if err := ValidatePreparedFoundation(f.prepared.Grant); err != nil {
		t.Fatal(err)
	}
	// A fresh client adopts the schema3 origin; the fixture already adopted its legacy grant at this generation.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f.bundle = signProvisionFoundation(t, f.prepared, f.base.bundle.RootChainWire, f.base.root, f.base.now)
	if len(f.bundle.GrantWire) > foundationGrantLimit {
		t.Fatal("complete signed fixture exceeds current grant read bound")
	}
	f.publish(f.bundle)
	original, err := json.Marshal(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) > MaxWorkloadGenesisEvidenceBytes {
		t.Fatal("complete original fixture exceeds evidence read bound")
	}
	for _, origin := range f.prepared.Grant.WorkloadGenesis {
		object, err := release.WorkloadGenesisObject(origin.TenancyID, origin.Cell, origin.Environment, origin.Role)
		if err != nil {
			t.Fatal(err)
		}
		f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+object, original)
	}
	for _, regional := range f.prepared.Grant.Regions {
		f.seedRegion(regional)
	}
	f.factory = f.base.factoryFor()
	client, err := f.factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	// The independent root comes from the offline fixture ceremony, never from
	// a transported grant, terminal root map or remote original-proof object.
	f.resolver, err = discoverCurrentFoundation(t.Context(), &client, f.bundle.TenancyID, f.base.roots)
	if err != nil {
		t.Fatal(err)
	}
	reader := f.resolver.Footprint.(*SignedFootprint)
	reader.factory = f.factory
	reader.independentGenesis = maps.Clone(f.base.roots)
	t.Cleanup(func() {
		f.base.cloud.mu.Lock()
		defer f.base.cloud.mu.Unlock()
		if f.base.cloud.creates != 0 || f.base.cloud.launchPosts != 0 || f.base.cloud.materialPosts != 0 {
			t.Errorf("read fixture performed effects: creates=%d launches=%d material=%d", f.base.cloud.creates, f.base.cloud.launchPosts, f.base.cloud.materialPosts)
		}
	})
	return f
}

func (f *genericReachabilityFixture) publish(bundle RetainedFoundation) {
	f.t.Helper()
	f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+foundationRootChainObject, bundle.RootChainWire)
	f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+foundationDiscoveryObject, bundle.AnchorWire)
	f.base.cloud.writeObject(foundationDiscoveryBucket+"/bootstrap/"+foundationGrantObject, bundle.GrantWire)
}

func (f *genericReachabilityFixture) seedRegion(regional FoundationIntent) {
	f.t.Helper()
	grant := f.prepared.Grant
	cell := regional.Plan["cell"].(string)
	region := catalog.OCIRegion(cell)
	ids := map[string]string{}
	pins := regional.Plan["resource_ids"].(map[string]any)
	kinds := map[string]string{"control_compartment": "compartment", "network_compartment": "compartment", "workload_compartment": "compartment", "vcn": "vcn", "subnet": "subnet", "network_security_group": "networksecuritygroup", "workload_network_security_group": "networksecuritygroup", "vault": "vault", "key": "key"}
	for role, kind := range kinds {
		idRegion := region
		if kind == "compartment" {
			idRegion = ""
		}
		id := "ocid1." + kind + ".oc1." + idRegion + ".fixture" + strings.ToLower(cell) + strings.ReplaceAll(role, "_", "")
		if pin, _ := pins[role].(string); pin != "" && !strings.HasPrefix(pin, "foundation:") {
			id = pin
		}
		ids[role] = id
	}
	digest, err := FoundationIntentDigest(regional)
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.base.now
	record := FoundationRecord{SchemaVersion: 1, Cell: cell, OCIRegion: region, TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID,
		Generation: grant.Generation, GrantSHA256: preparationDigest(f.bundle.GrantWire), IntentDigest: digest, OperationID: entityid.Derive("regional-foundation", grant.TenancyID, cell, fmt.Sprint(grant.Generation)), Epoch: 1,
		Stage: "reconciled", StartedAt: now.Add(-time.Minute), UpdatedAt: now, CompletedAt: now, ResourceIDs: ids, ResourceProvenance: map[string]FoundationResourceProvenance{}}
	for role, id := range ids {
		record.ResourceProvenance[role] = FoundationResourceProvenance{ResourceID: id, Generation: grant.Generation, GrantSHA256: record.GrantSHA256,
			Create: PendingFoundationCreate{OperationID: record.OperationID, IntentDigest: digest, FirstAttemptAt: record.StartedAt.Add(time.Second),
				Request: foundation.CreateIdentity{Key: role, Region: region, RequestDigest: strings.Repeat("a", 64), RetryToken: strings.Repeat("b", 64)}}}
	}
	if err := record.validate(); err != nil {
		f.t.Fatal(err)
	}
	f.records[cell] = record
	wire, err := json.Marshal(record)
	if err != nil {
		f.t.Fatal(err)
	}
	f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+foundationObjectPrefix+cell+".json", wire)
	cloud := f.base.cloud
	for _, role := range []string{"control_compartment", "network_compartment", "workload_compartment"} {
		cloud.rows[ids[role]] = map[string]any{"id": ids[role], "compartmentId": grant.ParentCompartmentID, "lifecycleState": "ACTIVE"}
		cloud.collections[ids[role]] = "compartments"
	}
	cloud.rows[ids["vcn"]] = map[string]any{"id": ids["vcn"], "compartmentId": ids["network_compartment"], "cidrBlock": regional.Plan["network_cidr"], "lifecycleState": "AVAILABLE"}
	cloud.rows[ids["subnet"]] = map[string]any{"id": ids["subnet"], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "cidrBlock": regional.Plan["subnet_cidr"], "prohibitPublicIpOnVnic": true, "lifecycleState": "AVAILABLE"}
	for _, role := range []string{"network_security_group", "workload_network_security_group"} {
		cloud.rows[ids[role]] = map[string]any{"id": ids[role], "compartmentId": ids["network_compartment"], "vcnId": ids["vcn"], "lifecycleState": "AVAILABLE"}
		cloud.collections[ids[role]] = "networkSecurityGroups"
	}
	cloud.rows[ids["vault"]] = map[string]any{"id": ids["vault"], "compartmentId": ids["control_compartment"], "lifecycleState": "ACTIVE", "vaultType": "DEFAULT", "managementEndpoint": "https://fixture-management.kms." + region + ".oraclecloud.com"}
	cloud.rows[ids["key"]] = map[string]any{"id": ids["key"], "compartmentId": ids["control_compartment"], "vaultId": ids["vault"], "lifecycleState": "ENABLED", "protectionMode": "HSM", "keyShape": map[string]any{"algorithm": "AES", "length": 32}}
	for role, collection := range map[string]string{"vcn": "vcns", "subnet": "subnets", "vault": "vaults", "key": "keys"} {
		cloud.collections[ids[role]] = collection
	}
}

// Authenticate the new anchor independently, but deliberately do not ask
// current discovery to accept a malformed grant before testing its consumers.
func (f *genericReachabilityFixture) readerFor(bundle RetainedFoundation) FoundationResolver {
	f.t.Helper()
	f.publish(bundle)
	anchor, err := verifyDiscoveryAnchor(bundle.AnchorWire, f.base.roots, bundle.TenancyID, bundle.Namespace)
	if err != nil {
		f.t.Fatal(err)
	}
	client := f.resolver.Footprint.(*SignedFootprint).client
	reader, err := NewSignedFootprint(client, anchor, f.base.roots, bundle.TenancyID)
	if err != nil {
		f.t.Fatal(err)
	}
	reader.factory = f.factory
	reader.independentGenesis = maps.Clone(f.base.roots)
	store, err := NewObjectFoundationStore(client, bundle.Namespace, foundationDiscoveryBucket)
	if err != nil {
		f.t.Fatal(err)
	}
	return FoundationResolver{Footprint: reader, Store: store}
}

func TestSchema3GenericReachabilitySignedSDK(t *testing.T) {
	f := newGenericReachabilityFixture(t)
	ctx := t.Context()
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		record, err := f.resolver.Resolve(ctx, cell)
		if err != nil || record.IntentDigest != f.records[cell].IntentDigest {
			t.Fatalf("Resolve %s: %v", cell, err)
		}
		// Schema3 startup is bound to the protected original birth this read
		// fixture must not invent; positive startup is the original startup suite's.
		if material, err := f.resolver.BootstrapMaterial(ctx, cell); err == nil || material.IsVerified() || !strings.Contains(err.Error(), "original startup protected birth") {
			t.Fatalf("%s escaped bound schema3 startup without its original birth: %v", cell, err)
		}
		origins, err := f.resolver.GenericWorkloadGeneses(ctx, cell, "production")
		if err != nil || len(origins) != 2 {
			t.Fatalf("generic origins %s: %d %v", cell, len(origins), err)
		}
		for _, role := range []string{"ts-auth", "function-worker"} {
			authority, err := f.resolver.ContainerReleaseAuthority(ctx, cell, role, "production")
			if err != nil || !authority.IsVerified() || !authority.WorkloadGenesis().IsVerified() || len(authority.OriginalProof()) == 0 {
				t.Fatalf("generic authority %s/%s: %v", cell, role, err)
			}
		}
		if _, err := f.resolver.ContainerReleaseAuthority(ctx, cell, "terrabase", "production"); err == nil {
			t.Fatal("TerraBase original commitment became generic authority")
		}
	}
	issuers, err := f.resolver.OCIRIssuers(ctx)
	if err != nil || len(issuers) == 0 {
		t.Fatalf("OCIR resolution: %v", err)
	}
	for _, issuer := range issuers {
		current, err := f.resolver.OCIRIssuer(ctx, issuer.ImageRepository())
		if err != nil || !current.IsVerified() {
			t.Fatalf("exact OCIR issuer: %v", err)
		}
	}
	cells, err := f.resolver.CapacityPoolCells(ctx)
	if err != nil || !slices.Equal(cells, []string{"FRA", "GRU", "SFO"}) {
		t.Fatalf("routing: %v %v", cells, err)
	}
	if err := f.resolver.VerifyNativeWorkloadAdmission(ctx, "GRU", "production"); err == nil {
		t.Fatal("schema3 became native admission")
	}
	// Valid routing never grants pool effects without original accepted births.
	if _, err := f.resolver.PoolMembership(ctx, "GRU", "ocid1.instancepool.oc1.sa-saopaulo-1.fixture", "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.fixture"); err == nil || !strings.Contains(err.Error(), "exact original accepted pool create") {
		t.Fatalf("pool birth hold: %v", err)
	}
	if _, err := f.resolver.PoolLifecycle(ctx, "GRU", entityid.Derive("fixture-child"), "ocid1.instance.oc1.sa-saopaulo-1.fixture"); err == nil || !strings.Contains(err.Error(), "exact positive original worker birth") {
		t.Fatalf("child birth hold: %v", err)
	}
}

func TestSchema3FullGrantRefusalsReachRoutingConsumers(t *testing.T) {
	f := newGenericReachabilityFixture(t)
	cases := []struct {
		name   string
		mutate func(*FoundationPreparation)
		hold   error
	}{
		{name: "missing genesis", mutate: func(p *FoundationPreparation) { p.Grant.WorkloadGenesis = nil }},
		{name: "incomplete genesis", mutate: func(p *FoundationPreparation) { p.Grant.WorkloadGenesis = p.Grant.WorkloadGenesis[:8] }},
		{name: "foreign genesis home", mutate: func(p *FoundationPreparation) { p.Grant.WorkloadGenesis[0].Namespace = "foreign" }},
		{name: "missing attestor", mutate: func(p *FoundationPreparation) { p.Grant.Regions[0].BootstrapMaterial.AdmissionAttestor = nil }, hold: ErrAdmissionAttestorHold},
		{name: "attestor purpose drift", mutate: func(p *FoundationPreparation) {
			p.Grant.Regions[0].BootstrapMaterial.AdmissionAttestor.Action = "publish"
		}, hold: ErrAdmissionAttestorHold},
		{name: "partial source purposes", mutate: func(p *FoundationPreparation) { p.Grant.Regions[0].BootstrapMaterial.OriginalSourceProducer = nil }, hold: ErrOriginalSourceProducerHold},
		{name: "all source purposes absent", mutate: func(p *FoundationPreparation) {
			for index := range p.Grant.Regions {
				p.Grant.Regions[index].BootstrapMaterial.OriginalSourceProducer = nil
			}
		}, hold: ErrOriginalSourceProducerHold},
		{name: "source purpose drift", mutate: func(p *FoundationPreparation) {
			p.Grant.Regions[0].BootstrapMaterial.OriginalSourceProducer.Purpose = "unrelated-purpose"
		}, hold: ErrOriginalSourceProducerHold},
		{name: "missing original region", mutate: func(p *FoundationPreparation) { p.Grant.Regions = p.Grant.Regions[:2] }},
		{name: "missing spend authority", mutate: func(p *FoundationPreparation) { p.Grant.MonthlyLimitMinor = 0 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			prepared := cloneReachabilityPreparation(t, f.prepared)
			test.mutate(&prepared)
			bundle := signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.base.root, f.base.now)
			resolver := f.readerFor(bundle)
			if _, err := resolver.ProtectedCapacityStore(f.factory); err != nil {
				t.Fatalf("fixture missed actual SDK/store precondition: %v", err)
			}
			_, _, gate := resolver.Footprint.(*SignedFootprint).verifyGrant(bundle.GrantWire)
			if gate == nil {
				t.Fatal("full G accepted malformed original authority")
			}
			if test.hold != nil && !errors.Is(gate, test.hold) {
				t.Fatalf("wrong full G refusal: %v", gate)
			}
			checks := []struct {
				name string
				call func() error
			}{
				{"Resolve", func() error { _, err := resolver.Resolve(t.Context(), "GRU"); return err }},
				{"OCIR", func() error { _, err := resolver.OCIRIssuers(t.Context()); return err }},
				{"startup", func() error { _, err := resolver.BootstrapMaterial(t.Context(), "GRU"); return err }},
				{"routing5 CapacityPoolCells", func() error { _, err := resolver.CapacityPoolCells(t.Context()); return err }},
				{"routing6 PoolMembership", func() error {
					_, err := resolver.PoolMembership(t.Context(), "GRU", "ocid1.instancepool.oc1.sa-saopaulo-1.fixture", "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.fixture")
					return err
				}},
				{"routing9 PoolLifecycle", func() error {
					_, err := resolver.PoolLifecycle(t.Context(), "GRU", entityid.Derive("fixture-child"), "ocid1.instance.oc1.sa-saopaulo-1.fixture")
					return err
				}},
			}
			for _, check := range checks {
				if err := check.call(); err == nil || err.Error() != gate.Error() {
					t.Errorf("%s missed shared full G: got %v want %v", check.name, err, gate)
				}
			}
		})
	}
}

func TestSchema3CurrentRootHomeWireAndOriginalEvidenceRefusals(t *testing.T) {
	f := newGenericReachabilityFixture(t)
	reader := f.resolver.Footprint.(*SignedFootprint)
	t.Run("independent foreign root", func(t *testing.T) {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := trust.ParseKeyring(public)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := discoverCurrentFoundation(t.Context(), reader.client.(foundationDiscoveryObjects), f.bundle.TenancyID, foreign); err == nil {
			t.Fatal("foreign independent discovery root accepted")
		}
		original := reader.independentGenesis
		reader.independentGenesis = foreign
		defer func() { reader.independentGenesis = original }()
		if _, _, err := f.resolver.WorkloadGenesis(t.Context(), "GRU", "ts-auth", "production"); err == nil {
			t.Fatal("transported original proof replaced independent genesis")
		}
		reader.independentGenesis = nil
		if _, _, err := f.resolver.WorkloadGenesis(t.Context(), "GRU", "ts-auth", "production"); err == nil {
			t.Fatal("empty independent genesis fell back to terminal roots")
		}
		resolver := f.readerFor(f.bundle)
		resolver.Footprint.(*SignedFootprint).roots = foreign
		_, _, gate := resolver.Footprint.(*SignedFootprint).verifyGrant(f.bundle.GrantWire)
		if gate == nil {
			t.Fatal("foreign full G root accepted")
		}
		for _, call := range []func() error{
			func() error { _, err := resolver.CapacityPoolCells(t.Context()); return err },
			func() error {
				_, err := resolver.PoolMembership(t.Context(), "GRU", "ocid1.instancepool.oc1.sa-saopaulo-1.fixture", "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.fixture")
				return err
			},
			func() error {
				_, err := resolver.PoolLifecycle(t.Context(), "GRU", entityid.Derive("fixture-child"), "ocid1.instance.oc1.sa-saopaulo-1.fixture")
				return err
			},
		} {
			if err := call(); err == nil || err.Error() != gate.Error() {
				t.Fatalf("routing bypassed foreign full G root: %v", err)
			}
		}
	})
	t.Run("foreign authenticated home", func(t *testing.T) {
		prepared := cloneReachabilityPreparation(t, f.prepared)
		prepared.Anchor.StorageDomain.HeadBucket = "foreign-head"
		prepared.Anchor.FoundationScope.StorageDomain.HeadBucket = "foreign-head"
		prepared.Anchor.InitialSourceRegistration.StorageDomain.HeadBucket = "foreign-head"
		bundle := signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.base.root, f.base.now)
		f.publish(bundle)
		defer f.publish(f.bundle)
		if _, err := discoverCurrentFoundation(t.Context(), reader.client.(foundationDiscoveryObjects), bundle.TenancyID, f.base.roots); err == nil {
			t.Fatal("signed foreign home accepted")
		}
	})
	t.Run("current wire substitution", func(t *testing.T) {
		f.base.cloud.writeObject(foundationDiscoveryBucket+"/bootstrap/"+foundationGrantObject, []byte("{}"))
		defer f.publish(f.bundle)
		if _, err := f.resolver.Resolve(t.Context(), "GRU"); err == nil {
			t.Fatal("substituted current wire accepted")
		}
		if _, err := f.resolver.CapacityPoolCells(t.Context()); err == nil {
			t.Fatal("substituted current wire reached pool routing")
		}
		if _, err := f.resolver.PoolMembership(t.Context(), "GRU", "ocid1.instancepool.oc1.sa-saopaulo-1.fixture", "ocid1.instanceconfiguration.oc1.sa-saopaulo-1.fixture"); err == nil {
			t.Fatal("substituted current wire reached pool membership")
		}
		if _, err := f.resolver.PoolLifecycle(t.Context(), "GRU", entityid.Derive("fixture-child"), "ocid1.instance.oc1.sa-saopaulo-1.fixture"); err == nil {
			t.Fatal("substituted current wire reached pool lifecycle")
		}
		if err := f.resolver.VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err == nil {
			t.Fatal("substituted native current wire accepted")
		}
	})
	t.Run("permanent proof remains full original", func(t *testing.T) {
		prepared := cloneReachabilityPreparation(t, f.prepared)
		for index := range prepared.Grant.Regions {
			prepared.Grant.Regions[index].BootstrapMaterial.OriginalSourceProducer = nil
		}
		bad := signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.base.root, f.base.now)
		wire, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		object, err := release.WorkloadGenesisObject(f.bundle.TenancyID, "GRU", "production", "ts-auth")
		if err != nil {
			t.Fatal(err)
		}
		original, err := json.Marshal(f.bundle)
		if err != nil {
			t.Fatal(err)
		}
		f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+object, wire)
		defer f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+object, original)
		if _, _, err := f.resolver.WorkloadGenesis(t.Context(), "GRU", "ts-auth", "production"); err == nil || !strings.Contains(err.Error(), "complete founding scope") {
			t.Fatalf("incomplete original proof: %v", err)
		}
	})
}

func TestSchema3TransportedMetadataConfersNoEffects(t *testing.T) {
	f := newGenericReachabilityFixture(t)
	ctx := t.Context()
	reader := f.resolver.Footprint.(*SignedFootprint)
	attestor, err := reader.AdmissionAttestor(ctx, "GRU")
	if err != nil || !attestor.IsVerified() {
		t.Fatalf("document attestor purpose: %v", err)
	}
	if binding, err := attestor.OriginalBinding(ctx, nil); !errors.Is(err, ErrAdmissionAttestorHold) || binding.IsVerified() {
		t.Fatalf("document created original source binding: %v", err)
	}
	if scope, err := reader.OriginalSourceProducer(ctx, "GRU"); err != nil || !scope.IsVerified() {
		t.Fatalf("document source purpose: %v", err)
	}
	if actor, err := NewSourceFounder(ctx, f.resolver, nil); err == nil || actor != nil {
		t.Fatal("document created source actor without sealed original authority")
	}
	if err := (&HomeIAMAuthority{}).VerifyFoundationWriter(ctx); err == nil {
		t.Fatal("document created home writer authority")
	}
	if err := (VerifiedNetBirdManager{}).Check(ctx); err == nil {
		t.Fatal("document created manager authority")
	}
	if err := (VerifiedNetBirdManager{}).ClaimGenesis(ctx); err == nil {
		t.Fatal("document created manager store genesis")
	}
	for _, test := range []struct {
		name   string
		mutate func(*FoundationRecord)
	}{
		{"originalFoundationCompartments", func(r *FoundationRecord) { r.OriginalFoundationCompartments = &OriginalFoundationCompartments{} }},
		{"originalSourceProducers", func(r *FoundationRecord) { r.OriginalSourceProducers = &[3]OriginalSourceProducerBirth{} }},
		{"netBirdMaterial", func(r *FoundationRecord) { r.NetBirdMaterial = &NetBirdMaterialJournal{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := f.records["GRU"]
			test.mutate(&record)
			wire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var carried FoundationRecord
			if err := json.Unmarshal(wire, &carried, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			if err := carried.validate(); err == nil {
				t.Fatal("transported field fabricated owner-specific authority")
			}
			f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+foundationObjectPrefix+"GRU.json", wire)
			original, err := json.Marshal(f.records["GRU"])
			if err != nil {
				t.Fatal(err)
			}
			defer f.base.cloud.writeObject(foundationDiscoveryBucket+"/"+foundationObjectPrefix+"GRU.json", original)
			if _, err := f.resolver.Resolve(t.Context(), "GRU"); err == nil {
				t.Fatal("protected transported field bypassed owner-specific record validation")
			}
		})
	}
	for _, record := range f.records {
		if record.FoundationWriter != nil || record.NetBirdManager != nil || record.NetBirdMaterial != nil || record.OriginalSourceProducers != nil || record.OriginalFoundationCompartments != nil {
			t.Fatal("read fixture invented an effect actor")
		}
	}
}

func TestNativeAdmissionCurrentLegacyLineagePredicate(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			f := newCurrentDiscoveryScenario(t)
			f.grant.SchemaVersion = schema
			f.publish()
			resolver, err := f.discover(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := resolver.VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err != nil {
				t.Fatalf("current legacy refused: %v", err)
			}
			for _, target := range []struct{ cell, environment string }{{"SFO", "production"}, {"GRU", "staging"}} {
				if err := resolver.VerifyNativeWorkloadAdmission(t.Context(), target.cell, target.environment); err == nil {
					t.Fatal("native target substitution accepted")
				}
			}
			f.mu.Lock()
			f.objects["bootstrap/"+foundationGrantObject] = []byte("{}")
			f.mu.Unlock()
			if err := resolver.VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err == nil {
				t.Fatal("stale retained legacy resolver admitted substituted current grant")
			}
		})
	}
	t.Run("unknown current schema", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		f.grant.SchemaVersion = 4
		f.publish()
		anchor, err := verifyDiscoveryAnchor(f.objects[foundationDiscoveryObject], f.genesis, f.grant.TenancyID, "ns")
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewSignedFootprint(f.client, anchor, f.genesis, f.grant.TenancyID)
		if err != nil {
			t.Fatal(err)
		}
		if err := (FoundationResolver{Footprint: reader}).VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err == nil {
			t.Fatal("unknown current schema admitted native workload")
		}
	})
	t.Run("expired current lineage", func(t *testing.T) {
		f := newCurrentDiscoveryScenario(t)
		resolver, err := f.discover(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(-3 * time.Hour)
		f.publish()
		if err := resolver.VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err == nil {
			t.Fatal("expired current lineage admitted native workload")
		}
		if _, err := f.discover(t.Context()); err == nil {
			t.Fatal("expired current anchor admitted")
		}
	})
	if err := (FoundationResolver{}).VerifyNativeWorkloadAdmission(t.Context(), "GRU", "production"); err == nil {
		t.Fatal("missing current capability admitted")
	}
}
