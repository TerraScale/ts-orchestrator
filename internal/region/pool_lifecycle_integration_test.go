package region

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// This extends the genuine signed ObjectStorage fixture. No current image
// channel is published: original birth provenance is enough for cleanup scope,
// while the separate runtime drain and destructive SDK admission remain required.
func testKnownPoolLifecycle(t *testing.T, resolver FoundationResolver, original FoundationRecord, poolID, configurationID string,
	publish func(string, []byte), now time.Time,
	grant *FoundationGrant, sign func(),
) {
	t.Helper()
	record := original
	record.cloneCapacity()
	pool := record.CapacityPools[poolID]
	child, _, _ := protectedChildFixture()
	child.PoolID, child.ConfigurationID, child.RecipeSHA256 = poolID, configurationID, pool.Configurations[configurationID].RecipeSHA256
	child.PublicCAPEM, child.AvailabilityDomains = []byte("retained-original-public-ca"), []string{"fixture:AD-1"}
	child.AvailabilityDomain, child.SubnetID = child.AvailabilityDomains[0], "ocid1.subnet.oc1..original"
	child.Node, child.Descriptor = "ts-gru-4", "original-canonical-worker-descriptor"
	child.Launch.FirstAttemptAt, child.Launch.LastAttemptAt = now.Add(-40*time.Second), now.Add(-40*time.Second)
	child.Launch.AcceptedAt, child.BornAt = now.Add(-39*time.Second), now.Add(-39*time.Second)
	child.Attach.FirstAttemptAt, child.Attach.LastAttemptAt = now.Add(-38*time.Second), now.Add(-38*time.Second)
	child.Attach.AcceptedAt, child.Attach.WorkCompletedAt, child.ReadyAt = now.Add(-37*time.Second), now.Add(-36*time.Second), now.Add(-35*time.Second)
	quote := capacityledger.Quote{ScopeSHA256: strings.Repeat("a", 64), Cell: record.Cell, CompartmentID: pool.CompartmentID, Shape: pool.Shape,
		Currency: "USD", OCPUs: 2, MemoryGB: 12, BootGB: 50, IssuedAt: now.Add(-50 * time.Second), ExpiresAt: now.Add(time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	quote.MonthlyCents, _ = ocicost.NodeMonthlyCents(quote.Prices, quote.Shape, quote.OCPUs, quote.MemoryGB, quote.BootGB)
	receipt := capacityledger.Receipt{OperationID: child.OperationID, RecipeSHA256: child.RecipeSHA256, GrantSHA256: record.GrantSHA256, GrantGeneration: record.Generation,
		LogicalScopeSHA256: quote.ScopeSHA256, ResolvedScopeSHA256: quote.ScopeSHA256, TenancyID: record.TenancyID, ReservedAt: now.Add(-49 * time.Second), QuoteSHA256: quote.SHA256(), Quote: quote}
	record.CapacityLedger = &capacityledger.Ledger{Version: capacityledger.Version, Hosts: []capacityledger.Host{{Receipt: receipt,
		RequestSHA256: child.Launch.RequestSHA256, StartedAt: child.Launch.FirstAttemptAt, BornAt: child.BornAt, InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID}}}
	record.PoolChildren = map[string]PoolChildRecord{child.OperationID: child}
	_, etag, err := resolver.Store.Load(t.Context(), record.Cell)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Store.CompareAndSwap(t.Context(), record, etag); err != nil {
		t.Fatal(err)
	}
	// Restore only through the fixture's raw object publisher, never production
	// CAS: original births cannot be pruned by a real foundation writer.
	defer func() {
		wire, err := json.Marshal(original, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		publish(foundationObjectPrefix+record.Cell+".json", wire)
	}()
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	proof, err := resolver.PoolLifecycle(ctx, record.Cell, child.OperationID, child.InstanceID)
	if err != nil || !proof.IsVerified() || proof.Binding().BootVolumeID != child.BootVolumeID || proof.Binding().ConfigurationID != child.ConfigurationID {
		t.Fatalf("original signed known-child lifecycle without current image: %v", err)
	}
	if err := proof.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.PoolLifecycle(ctx, record.Cell, entityid.New(), child.InstanceID); err == nil {
		t.Fatal("adopted an instance without its exact original protected birth")
	}
	if _, err := resolver.PoolLifecycle(ctx, record.Cell, child.OperationID, "ocid1.instance.oc1..foreign"); err == nil {
		t.Fatal("rebound an original birth to another instance")
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var fabricated VerifiedPoolLifecycle
	if err := json.Unmarshal(encoded, &fabricated); err != nil {
		t.Fatal(err)
	}
	if fabricated.IsVerified() || fabricated.Revalidate(ctx) == nil {
		t.Fatal("public JSON minted known-child lifecycle authority")
	}
	originalCtx, revoke := context.WithCancel(ctx)
	retained, err := resolver.PoolLifecycle(originalCtx, record.Cell, child.OperationID, child.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	revoke()
	if retained.IsVerified() || retained.Revalidate(ctx) == nil {
		t.Fatal("fresh context replaced original cancelled known-child authority")
	}
	t.Run("compatible preferred successor keeps original birth", func(t *testing.T) {
		reader := resolver.Footprint.(*SignedFootprint)
		originalGrant, generation := *grant, reader.home.GrantGeneration
		defer func() {
			*grant, reader.home.GrantGeneration = originalGrant, generation
			sign()
			wire, err := json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			publish(foundationObjectPrefix+record.Cell+".json", wire)
		}()
		wire, err := json.Marshal(grant)
		if err != nil {
			t.Fatal(err)
		}
		var successor FoundationGrant
		if err := json.Unmarshal(wire, &successor); err != nil {
			t.Fatal(err)
		}
		successor.Generation++
		successor.Regions[0].Generation = successor.Generation
		successor.Regions[0].BootstrapMaterial.PlanSHA256 = strings.Repeat("9", 64)
		successor.WorkerProfiles[0].Bootstrap.MaterialPlanSHA256 = successor.Regions[0].BootstrapMaterial.PlanSHA256
		successor.WorkerProfiles[0].RuntimeSHA256 = strings.Repeat("8", 64)
		successor.WorkerProfiles[0].Shape = "VM.Standard.A2.Flex"
		successor.WorkerProfiles[0].AvailabilityDomains = []string{"fixture:AD-2"}
		successor.WorkerProfiles[0].ImageSource.Namespace = "preferred-images"
		successor.Regions[0].BootstrapMaterial.SourceRegistration.StorageDomain.Namespace = "preferred-images"
		alternative := successor.WorkerProfiles[0]
		alternative.Shape, alternative.AvailabilityDomains = "VM.Standard.A3.Flex", []string{"fixture:AD-3"}
		successor.WorkerProfiles = append(successor.WorkerProfiles, alternative)
		unauthorized := alternative
		unauthorized.CapacityJournal = WorkerCapacityJournal{}
		successor.WorkerProfiles = append(successor.WorkerProfiles, unauthorized)
		*grant, reader.home.GrantGeneration = successor, successor.Generation
		sign()
		current := record
		current.Generation, current.GrantSHA256 = successor.Generation, reader.home.GrantSHA256
		current.ResourceIDs = map[string]string{"workload_compartment": pool.CompartmentID, "subnet": "ocid1.subnet.oc1..preferred"}
		current.IntentDigest, err = FoundationIntentDigest(successor.Regions[0])
		if err != nil {
			t.Fatal(err)
		}
		wire, err = json.Marshal(current, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		publish(foundationObjectPrefix+record.Cell+".json", wire)
		next, err := resolver.PoolLifecycle(ctx, current.Cell, child.OperationID, child.InstanceID)
		if err != nil || !next.IsVerified() {
			t.Fatalf("current signed preferred runtime/source-plan change blocked known original cleanup: %v", err)
		}
		before, after := proof.Binding(), next.Binding()
		if after.ProfileSHA256 != before.ProfileSHA256 || after.RecipeSHA256 != before.RecipeSHA256 || after.BirthSHA256 != before.BirthSHA256 ||
			after.ConfigurationSHA256 != before.ConfigurationSHA256 || after.PoolBirthSHA256 != before.PoolBirthSHA256 ||
			after.Shape != pool.Shape || after.CurrentProfileSHA256 == before.CurrentProfileSHA256 || after.GrantSHA256 == before.GrantSHA256 || after.Generation != successor.Generation {
			t.Fatal("compatible cleanup rebound original birth or failed to pin distinct current authority")
		}
		preferredWire, err := json.Marshal(successor.WorkerProfiles[0], json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		alternativeWire, err := json.Marshal(alternative, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if after.CurrentProfileSHA256 != min(workerSHA256(preferredWire), workerSHA256(alternativeWire)) {
			t.Fatal("multi-shape cleanup did not pin the smallest actual canonical signed witness")
		}
		if err := next.Revalidate(ctx); err != nil {
			t.Fatal(err)
		}
		if proof.Revalidate(ctx) == nil {
			t.Fatal("an operation replaced its original current grant/profile with a compatible successor")
		}
		for _, test := range []struct {
			name   string
			change func(*FoundationGrant, *FoundationRecord)
		}{
			{"original workload scope removed", func(_ *FoundationGrant, r *FoundationRecord) {
				r.ResourceIDs = map[string]string{"workload_compartment": "ocid1.compartment.oc1..foreign"}
			}},
			{"original role removed", func(g *FoundationGrant, _ *FoundationRecord) { g.WorkerProfiles = nil }},
			{"cleanup clause revoked", func(g *FoundationGrant, _ *FoundationRecord) {
				for i := range g.WorkerProfiles {
					g.WorkerProfiles[i].CapacityJournal = WorkerCapacityJournal{}
				}
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				candidate, changed := successor, current
				candidate.WorkerProfiles = append([]WorkerProfile(nil), successor.WorkerProfiles...)
				test.change(&candidate, &changed)
				*grant = candidate
				sign()
				changed.GrantSHA256 = reader.home.GrantSHA256
				wire, err := json.Marshal(changed, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				publish(foundationObjectPrefix+record.Cell+".json", wire)
				if _, err := resolver.PoolLifecycle(ctx, current.Cell, child.OperationID, child.InstanceID); err == nil {
					t.Fatal("current signed grant no longer independently authorizes this exact original cleanup scope")
				}
			})
		}
	})
	changed := record
	changed.cloneCapacity()
	configuration := changed.CapacityPools[poolID].Configurations[configurationID]
	configuration.ProfileSHA256 = strings.Repeat("1", 64)
	changed.CapacityPools[poolID].Configurations[configurationID] = configuration
	wire, err := json.Marshal(changed, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	publish(foundationObjectPrefix+record.Cell+".json", wire)
	if err := proof.Revalidate(ctx); err == nil {
		t.Fatal("role and shape substituted for exact original signed profile")
	}
}
