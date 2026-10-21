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
	// json/v2 refuses opaque proofs; only the zero value can be fabricated.
	if encoded, err := json.Marshal(proof); err == nil {
		t.Fatalf("opaque proof serialized: %s", encoded)
	}
	var fabricated VerifiedPoolLifecycle
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
