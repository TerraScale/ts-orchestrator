package budget

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestSignedSpendingAuthorityDeniesCanceledObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	writer, _, epoch := reservationStoreHome(t, ctx)
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
	const tenancy = "ocid1.tenancy.oc1..integration"
	const parent = "ocid1.compartment.oc1..parent"
	const shared = "ocid1.compartment.oc1..shared"
	grant := region.FoundationGrant{InstallationID: installation, SchemaVersion: 1, Generation: 1, TenancyID: tenancy,
		ParentCompartmentID: parent, SharedCompartmentID: shared, Currency: "USD", MonthlyLimitMinor: 10000, CleanupOwner: "integration",
		Regions: []region.FoundationIntent{{Generation: 1, Plan: map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy,
			"parent_compartment_id": parent, "shared_compartment_id": shared, "resource_ids": map[string]any{
				"control_compartment": "ocid1.compartment.oc1..control", "network_compartment": "ocid1.compartment.oc1..network", "workload_compartment": "ocid1.compartment.oc1..workload"}}}}}
	scopeDigest, err := region.FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	slot := region.BootstrapSlotIntent{SlotID: region.BootstrapSlotID(installation, "GRU", "controller", "controller-a"), Cell: "GRU", Role: "controller", Slot: "controller-a",
		CompartmentID: "ocid1.compartment.oc1..control", ProfileSHA256: strings.Repeat("d", 64), RecipeSHA256: strings.Repeat("e", 64),
		Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyLimitMinor: 2000}
	grant.InfrastructureSpend = &region.InfrastructureSpendIntent{BudgetID: entityid.New(), Currency: "USD", MonthlyLimitMinor: 9000, ScopeSHA256: scopeDigest,
		Bootstrap: &region.BootstrapSpendingIntent{ReservedMinor: 2000, Slots: []region.BootstrapSlotIntent{slot}}}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "foundation", Slot: cluster}, now.Add(-time.Minute), now.Add(30*time.Minute), private)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	grantDigest := sha256.Sum256(grantWire)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" || !strings.HasSuffix(r.URL.Path, "/bootstrap/foundation-scope-v1.json") {
			t.Errorf("unexpected or unsigned grant read: %s %s", r.Method, r.URL.Path)
			http.Error(w, "invalid grant request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(grantWire)
	}))
	defer store.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..integration", "sa-saopaulo-1", "integration",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	objects.Host = store.URL
	domain := bootstrap.StorageDomain{Namespace: "integration", LedgerBucket: "ledger", HeadBucket: "heads", Prefix: "bootstrap",
		LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head"}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerKeyID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublicWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	var capabilities []trust.Capability
	for _, name := range []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"} {
		capabilities = append(capabilities, trust.Capability{Domain: name, DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "controller", Slots: []string{"controller-a"}, Actions: []string{"sign"}})
	}
	ledgerGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: ledgerKeyID, SubjectPublicKey: ledgerPublicWire, Capabilities: capabilities}, now.Add(-2*time.Minute), now.Add(2*time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	ledgerWire, err := trust.EncodeEnvelope(ledgerGrant)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 1, BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion, DeploymentID: deployment, Environment: "production", ClusterID: cluster,
		Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, ControllerSlots: []string{"controller-a"}, LedgerDelegationWire: ledgerWire,
		InitialRegionIntentGeneration: 1, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]), InitialRegionIntentWire: intentWire,
		FoundationScope: &bootstrap.FoundationScope{InstallationID: installation, DeploymentID: deployment, ClusterID: cluster, TenancyID: tenancy, OCIRegion: "sa-saopaulo-1", StorageDomain: domain, GrantGeneration: 1, GrantSHA256: hex.EncodeToString(grantDigest[:])}}
	signedAnchor, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(signedAnchor, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := region.NewSignedFootprint(&objects, verifiedAnchor, roots, tenancy)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signed.InfrastructureSpend(ctx)
	if err != nil || !proof.ValidAt(time.Now()) {
		t.Fatalf("signed infrastructure authority was not verified: %v", err)
	}
	bootstrapDigest := proof.BootstrapDigest()
	if proof.BootstrapReservedMinor() != 2000 || !reservationDigest.MatchString(bootstrapDigest) || proof.Generation() != 1 || proof.InstallationID() != installation || proof.PhysicalScopeDigest() != proof.ScopeDigest() || proof.BindingDigest() != "" {
		t.Fatalf("signed bootstrap slice was not sealed: reserve=%d digest=%q", proof.BootstrapReservedMinor(), bootstrapDigest)
	}
	allocation, err := signed.BootstrapAllocation(ctx, slot.SlotID)
	if err != nil || !allocation.IsVerified() || allocation.Slot() != slot || allocation.SignedSlot() != slot || allocation.OperationID() != region.BootstrapOperationID(installation, slot.SlotID) {
		t.Fatalf("signed bootstrap slot was not verified: allocation=%+v err=%v", allocation, err)
	}
	if available, err := bootstrapLimit(Capacity{}, proof, 9000); err != nil || available != 7000 {
		t.Fatalf("ordinary spending did not withhold the entire signed slice: available=%d err=%v", available, err)
	}
	if available, err := bootstrapLimit(Capacity{}, proof, 1000); err == nil || available != 0 {
		t.Fatalf("tenant tightening below the bootstrap slice did not fail closed: available=%d err=%v", available, err)
	}
	inventory, err := capacityinventory.New(factory)
	if err != nil {
		t.Fatal(err)
	}
	observationCtx, stop := context.WithCancel(ctx)
	stop()
	snapshot, err := inventory.Read(observationCtx, proof.Footprint())
	if err != nil || len(snapshot.Pending) == 0 {
		t.Fatalf("canceled SDK observation must retain unknown cost: pending=%v err=%v", snapshot.Pending, err)
	}
	// This validates receipt predicates only; incomplete accounting below still
	// prevents this fixture from authorizing an attach or a new purchase.
	at := now.Add(-5 * time.Minute)
	original := capacityledger.Quote{ScopeSHA256: proof.PhysicalScopeDigest(), Cell: "GRU", CompartmentID: "ocid1.compartment.oc1..workload",
		Shape: "VM.Standard.A1.Flex", Currency: "USD", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyCents: 300, IssuedAt: at, ExpiresAt: at.Add(2 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: 0}, {SKU: "B91962", PerUnit: 0}, {SKU: "B93297", PerUnit: 3.0 / (2 * 744)}, {SKU: "B93298", PerUnit: 0}}}
	receipt := Reservation{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64), Cell: original.Cell, CompartmentID: original.CompartmentID,
		Shape: original.Shape, OCPUs: original.OCPUs, MemoryGB: original.MemoryGB, BootGB: original.BootGB, MonthlyCents: original.MonthlyCents,
		InfrastructureBudgetID: proof.BudgetID(), GrantSHA256: proof.GrantDigest(), ScopeSHA256: proof.ScopeDigest(), ResolvedScopeSHA256: proof.PhysicalScopeDigest(),
		BindingSHA256: proof.BindingDigest(), GrantGeneration: proof.Generation(), QuoteSHA256: original.SHA256(), OriginalQuote: new(original),
		Currency: proof.Currency(), TenancyID: tenancy, IssuedAt: at.Add(time.Second), LaunchExpiresAt: at.Add(time.Minute)}
	if err := sameOriginalReservation(receipt, receipt); err != nil {
		t.Fatal(err)
	}
	if err := existingReservation(receipt, "", proof, time.Now()); err != nil {
		t.Fatalf("existing commitment depends on expired launch or quote: %v", err)
	}
	if err := currentReservation(receipt, "", proof, time.Now()); err == nil {
		t.Fatal("existing-child validation renewed expired launch permission")
	}
	for _, mutate := range []func(*Reservation){
		func(r *Reservation) { r.RetiredAt = now },
		func(r *Reservation) { r.GrantSHA256 = strings.Repeat("f", 64) },
		func(r *Reservation) { r.GrantGeneration++ },
		func(r *Reservation) { r.CompartmentID = "ocid1.compartment.oc1..foreign" },
		func(r *Reservation) { r.BudgetID = entityid.New() },
	} {
		changed := receipt
		mutate(&changed)
		if err := existingReservation(changed, "", proof, time.Now()); err == nil {
			t.Fatalf("existing commitment accepted changed authority or retirement: %+v", changed)
		}
	}
	changed := receipt
	changed.BindingSHA256 = strings.Repeat("d", 64)
	if err := sameOriginalReservation(receipt, changed); err == nil {
		t.Fatal("existing commitment accepted a replaced immutable origin binding")
	}
	if err := RevalidateExisting(ctx, &writer.Reader, receipt, proof, snapshot, time.Now()); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("existing commitment bypassed complete accounting: %v", err)
	}
	headroom, err := InfrastructureHeadroom(ctx, &writer.Reader, proof, snapshot, entityid.New(), time.Now())
	if err == nil || headroom != 0 || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("signed authority with canceled observation admitted capacity: headroom=%d err=%v", headroom, err)
	}
	if _, found, err := ReadCapacity(ctx, &writer.Reader); err != nil || found {
		t.Fatalf("denied observation created a commitment: found=%v err=%v", found, err)
	}
	demand := []Region{{Cell: "gru", Nodes: 1, Want: 2, Pressure: .9, At: time.Now(), NodeMonthlyCents: 1, ProjectedCents: 0, Currency: "USD"}}
	stale := Allocate(nil, demand, nil, time.Now())
	if err := WriteCapacity(ctx, writer, epoch, stale); err != nil {
		t.Fatal(err)
	}
	held, err := AllocateInfrastructure(ctx, &writer.Reader, proof, snapshot, demand, nil, time.Now())
	if err == nil || !strings.Contains(err.Error(), "incomplete") || held.State != StateNone || held.Regions[0].Allowance != 1 || !held.Regions[0].GrantedAt.IsZero() {
		t.Fatalf("signed planning with canceled costs trusted regional prices: capacity=%+v err=%v", held, err)
	}
	if err := WriteCapacity(ctx, writer, epoch, held); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.Regions[0].Allowance != 1 || len(persisted.Reservations) != 0 || persisted.BootstrapReservedCents != 2000 || persisted.BootstrapSHA256 != bootstrapDigest {
		t.Fatalf("failed planning did not persist a hold: %+v found=%v err=%v", persisted, found, err)
	}
	if err := WriteCapacity(ctx, writer, epoch, stale); err != nil {
		t.Fatal(err)
	}
	persisted, found, err = ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.BootstrapReservedCents != 2000 || persisted.BootstrapSHA256 != bootstrapDigest {
		t.Fatalf("stale periodic write refunded signed bootstrap slice: %+v found=%v err=%v", persisted, found, err)
	}
	for _, current := range []region.VerifiedInfrastructureSpend{proof, {}} {
		if available, err := bootstrapLimit(persisted, current, 1000); err == nil || available != 0 {
			t.Fatalf("tenant tightening or missing grant refunded pinned bootstrap slice: available=%d err=%v", available, err)
		}
	}
	drifted := persisted
	drifted.BootstrapSHA256 = strings.Repeat("f", 64)
	if available, err := bootstrapLimit(drifted, proof, 9000); err == nil || available != 0 {
		t.Fatalf("changed allocation admitted ordinary spending: available=%d err=%v", available, err)
	}
	monthly := Budget{Schema: Schema, ID: entityid.New(), MonthlyCapCents: 1000, Currency: "USD", SetBy: "integration", SetAt: time.Now()}
	if err := WriteBudget(ctx, writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	held, err = AllocateInfrastructure(ctx, &writer.Reader, proof, snapshot, demand, &persisted, time.Now())
	if err == nil || held.Regions[0].Allowance != 1 || len(held.Reservations) != 0 {
		t.Fatalf("tenant budget bypassed incomplete infrastructure evidence: %+v err=%v", held, err)
	}
	held, err = AllocateInfrastructure(ctx, &writer.Reader, region.VerifiedInfrastructureSpend{}, capacityinventory.Snapshot{}, demand, &persisted, time.Now())
	if err == nil || !strings.Contains(err.Error(), "signed infrastructure") || held.State != StateNone || held.Regions[0].Allowance != 1 {
		t.Fatalf("tenant budget replaced missing signed spending authority: %+v err=%v", held, err)
	}
	for _, current := range []region.VerifiedInfrastructureSpend{{}, proof} {
		held, err := AllocateInfrastructure(ctx, &writer.Reader, current, snapshot, demand, &persisted, proof.ExpiresAt().Add(time.Second))
		if err == nil || held.BootstrapReservedCents != 2000 || held.BootstrapSHA256 != bootstrapDigest {
			t.Fatalf("missing or expired authority released bootstrap slice: %+v err=%v", held, err)
		}
		if err := WriteCapacity(ctx, writer, epoch, held); err != nil {
			t.Fatal(err)
		}
		stored, found, err := ReadCapacity(ctx, &writer.Reader)
		if err != nil || !found || stored.BootstrapReservedCents != 2000 || stored.BootstrapSHA256 != bootstrapDigest {
			t.Fatalf("held periodic write released bootstrap slice: %+v found=%v err=%v", stored, found, err)
		}
	}
	for _, scenario := range []struct {
		name    string
		mutate  func(*region.BootstrapSpendingIntent)
		valid   bool
		logical bool
	}{
		{"increased-slice", func(b *region.BootstrapSpendingIntent) { b.ReservedMinor = 2500 }, true, false},
		{"logical-unbound", func(b *region.BootstrapSpendingIntent) {}, false, true},
		{"zero-geometry", func(b *region.BootstrapSpendingIntent) { b.Slots[0].OCPUs = 0 }, false, false},
		{"duplicate-slot", func(b *region.BootstrapSpendingIntent) { b.Slots = append(b.Slots, b.Slots[0]) }, false, false},
		{"slot-over-slice", func(b *region.BootstrapSpendingIntent) { b.Slots[0].MonthlyLimitMinor = 2001 }, false, false},
		{"slice-over-ceiling", func(b *region.BootstrapSpendingIntent) { b.ReservedMinor = 9001 }, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			changed := grant
			spending := *grant.InfrastructureSpend
			allocation := *spending.Bootstrap
			allocation.Slots = slices.Clone(allocation.Slots)
			scenario.mutate(&allocation)
			spending.Bootstrap, changed.InfrastructureSpend = &allocation, &spending
			if scenario.logical {
				changed.SchemaVersion = 2
				changed.Regions = slices.Clone(changed.Regions)
				changed.Regions[0].Plan = map[string]any{"cell": "GRU", "region": "sa-saopaulo-1", "tenancy_id": tenancy,
					"parent_compartment_id": parent, "shared_compartment_id": shared, "resource_ids": map[string]any{}}
				ref, err := region.FoundationResourceReference("GRU", "control_compartment")
				if err != nil {
					t.Fatal(err)
				}
				allocation.Slots[0].CompartmentID = ref
				spending.ScopeSHA256, err = region.FoundationInfrastructureScopeDigest(changed)
				if err != nil || spending.ScopeSHA256 == proof.ScopeDigest() {
					t.Fatalf("logical producer did not retain a distinct canonical authority scope: digest=%q err=%v", spending.ScopeSHA256, err)
				}
				if err := region.ValidateBootstrapSpending(changed); err != nil {
					t.Fatalf("canonical logical bootstrap role was rejected before signing: %v", err)
				}
			}
			payload, err := trust.EncodePayload(changed)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: deployment, Cell: "GRU", Environment: "production", Role: "foundation", Slot: cluster}, now.Add(-time.Minute), now.Add(30*time.Minute), private)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := trust.EncodeEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			variantStore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wire) }))
			defer variantStore.Close()
			variantObjects, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			variantObjects.Host = variantStore.URL
			variantAnchor := anchor
			home := *anchor.FoundationScope
			digest := sha256.Sum256(wire)
			home.GrantSHA256, variantAnchor.FoundationScope = hex.EncodeToString(digest[:]), &home
			signedAnchor, err := bootstrap.SignBootstrapAnchor(variantAnchor, now.Add(-time.Minute), now.Add(time.Hour), private)
			if err != nil {
				t.Fatal(err)
			}
			verifiedAnchor, err := bootstrap.VerifyBootstrapAnchor(signedAnchor, roots, bootstrap.BootstrapAnchorExpectation{DeploymentID: deployment, Environment: "production", Cell: oci.RegionGRU}, now, bootstrap.BootstrapAnchorTrustPolicy())
			if err != nil {
				t.Fatal(err)
			}
			reader, err := region.NewSignedFootprint(&variantObjects, verifiedAnchor, roots, tenancy)
			if err != nil {
				t.Fatal(err)
			}
			variant, err := reader.InfrastructureSpend(ctx)
			if !scenario.valid {
				if scenario.logical && (err == nil || !strings.Contains(err.Error(), "independently verified foundation bindings")) {
					t.Fatalf("logical scope did not reach the authenticated physical-binding boundary: %v", err)
				}
				if err == nil || variant.IsVerified() {
					t.Fatal("invalid root-signed bootstrap allocation became spending authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			held, err := AllocateInfrastructure(ctx, &writer.Reader, variant, snapshot, demand, &persisted, time.Now())
			if err == nil || held.BootstrapReservedCents != 2500 || held.BootstrapSHA256 != bootstrapDigest {
				t.Fatalf("changed grant refunded the larger slice or replaced the original identity: %+v err=%v", held, err)
			}
			if err := WriteCapacity(ctx, writer, epoch, held); err != nil {
				t.Fatal(err)
			}
			stored, found, err := ReadCapacity(ctx, &writer.Reader)
			if err != nil || !found || stored.BootstrapReservedCents != 2500 || stored.BootstrapSHA256 != bootstrapDigest {
				t.Fatalf("changed slice was not retained through home CAS: %+v found=%v err=%v", stored, found, err)
			}
			if available, err := bootstrapLimit(stored, variant, 9000); err == nil || available != 0 {
				t.Fatalf("changed grant admitted ordinary spending: available=%d err=%v", available, err)
			}
		})
	}

}

// This exercises persisted commitments, not spending admission: no fixture can
// manufacture the complete accounting evidence the production producer lacks.
func TestReservationLedgerSurvivesPeriodicWritesThroughHomeCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	writer, concurrent, epoch := reservationStoreHome(t, ctx)
	now := time.Now().UTC()
	monthly := Budget{Schema: Schema, ID: entityid.New(), MonthlyCapCents: 1000, Currency: "USD", SetBy: "integration", SetAt: now}
	if err := WriteBudget(ctx, writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	regions := []Region{
		{Cell: "gru", Nodes: 1, Want: 2, Pressure: .9, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
		{Cell: "sfo", Nodes: 1, Want: 2, Pressure: .5, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
	}
	allocated := Allocate(&monthly, regions, nil, now)
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.ProjectedCents != 800 || persisted.Headroom() != 200 || persisted.State != StateWarn {
		t.Fatalf("new grants must count in persisted headroom: %+v, found=%v, err=%v", persisted, found, err)
	}
	seed := Reservation{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64), Cell: "gru", CompartmentID: "ocid1.compartment.oc1..integration",
		Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyCents: 300, BudgetID: monthly.ID,
		InfrastructureBudgetID: entityid.New(), GrantSHA256: strings.Repeat("b", 64), ScopeSHA256: strings.Repeat("c", 64),
		IssuedAt: now.Add(-time.Hour), LaunchExpiresAt: now.Add(-30 * time.Minute)}
	appendCommitment := func(reservation Reservation) error {
		for range 32 {
			current, found, err := ReadCapacity(ctx, &concurrent.Reader)
			if err != nil || !found {
				return errors.Join(err, errors.New("capacity ledger unavailable"))
			}
			expected, err := current.Encode()
			if err != nil {
				return err
			}
			current.Reservations = append(current.Reservations, reservation)
			slices.SortFunc(current.Reservations, func(a, b Reservation) int { return cmp.Compare(a.OperationID, b.OperationID) })
			var commitments uint64
			for _, receipt := range current.Reservations {
				commitments += receipt.MonthlyCents
			}
			current.Spending = &InfrastructureSpending{InfrastructureBudgetID: seed.InfrastructureBudgetID, GrantSHA256: seed.GrantSHA256, ScopeSHA256: seed.ScopeSHA256,
				Currency: "USD", MonthlyLimitCents: 1000, ProjectedCents: commitments, ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-59 * time.Minute)}
			payload, err := current.Encode()
			if err != nil {
				return err
			}
			_, err = concurrent.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, func(stored []byte) error {
				if !sameCapacity(stored, expected) {
					return globalcontrol.ErrConflict
				}
				return nil
			})
			if errors.Is(err, globalcontrol.ErrConflict) {
				continue
			}
			return err
		}
		return globalcontrol.ErrConflict
	}
	if err := appendCommitment(seed); err != nil {
		t.Fatal(err)
	}
	// The caller's stale allocation predates the stored, already-expired receipt.
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	second := seed
	second.OperationID = entityid.New()
	second.GrantGeneration, second.ResolvedScopeSHA256, second.BindingSHA256, second.QuoteSHA256 = 1, strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)
	second.Currency, second.TenancyID = "USD", "ocid1.tenancy.oc1..integration"
	original := capacityledger.Quote{ScopeSHA256: second.ResolvedScopeSHA256, Cell: second.Cell, CompartmentID: second.CompartmentID,
		Shape: second.Shape, Currency: second.Currency, OCPUs: second.OCPUs, MemoryGB: second.MemoryGB, BootGB: second.BootGB,
		MonthlyCents: second.MonthlyCents, IssuedAt: second.IssuedAt, ExpiresAt: second.IssuedAt.Add(2 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: 0}, {SKU: "B91962", PerUnit: 0}, {SKU: "B93297", PerUnit: 3.0 / (2 * 744)}, {SKU: "B93298", PerUnit: 0}}}
	second.OriginalQuote, second.QuoteSHA256 = new(original), original.SHA256()
	go func() {
		<-start
		results <- appendCommitment(second)
	}()
	go func() {
		<-start
		for range 16 {
			if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	persisted, found, err = ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || len(persisted.Reservations) != 2 {
		t.Fatalf("concurrent periodic write erased commitments: %+v, found=%v, err=%v", persisted, found, err)
	}
	for _, candidate := range []Capacity{
		Allocate(nil, regions, &persisted, now.Add(2*time.Hour)),
		Allocate(&monthly, regions, &persisted, now.Add(StatusMaxAge+time.Minute)),
	} {
		if err := WriteCapacity(ctx, writer, epoch, candidate); err != nil {
			t.Fatal(err)
		}
		stored, found, err := ReadCapacity(ctx, &writer.Reader)
		if err != nil || !found || len(stored.Reservations) != 2 || stored.Spending == nil || stored.Spending.ProjectedCents != 600 {
			t.Fatalf("unknown budget/spend or expired launch released commitments: %+v, found=%v, err=%v", stored, found, err)
		}
		for _, receipt := range stored.Reservations {
			if receipt.OperationID == second.OperationID && (receipt.GrantGeneration != second.GrantGeneration || receipt.ResolvedScopeSHA256 != second.ResolvedScopeSHA256 || receipt.BindingSHA256 != second.BindingSHA256 || receipt.QuoteSHA256 != second.QuoteSHA256 || receipt.Currency != second.Currency || receipt.TenancyID != second.TenancyID) {
				t.Fatalf("periodic write replaced original authority or quote receipt metadata: %+v", receipt)
			}
			if receipt.OperationID == second.OperationID {
				financial, err := receipt.FinancialReceipt()
				if err != nil || financial.QuoteSHA256 != original.SHA256() || financial.Quote.Prices[2].PerUnit != original.Prices[2].PerUnit {
					t.Fatalf("periodic write lost original expired tariffs: %+v err=%v", financial, err)
				}
			}
			if receipt.MonthlyCents != 300 || !receipt.RetiredAt.IsZero() || len(receipt.ResourceIDs) != 0 {
				t.Fatalf("unknown outcome was changed or retired: %+v", receipt)
			}
		}
	}
	storedBudget, found, err := ReadBudget(ctx, &concurrent.Reader)
	if err != nil || !found || storedBudget.Schema != monthly.Schema || storedBudget.ID != monthly.ID ||
		storedBudget.MonthlyCapCents != monthly.MonthlyCapCents || storedBudget.Currency != monthly.Currency ||
		storedBudget.SetBy != monthly.SetBy || !storedBudget.SetAt.Equal(monthly.SetAt) {
		t.Fatalf("committed monthly budget = %+v, found=%v, err=%v", storedBudget, found, err)
	}
	budgetDocument, err := concurrent.Document(ctx, globalcontrol.KindBudget, protocol.GlobalScope)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Budget){
		"schema":         func(b *Budget) { b.Schema = 2 },
		"bad ULID":       func(b *Budget) { b.ID = "not-a-ulid" },
		"zero cap":       func(b *Budget) { b.MonthlyCapCents = 0 },
		"cap too large":  func(b *Budget) { b.MonthlyCapCents = 1_000_000_000_001 },
		"lower currency": func(b *Budget) { b.Currency = "brl" },
		"short currency": func(b *Budget) { b.Currency = "BR" },
		"long currency":  func(b *Budget) { b.Currency = "BRLX" },
		"empty set_by":   func(b *Budget) { b.SetBy = "" },
		"control set_by": func(b *Budget) { b.SetBy = "mariogk\n@terrascale.tech" },
		"long set_by":    func(b *Budget) { b.SetBy = strings.Repeat("a", 255) },
		"zero set_at":    func(b *Budget) { b.SetAt = time.Time{} },
	} {
		t.Run("budget/"+name, func(t *testing.T) {
			b := testBudget()
			mutate(&b)
			if err := WriteBudget(ctx, writer, epoch, b); err == nil {
				t.Fatal("malformed budget was committed")
			}
			stored, found, err := ReadBudget(ctx, &concurrent.Reader)
			if err != nil || !found || stored.Schema != monthly.Schema || stored.ID != monthly.ID ||
				stored.MonthlyCapCents != monthly.MonthlyCapCents || stored.Currency != monthly.Currency ||
				stored.SetBy != monthly.SetBy || !stored.SetAt.Equal(monthly.SetAt) {
				t.Fatalf("rejected budget changed committed fields: %+v, found=%v, err=%v", stored, found, err)
			}
			document, err := concurrent.Document(ctx, globalcontrol.KindBudget, protocol.GlobalScope)
			if err != nil || string(document.Payload) != string(budgetDocument.Payload) ||
				document.Generation != budgetDocument.Generation || document.Epoch != budgetDocument.Epoch || document.Sequence != budgetDocument.Sequence {
				t.Fatalf("rejected budget changed committed record: %+v, err=%v", document, err)
			}
		})
	}

	want := testBudget()
	encoded, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindBudget, protocol.GlobalScope, encoded, nil); err != nil {
		t.Fatal(err)
	}
	got, found, err := ReadBudget(ctx, &concurrent.Reader)
	if err != nil || !found || got.ID != want.ID || got.MonthlyCapCents != want.MonthlyCapCents || got.Currency != want.Currency ||
		got.SetBy != want.SetBy || !got.SetAt.Equal(want.SetAt) || got.Schema != want.Schema {
		t.Fatalf("stored round trip = %+v, found=%v, err=%v; want %+v", got, found, err, want)
	}
	again, err := got.Encode()
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatalf("stored re-encode = %s, %v; want %s", again, err, encoded)
	}

	id := entityid.New()
	valid := `"schema":1,"id":"` + id + `","monthly_cap_cents":1,"currency":"BRL","set_by":"x","set_at":"2026-10-10T20:00:00Z"`
	if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindBudget, protocol.GlobalScope, []byte("{"+valid+"}"), nil); err != nil {
		t.Fatal(err)
	}
	got, found, err = ReadBudget(ctx, &concurrent.Reader)
	if err != nil || !found || got.Schema != 1 || got.ID != id || got.MonthlyCapCents != 1 || got.Currency != "BRL" ||
		got.SetBy != "x" || !got.SetAt.Equal(time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)) {
		t.Fatalf("stored valid raw budget = %+v, found=%v, err=%v", got, found, err)
	}
	for _, hostile := range []struct {
		name    string
		payload []byte
	}{
		{"unknown field", []byte("{" + valid + `,"extra":true}`)},
		{"invalid currency", []byte("{" + strings.Replace(valid, `"currency":"BRL"`, `"currency":"brl"`, 1) + "}")},
		{"garbage", []byte("not json")},
	} {
		if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindBudget, protocol.GlobalScope, hostile.payload, nil); err != nil {
			t.Fatalf("store %s: %v", hostile.name, err)
		}
		got, found, err := ReadBudget(ctx, &concurrent.Reader)
		if err == nil || found || got != (Budget{}) {
			t.Fatalf("stored %s decoded = %+v, found=%v, err=%v", hostile.name, got, found, err)
		}
	}

	if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindBudget, protocol.GlobalScope, budgetDocument.Payload, nil); err != nil {
		t.Fatal(err)
	}
	restoredDocument, err := concurrent.Document(ctx, globalcontrol.KindBudget, protocol.GlobalScope)
	if err != nil || !bytes.Equal(restoredDocument.Payload, budgetDocument.Payload) {
		t.Fatalf("restored monthly payload = %s, err=%v; want %s", restoredDocument.Payload, err, budgetDocument.Payload)
	}
	storedBudget, found, err = ReadBudget(ctx, &concurrent.Reader)
	if err != nil || !found || storedBudget.Schema != monthly.Schema || storedBudget.ID != monthly.ID ||
		storedBudget.MonthlyCapCents != monthly.MonthlyCapCents || storedBudget.Currency != monthly.Currency ||
		storedBudget.SetBy != monthly.SetBy || !storedBudget.SetAt.Equal(monthly.SetAt) {
		t.Fatalf("restored monthly budget = %+v, found=%v, err=%v", storedBudget, found, err)
	}

	capacityDocument, err := concurrent.Document(ctx, globalcontrol.KindCapacity, protocol.GlobalScope)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := ReadCapacity(ctx, &concurrent.Reader); err != nil || !found {
		t.Fatalf("capacity baseline = found=%v, err=%v", found, err)
	}
	priorCapacityDocument := capacityDocument
	for _, hostile := range []struct {
		name    string
		payload string
	}{
		{"not json", "{"},
		{"fails validation", `{"schema":1}`},
	} {
		t.Run("capacity/"+hostile.name, func(t *testing.T) {
			payload := []byte(hostile.payload)
			if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, nil); err != nil {
				t.Fatalf("store %s capacity: %v", hostile.name, err)
			}
			document, err := concurrent.Document(ctx, globalcontrol.KindCapacity, protocol.GlobalScope)
			if err != nil || !bytes.Equal(document.Payload, payload) ||
				document.Generation <= priorCapacityDocument.Generation || document.Sequence <= priorCapacityDocument.Sequence {
				t.Fatalf("stored %s capacity = %+v, err=%v; prior=%+v", hostile.name, document, err, priorCapacityDocument)
			}
			if _, _, err := ReadCapacity(ctx, &concurrent.Reader); !errors.Is(err, ErrInvalidCapacity) {
				t.Fatalf("stored %s capacity error = %v, want ErrInvalidCapacity", hostile.name, err)
			}
			priorCapacityDocument = document
		})
	}
	if _, err := writer.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, capacityDocument.Payload, nil); err != nil {
		t.Fatal(err)
	}
	restoredCapacityDocument, err := concurrent.Document(ctx, globalcontrol.KindCapacity, protocol.GlobalScope)
	if err != nil || !bytes.Equal(restoredCapacityDocument.Payload, capacityDocument.Payload) ||
		restoredCapacityDocument.Generation <= priorCapacityDocument.Generation || restoredCapacityDocument.Sequence <= priorCapacityDocument.Sequence {
		t.Fatalf("restored capacity = %+v, err=%v; prior=%+v", restoredCapacityDocument, err, priorCapacityDocument)
	}
	if _, found, err := ReadCapacity(ctx, &concurrent.Reader); err != nil || !found {
		t.Fatalf("restored capacity = found=%v, err=%v", found, err)
	}
}

func reservationStoreHome(t *testing.T, ctx context.Context) (*globalcontrol.Writer, *globalcontrol.Writer, uint64) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: protocol.GlobalScope, CandidateID: entityid.New(), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		select {
		case <-ctx.Done():
			t.Fatal("global authority never became ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	concurrent, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return writer, concurrent, runtime.Current().Epoch
}
