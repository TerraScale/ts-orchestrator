package rootcapacity

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// This is only a serialized-selector fixture. Its hand-seeded receipts and
// outcomes cannot enter the signed SDK backend or mint runtime admission.
func retirementPreparationFixture(t *testing.T) (region.FoundationRecord, region.PoolChildRecord) {
	t.Helper()
	at := time.Now().UTC().Add(-5 * time.Minute)
	quote := capacityledger.Quote{ScopeSHA256: strings.Repeat("d", 64), Cell: "GRU", CompartmentID: "ocid1.compartment.oc1..workload", Shape: "VM.Standard.A1.Flex",
		Currency: "USD", OCPUs: 2, MemoryGB: 12, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	var known bool
	quote.MonthlyCents, known = ocicost.NodeMonthlyCents(quote.Prices, quote.Shape, quote.OCPUs, quote.MemoryGB, quote.BootGB)
	if !known {
		t.Fatal("selection fixture has no historical payable quote")
	}
	child := region.PoolChildRecord{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64), PoolID: "ocid1.instancepool.oc1..original",
		ConfigurationID: "ocid1.instanceconfiguration.oc1..original", InstanceID: "ocid1.instance.oc1..original", BootVolumeID: "ocid1.bootvolume.oc1..original",
		BootAttachmentID: "ocid1.bootvolumeattachment.oc1..original", BirthEpoch: 7, Stage: region.PoolChildReady, Node: "ts-gru-4",
		BornAt: at.Add(3 * time.Second), ReadyAt: at.Add(6 * time.Second),
		Launch: &region.PoolWireRecord{RequestSHA256: strings.Repeat("e", 64), FirstAttemptAt: at.Add(2 * time.Second), AcceptedAt: at.Add(3 * time.Second)},
		Attach: &region.PoolWireRecord{AcceptedAt: at.Add(4 * time.Second), WorkCompletedAt: at.Add(5 * time.Second)}}
	receipt := capacityledger.Receipt{OperationID: child.OperationID, RecipeSHA256: child.RecipeSHA256, GrantSHA256: strings.Repeat("b", 64), GrantGeneration: 1,
		LogicalScopeSHA256: quote.ScopeSHA256, ResolvedScopeSHA256: quote.ScopeSHA256, TenancyID: "ocid1.tenancy.oc1..original",
		QuoteSHA256: quote.SHA256(), ReservedAt: at.Add(time.Second), Quote: quote}
	record := region.FoundationRecord{Cell: quote.Cell, TenancyID: receipt.TenancyID, GrantSHA256: strings.Repeat("c", 64), Generation: 2,
		PoolChildren: map[string]region.PoolChildRecord{child.OperationID: child}, CapacityPools: map[string]region.PoolResourceRecord{
			child.PoolID: {PoolID: child.PoolID, CompartmentID: quote.CompartmentID, Shape: quote.Shape}},
		CapacityLedger: &capacityledger.Ledger{Version: capacityledger.Version, Hosts: []capacityledger.Host{{Receipt: receipt,
			InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID, BornAt: child.BornAt,
			RequestSHA256: child.Launch.RequestSHA256, StartedAt: child.Launch.FirstAttemptAt}}}}
	return record, child
}

func TestRetirementPreparationSelectsUniqueOriginalBirthWithoutCurrentPurchase(t *testing.T) {
	record, child := retirementPreparationFixture(t)
	selected, receipt, err := retirementPreparationBirth(record, child.InstanceID)
	if err != nil || selected.OperationID != child.OperationID || receipt.OperationID != child.OperationID ||
		receipt.GrantSHA256 == record.GrantSHA256 || receipt.GrantGeneration == record.Generation || selected.BirthEpoch != child.BirthEpoch {
		t.Fatalf("retirement selection lost the immutable original birth across current grant changes: %v", err)
	}
	if !time.Now().After(receipt.Quote.ExpiresAt) {
		t.Fatal("selection fixture did not exercise expired purchase permission")
	}
	if _, _, err := retirementPreparationBirth(record, "ocid1.instance.oc1..foreign"); err == nil {
		t.Fatal("descriptive selector adopted an unknown provider instance")
	}
	for _, test := range []struct {
		name   string
		change func(*region.FoundationRecord, *region.PoolChildRecord)
	}{
		{"original acceptance absent", func(_ *region.FoundationRecord, c *region.PoolChildRecord) { c.Launch.AcceptedAt = time.Time{} }},
		{"original attachment incomplete", func(_ *region.FoundationRecord, c *region.PoolChildRecord) { c.Attach.WorkCompletedAt = time.Time{} }},
		{"original node foreign", func(_ *region.FoundationRecord, c *region.PoolChildRecord) { c.Node = "ts-fra-4" }},
		{"original birth epoch absent", func(_ *region.FoundationRecord, c *region.PoolChildRecord) { c.BirthEpoch = 0 }},
		{"retirement already underway", func(_ *region.FoundationRecord, c *region.PoolChildRecord) { c.Stage = region.PoolChildTerminating }},
		{"original boot replaced", func(r *region.FoundationRecord, _ *region.PoolChildRecord) {
			r.CapacityLedger.Hosts[0].BootVolumeID = "ocid1.bootvolume.oc1..foreign"
		}},
		{"original request replaced", func(r *region.FoundationRecord, _ *region.PoolChildRecord) {
			r.CapacityLedger.Hosts[0].RequestSHA256 = strings.Repeat("f", 64)
		}},
		{"original liability retired", func(r *region.FoundationRecord, _ *region.PoolChildRecord) {
			r.CapacityLedger.Hosts[0].InstanceRetiredAt = time.Now()
		}},
		{"ambiguous original liability", func(r *region.FoundationRecord, _ *region.PoolChildRecord) {
			r.CapacityLedger.Hosts = append(r.CapacityLedger.Hosts, r.CapacityLedger.Hosts[0])
		}},
		{"ambiguous original birth", func(r *region.FoundationRecord, c *region.PoolChildRecord) {
			another := *c
			another.OperationID = entityid.New()
			r.PoolChildren[another.OperationID] = another
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, selected := retirementPreparationFixture(t)
			test.change(&candidate, &selected)
			candidate.PoolChildren[selected.OperationID] = selected
			if _, _, err := retirementPreparationBirth(candidate, selected.InstanceID); err == nil {
				t.Fatal("retirement description accepted absent, ambiguous or replaced original birth evidence")
			}
		})
	}
}

func TestRetirementPreparationCannotUseCallerBuiltAuthority(t *testing.T) {
	var controller *Controller
	if _, err := controller.PreparePoolRetirement(t.Context(), rootoci.Call{}, rootoci.PoolRetirementSelector{Cell: "GRU", InstanceID: "ocid1.instance.oc1..original"}); err == nil {
		t.Fatal("caller-built data gained independent root cleanup scope")
	}
}
