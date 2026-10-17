package rootcapacity

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// These are receipt-selection fixtures, not evidence of provider creation or
// complete financial history.
func TestPoolChildReceiptKeepsOriginalBirthAcrossCurrentGrantChanges(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	quote := capacityledger.Quote{ScopeSHA256: strings.Repeat("a", 64), Cell: "GRU", CompartmentID: "ocid1.compartment.oc1..workers",
		Shape: "VM.Standard.A1.Flex", Currency: "USD", OCPUs: 2, MemoryGB: 12, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(2 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	var known bool
	quote.MonthlyCents, known = ocicost.NodeMonthlyCents(quote.Prices, quote.Shape, quote.OCPUs, quote.MemoryGB, quote.BootGB)
	if !known {
		t.Fatal("receipt-selection fixture has no original tariff")
	}
	receipt := capacityledger.Receipt{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("b", 64), GrantSHA256: strings.Repeat("c", 64),
		GrantGeneration: 1, LogicalScopeSHA256: quote.ScopeSHA256, ResolvedScopeSHA256: quote.ScopeSHA256,
		TenancyID: "ocid1.tenancy.oc1..original", ReservedAt: at.Add(time.Second), QuoteSHA256: quote.SHA256(), Quote: quote}
	child := region.PoolChildRecord{OperationID: receipt.OperationID, RecipeSHA256: receipt.RecipeSHA256, PoolID: "original-pool",
		InstanceID: "ocid1.instance.oc1..original", BootVolumeID: "ocid1.bootvolume.oc1..original", BornAt: at.Add(3 * time.Second)}
	record := region.FoundationRecord{Cell: quote.Cell, TenancyID: receipt.TenancyID, GrantSHA256: strings.Repeat("d", 64), Generation: 2,
		CapacityPools: map[string]region.PoolResourceRecord{child.PoolID: {CompartmentID: quote.CompartmentID}},
		CapacityLedger: &capacityledger.Ledger{Version: capacityledger.Version, Hosts: []capacityledger.Host{{Receipt: receipt,
			InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID, BornAt: child.BornAt}}}}
	got, err := originalPoolChildReceipt(record, child)
	if err != nil || got.GrantSHA256 != receipt.GrantSHA256 || got.GrantGeneration != 1 || got.GrantSHA256 == record.GrantSHA256 {
		t.Fatalf("current grant replaced original purchase selectors: receipt=%+v err=%v", got, err)
	}
	for _, change := range []struct {
		name  string
		apply func(*region.FoundationRecord)
	}{
		{"missing ledger", func(r *region.FoundationRecord) { r.CapacityLedger = nil }},
		{"duplicate birth", func(r *region.FoundationRecord) {
			r.CapacityLedger.Hosts = append(r.CapacityLedger.Hosts, r.CapacityLedger.Hosts[0])
		}},
		{"different instance", func(r *region.FoundationRecord) {
			r.CapacityLedger.Hosts[0].InstanceID = "ocid1.instance.oc1..different"
		}},
		{"retired boot", func(r *region.FoundationRecord) { r.CapacityLedger.Hosts[0].BootRetiredAt = at.Add(time.Hour) }},
		{"changed original grant", func(r *region.FoundationRecord) { r.CapacityLedger.Hosts[0].Receipt.GrantSHA256 = "invalid" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			candidate := record
			ledger := record.CapacityLedger.Clone()
			candidate.CapacityLedger = &ledger
			change.apply(&candidate)
			if _, err := originalPoolChildReceipt(candidate, child); err == nil {
				t.Fatal("accepted missing, ambiguous, changed or terminal original purchase")
			}
		})
	}
}
