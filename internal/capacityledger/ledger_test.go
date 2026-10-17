package capacityledger

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

func financialReceipt(at time.Time) Receipt {
	q := Quote{ScopeSHA256: strings.Repeat("a", 64), Cell: "GRU", CompartmentID: "ocid1.compartment.oc1..workers", Shape: "VM.Standard.A1.Flex",
		Currency: "USD", OCPUs: 1, MemoryGB: 6, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(2 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	q.MonthlyCents, _ = ocicost.NodeMonthlyCents(q.Prices, q.Shape, q.OCPUs, q.MemoryGB, q.BootGB)
	return Receipt{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("b", 64), GrantSHA256: strings.Repeat("c", 64), GrantGeneration: 1,
		LogicalScopeSHA256: q.ScopeSHA256, ResolvedScopeSHA256: q.ScopeSHA256, TenancyID: "ocid1.tenancy.oc1..financial",
		ReservedAt: at.Add(time.Second), QuoteSHA256: q.SHA256(), Quote: q}
}

func TestOriginalCeilingSurvivesRetirementReplacementAndMonthRollover(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	first := financialReceipt(at)
	var ledger Ledger
	if err := ledger.Reserve(first); err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("d", 64)
	if err := ledger.Prepare(first.OperationID, request, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.BindBirth(first.OperationID, request, "ocid1.instance.oc1..original", "ocid1.bootvolume.oc1..original", at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	retired := at.Add(24 * time.Hour)
	if err := ledger.RetireResource(first.OperationID, ledger.Hosts[0].InstanceID, retired); err != nil {
		t.Fatal(err)
	}
	if err := ledger.RetireResource(first.OperationID, ledger.Hosts[0].BootVolumeID, retired); err != nil {
		t.Fatal(err)
	}
	replacement := financialReceipt(at.Add(2 * 24 * time.Hour))
	if err := ledger.Reserve(replacement); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Prepare(replacement.OperationID, request, replacement.ReservedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.BindBirth(replacement.OperationID, request, "ocid1.instance.oc1..replacement", "ocid1.bootvolume.oc1..replacement", replacement.ReservedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	unknown := financialReceipt(at.Add(3 * 24 * time.Hour))
	if err := ledger.Reserve(unknown); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Prepare(unknown.OperationID, request, unknown.ReservedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, err := ledger.Monthly(at.Add(4 * 24 * time.Hour)); err != nil || got != 3*first.Quote.MonthlyCents {
		t.Fatalf("retired original, replacement and unknown were not each charged once: got=%d err=%v", got, err)
	}

	// Restart serialization keeps the original prices and resource IDs, even
	// though their launch quotes expired long before the next accounting month.
	wire, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var restarted Ledger
	if err := json.Unmarshal(wire, &restarted, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	nextMonth := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got, err := restarted.Monthly(nextMonth); err != nil || got != 2*first.Quote.MonthlyCents {
		t.Fatalf("rollover lost a live host/unknown hold or retained last month's retired host: got=%d err=%v", got, err)
	}
	if !equal(restarted.Hosts[0], ledger.Hosts[0]) {
		t.Fatal("rollover or restart rewrote the original quote/grant/IDs")
	}
	if err := restarted.RetireResource(replacement.OperationID, restarted.Hosts[1].InstanceID, nextMonth); err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Monthly(nextMonth.AddDate(0, 1, 0)); err != nil || got != 2*first.Quote.MonthlyCents {
		t.Fatalf("unattached boot or unknown outcome was refunded: got=%d err=%v", got, err)
	}
}

func TestFinancialLedgerRejectsRebindingAndMutableTariffsAtomically(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	receipt := financialReceipt(at)
	var ledger Ledger
	if err := ledger.Reserve(receipt); err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("d", 64)
	if err := ledger.Prepare(receipt.OperationID, request, receipt.ReservedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.BindBirth(receipt.OperationID, request, "ocid1.instance.oc1..original", "ocid1.bootvolume.oc1..original", receipt.ReservedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	before := ledger.Clone()
	for _, attempt := range []func() error{
		func() error { changed := receipt; changed.GrantGeneration++; return ledger.Reserve(changed) },
		func() error {
			changed := receipt
			changed.Quote = changed.Quote.Clone()
			changed.Quote.Prices[0].PerUnit = 0
			return ledger.Reserve(changed)
		},
		func() error {
			return ledger.Prepare(receipt.OperationID, request, receipt.ReservedAt.Add(2*time.Second))
		},
		func() error {
			return ledger.BindBirth(receipt.OperationID, request, "ocid1.instance.oc1..replacement", "ocid1.bootvolume.oc1..replacement", at.Add(time.Hour))
		},
		func() error {
			return ledger.RetireResource(receipt.OperationID, "ocid1.bootvolume.oc1..foreign", at.Add(time.Hour))
		},
	} {
		if err := attempt(); err == nil || !equal(before, ledger) {
			t.Fatalf("rebind changed durable original liability: err=%v ledger=%+v", err, ledger)
		}
	}
	second := financialReceipt(at.Add(time.Hour))
	if err := ledger.Reserve(second); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Prepare(second.OperationID, request, second.ReservedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	before = ledger.Clone()
	if err := ledger.BindBirth(second.OperationID, request, "ocid1.instance.oc1..new", "ocid1.bootvolume.oc1..original", second.ReservedAt.Add(2*time.Second)); err == nil || !equal(before, ledger) {
		t.Fatal("two reservations shared the original boot disk liability")
	}
	copy := ledger.Clone()
	copy.Hosts[0].Receipt.Quote.Prices[0].PerUnit = 0
	if !equal(before, ledger) {
		t.Fatal("returned record mutated protected tariff slices")
	}
}
