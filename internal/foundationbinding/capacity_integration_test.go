package foundationbinding

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

func TestCapacityLedgerRequiresCurrentSignedGrantAndProtectedSDKRecord(t *testing.T) {
	s := newBindingScenario(t)
	s.grant.InfrastructureSpend = jsontext.Value(`{"monthlyLimitMinor":1000}`)
	s.publish()
	at := time.Now().UTC().Add(-10 * time.Second)
	quote := capacityledger.Quote{ScopeSHA256: strings.Repeat("a", 64), Cell: s.authority.Cell,
		CompartmentID: s.record.ResourceIDs["workload_compartment"], Shape: "VM.Standard.A1.Flex", Currency: "USD",
		OCPUs: 1, MemoryGB: 6, BootGB: 50, IssuedAt: at, ExpiresAt: at.Add(2 * time.Minute),
		Prices: []ocicost.Price{{SKU: "B91961", PerUnit: .0255}, {SKU: "B91962", PerUnit: .0017}, {SKU: "B93297", PerUnit: .01}, {SKU: "B93298", PerUnit: .0015}}}
	quote.MonthlyCents, _ = ocicost.NodeMonthlyCents(quote.Prices, quote.Shape, quote.OCPUs, quote.MemoryGB, quote.BootGB)
	receipt := capacityledger.Receipt{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("b", 64), GrantSHA256: s.authority.GrantSHA256,
		GrantGeneration: s.authority.Generation, LogicalScopeSHA256: quote.ScopeSHA256, ResolvedScopeSHA256: quote.ScopeSHA256,
		TenancyID: s.authority.TenancyID, ReservedAt: at.Add(time.Second), QuoteSHA256: quote.SHA256(), Quote: quote}
	ledger := &capacityledger.Ledger{}
	if err := ledger.Reserve(receipt); err != nil {
		t.Fatal(err)
	}
	s.record.CapacityLedger = ledger
	bindings, err := Verify(t.Context(), s.factory, s.authority, s.wire)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := bindings.CapacityLedger(t.Context())
	if err != nil || !proof.ValidAt(time.Now()) || proof.TenancyID() != s.authority.TenancyID || proof.Cell() != s.authority.Cell {
		t.Fatalf("authenticated financial history unavailable: %+v err=%v", proof, err)
	}
	if proof.ExpiresAt().After(time.Now().Add(2*time.Minute)) || proof.ValidAt(proof.ExpiresAt()) {
		t.Fatal("protected history expiry outlives its original SDK observations")
	}
	copy := proof.Ledger()
	copy.Hosts[0].Receipt.Quote.Prices[0].PerUnit = 0
	if proof.Ledger().Hosts[0].Receipt.Quote.SHA256() != receipt.QuoteSHA256 {
		t.Fatal("returned history rewrote the verified original tariff")
	}
	if err := proof.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := (VerifiedBindings{}).CapacityLedger(t.Context()); err == nil || (VerifiedCapacityLedger{}).ValidAt(time.Now()) {
		t.Fatal("caller-provided data minted protected accounting history")
	}
	if err := s.record.CapacityLedger.Prepare(receipt.OperationID, strings.Repeat("d", 64), at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := proof.Revalidate(t.Context()); err == nil {
		t.Fatal("a new protected root effect was invisible to accounting revalidation")
	}
	if err := s.record.CapacityLedger.BindBirth(receipt.OperationID, strings.Repeat("d", 64), "ocid1.instance.oc1.us-sanjose-1.child", "ocid1.bootvolume.oc1.us-sanjose-1.child", at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	child := capacityChild{OperationID: receipt.OperationID, RecipeSHA256: receipt.RecipeSHA256,
		InstanceID: s.record.CapacityLedger.Hosts[0].InstanceID, BootVolumeID: s.record.CapacityLedger.Hosts[0].BootVolumeID, BornAt: at.Add(3 * time.Second)}
	child.Launch.RequestSHA256, child.Launch.FirstAttemptAt = strings.Repeat("d", 64), at.Add(2*time.Second)
	s.record.PoolChildren, err = json.Marshal(map[string]capacityChild{receipt.OperationID: child})
	if err != nil {
		t.Fatal(err)
	}
	var additive map[string]map[string]any
	if err := json.Unmarshal(s.record.PoolChildren, &additive); err != nil {
		t.Fatal(err)
	}
	metadata := additive[receipt.OperationID]
	metadata["publicCaPem"], metadata["availabilityDomains"] = []byte("original public CA"), []string{"original AD"}
	metadata["node"], metadata["descriptor"] = "ts-sfo-4", "original descriptor"
	metadata["launch"].(map[string]any)["pendingAttemptId"] = entityid.New()
	s.record.PoolChildren, err = json.Marshal(additive)
	if err != nil {
		t.Fatal(err)
	}
	born, err := bindings.CapacityLedger(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	child.BootVolumeID = "ocid1.bootvolume.oc1.us-sanjose-1.foreign"
	s.record.PoolChildren, err = json.Marshal(map[string]capacityChild{receipt.OperationID: child})
	if err != nil {
		t.Fatal(err)
	}
	if err := born.Revalidate(t.Context()); err == nil {
		t.Fatal("financial liability accepted a different protected child boot result")
	}
	s.record.CapacityLedger = nil
	if _, err := bindings.CapacityLedger(t.Context()); err == nil {
		t.Fatal("missing protected history became zero liability")
	}
	s.record.CapacityLedger = ledger
	s.activeWire = []byte(`{"revoked":true}`)
	if _, err := bindings.CapacityLedger(t.Context()); err == nil {
		t.Fatal("revoked root grant still authenticated financial history")
	}
}
