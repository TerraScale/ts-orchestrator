package bootstrap

import (
	"bytes"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestControllerRetirementReadsExactRootRetiredAttempt(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := BootstrapScope{DeploymentID: fixture.ledger.config.DeploymentID, Cell: "GRU", Slot: "controller-a"}
	completed := completeFirstManagedAttempt(t, fixture, scope)
	evidence := fixture.retirement(scope, completed, SlotRetirementDisposition)
	wire := fixture.sign(t, scope, domainSlotRetirement, evidence, fixture.now)
	checked, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, wire)
	if err != nil || checked.Evidence != evidence || checked.PriorIntent.CreateKey != completed.Intent.CreateKey || checked.RetirementSHA256 != bodyDigest(wire) {
		t.Fatalf("current completed retirement failed exact binding: %+v %v", checked, err)
	}
	if _, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, nil); err == nil {
		t.Fatal("unadvanced current HEAD invented a protected retirement")
	}
	payload, err := trust.EncodePayload(evidence)
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := trust.Sign(payload, trust.Scope{Domain: domainSlotRetirement, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: fixture.environment, Role: roleController, Slot: scope.Slot}, fixture.now, fixture.now.Add(time.Hour), fixture.authority.peerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegatedWire, err := trust.EncodeEnvelope(delegated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, delegatedWire); err == nil {
		t.Fatal("delegated ledger key acquired root retirement authority")
	}
	wrong := evidence
	wrong.PriorInstanceOCID = "ocid1.instance.oc1.sa-saopaulo-1.successor"
	if _, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, fixture.sign(t, scope, domainSlotRetirement, wrong, fixture.now)); err == nil {
		t.Fatal("root retirement for another instance selected the active slot")
	}
}

func TestControllerRetirementReadsProtectedImmediatePredecessor(t *testing.T) {
	fixture := newLedgerFixture(t)
	scope := BootstrapScope{DeploymentID: fixture.ledger.config.DeploymentID, Cell: "GRU", Slot: "controller-a"}
	advanced := advanceManagedAttemptForTest(t, fixture, scope)
	checked, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, nil)
	if err != nil || checked.Evidence.PreviousAttempt != advanced.Head.PreviousAttempt || checked.Current.Head.Attempt != advanced.Head.Attempt ||
		checked.RetirementSHA256 != advanced.Head.RetirementDigest || checked.PriorIntent.CreateKey == advanced.Intent.CreateKey {
		t.Fatalf("protected retirement lost the exact predecessor: %+v %v", checked, err)
	}
	record, err := fixture.ledger.read(t.Context(), scope, advanced.Head.Attempt, ledgerRetirement)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, bytes.Clone(record.Bytes))
	if err != nil || explicit.RetirementSHA256 != checked.RetirementSHA256 {
		t.Fatalf("exact protected wire failed: %v", err)
	}
	wrong := checked.Evidence
	wrong.ObservedEvidenceDigest = bodyDigest([]byte("another-observation"))
	if _, err := fixture.ledger.ReadControllerRetirement(t.Context(), scope, fixture.sign(t, scope, domainSlotRetirement, wrong, fixture.now)); err == nil {
		t.Fatal("another signed retirement replaced protected HEAD's exact retirement")
	}
}
