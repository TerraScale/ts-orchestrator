package bootstrapstart

import (
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (f *controllerRecipientFixture) activationRecipient(t *testing.T, slot string, grants []cellspec.HostGrant) *ControllerHostRecipient {
	t.Helper()
	wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: cellspec.Identity{
		DeploymentID: f.issuer.DeploymentID, Cell: strings.ToLower(f.issuer.Cell), Environment: f.issuer.Environment},
		Generation: 1, RequiresBinary: 17, HostGrants: grants}, nil,
		f.founder.baked.Roots, time.Now().UTC(), time.Hour, f.founder.root)
	if err != nil {
		t.Fatal(err)
	}
	grant := f.grant(slot)
	proof, err := readControllerHostRecipient(t.Context(), f.reader, f.issuer, wire, grant.Node,
		f.states[slot].Result.InstanceOCID, grant.PrivateIP, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestControllerActivationRequiresCompleteSignedTopology(t *testing.T) {
	f := newControllerRecipientFixture(t)
	grants := []cellspec.HostGrant{f.grant("controller-a"), f.grant("controller-b"), f.grant("controller-c")}
	proof := f.activationRecipient(t, "controller-b", grants)
	domains, err := proof.VerifyActivationTopology(t.Context())
	if err != nil || len(domains) != 3 {
		t.Fatalf("three genuine signed grants rejected: %v", err)
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		sibling, err := proof.ReadSlotRecipient(t.Context(), slot, f.states[slot].Result.InstanceOCID)
		if err != nil || sibling.FailureDomain() != domains[slot] || sibling.ExpiresAt().After(proof.ExpiresAt()) {
			t.Fatalf("signed slot recipient lost its domain or original deadline: %s %v", slot, err)
		}
	}
	if _, err := f.activationRecipient(t, "controller-b", grants[:2]).VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("incomplete TSAuth topology admitted")
	}
	changed := append([]cellspec.HostGrant(nil), grants...)
	changed[2].Roles = []string{"ts-console"}
	if _, err := f.activationRecipient(t, "controller-b", changed).VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("third controller without TSAuth grant admitted")
	}
	if _, err := proof.ReadSlotRecipient(t.Context(), "controller-a", f.states["controller-c"].Result.InstanceOCID); err == nil {
		t.Fatal("foreign instance accepted for a signed slot")
	}
	if _, err := proof.ReadManagerRetirement(t.Context(), "controller-a", f.states["controller-a"].Result.InstanceOCID); err == nil {
		t.Fatal("current running controller accepted as a terminated predecessor")
	}
	proof.validUntil = time.Now().Add(-time.Second)
	if _, err := proof.VerifyActivationTopology(t.Context()); err == nil {
		t.Fatal("expired original recipient renewed topology authority")
	}
	if _, err := proof.ReadSlotRecipient(t.Context(), "controller-a", f.states["controller-a"].Result.InstanceOCID); err == nil {
		t.Fatal("expired original recipient renewed sibling authority")
	}
	if _, err := proof.ReadManagerRetirement(t.Context(), "controller-a", f.states["controller-a"].Result.InstanceOCID); err == nil {
		t.Fatal("expired original recipient renewed retirement authority")
	}
}

func TestControllerActivationRetirementRequiresExactTerminatedPredecessor(t *testing.T) {
	f := newControllerRecipientFixture(t)
	grants := []cellspec.HostGrant{f.grant("controller-a"), f.grant("controller-b"), f.grant("controller-c")}
	proof := f.activationRecipient(t, "controller-a", grants)
	slot := "controller-b"
	state := f.states[slot]
	observed, err := f.sources.observer.ObserveInstance(t.Context(), state.Result.InstanceOCID)
	if err != nil {
		t.Fatal(err)
	}
	observedWire, err := protocol.EncodeJSON(observed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	evidence, err := bootstrap.SlotRetirementCandidate(state, digestWire(observedWire), "actual-fixture-root", now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bootstrap.SignSlotRetirement(evidence, now, now.Add(time.Hour), f.founder.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := f.founder.current.Plan.ReplacementManagedPeerIntent(slot, state, wire, now)
	if err != nil {
		t.Fatal(err)
	}
	scope := bootstrap.BootstrapScope{DeploymentID: f.issuer.DeploymentID, Cell: f.issuer.Cell, Slot: slot}
	intentWire := signFounderLedgerValue(t, f.founder.ledgerKey, "bootstrap-intent", scope, intent, now)
	head, err := bootstrap.ReplacementSlotHead(state, intent, intentWire, wire)
	if err != nil {
		t.Fatal(err)
	}
	headWire := signFounderLedgerValue(t, f.founder.ledgerKey, "bootstrap-slot-head", scope, head, now)
	if _, err := f.sources.ledger.AdvanceSlot(t.Context(), scope, state.HeadRecord.ETag, wire, intentWire, headWire); err != nil {
		t.Fatal(err)
	}
	if _, err := proof.ReadManagerRetirement(t.Context(), slot, state.Result.InstanceOCID); err == nil {
		t.Fatal("root-signed retirement treated a still-running VM as stopped")
	}
	observed.LifecycleState = "TERMINATED"
	f.live[observed.InstanceOCID] = observed
	retired, err := proof.ReadManagerRetirement(t.Context(), slot, state.Result.InstanceOCID)
	if err != nil {
		t.Fatal("genuine selected predecessor and exact SDK TERMINATED evidence rejected", err)
	}
	if retired.PriorInstanceID() != state.Result.InstanceOCID || retired.ExpiresAt().After(proof.ExpiresAt()) || retired.Verify(t.Context()) != nil {
		t.Fatal("selected retirement lost its exact instance, current source or original deadline")
	}
	if _, err := proof.ReadManagerRetirement(t.Context(), slot, f.states["controller-c"].Result.InstanceOCID); err == nil {
		t.Fatal("selected retirement admitted a foreign prior instance")
	}
	observed.LifecycleState = "RUNNING"
	f.live[observed.InstanceOCID] = observed
	if retired.Verify(t.Context()) == nil {
		t.Fatal("retirement renewed after exact old VM lost TERMINATED evidence")
	}
}
