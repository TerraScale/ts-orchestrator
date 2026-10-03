package bootstrapstart

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const replacementObservedDigest = "1111111111111111111111111111111111111111111111111111111111111111"

func founderReplacementFixture(t *testing.T) (*founderSignerFixture, *founderCaller, *founderFakeOCI, *bootstrap.Ledger) {
	t.Helper()
	fixture, caller, _, fake := newFounderRuntimeFixtureWithSetup(t, func(fixture *founderSignerFixture) {
		founderFixtureWithAdmissibleRelease(t, fixture)
	})
	for _, row := range fixture.plan.Peers {
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatalf("found %s: %v", row.Slot, err)
		}
	}
	ledger, err := caller.openLedger(t.Context(), fixture.current, fixture.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, caller, fake, ledger
}

func signedSlotRetirement(t *testing.T, fixture *founderSignerFixture, ledger *bootstrap.Ledger, slot string,
	key ed25519.PrivateKey,
) []byte {
	t.Helper()
	candidate, err := RenderSlotRetirementCandidate(t.Context(), ledger, fixture.accepted.DeploymentID,
		fixture.accepted.Cell, slot, replacementObservedDigest, "authority-epoch-7", fixture.now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bootstrap.SignSlotRetirement(candidate, fixture.now.Add(-30*time.Second),
		fixture.now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func readFounderSlot(t *testing.T, fixture *founderSignerFixture, ledger *bootstrap.Ledger, slot string) bootstrap.SlotState {
	t.Helper()
	state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{DeploymentID: fixture.accepted.DeploymentID,
		Cell: fixture.accepted.Cell, Slot: slot})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestFounderReplacementRelaunchesRetiredPeerAsNextAttempt(t *testing.T) {
	fixture, caller, fake, ledger := founderReplacementFixture(t)
	row := fixture.plan.Peers[0]
	before := readFounderSlot(t, fixture, ledger, row.Slot)
	if before.Head.Attempt != 1 || before.Result == nil {
		t.Fatalf("founded slot = attempt %d result %v", before.Head.Attempt, before.Result)
	}
	retirement := signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)
	launches := fake.launches
	if err := caller.replacePeer(t.Context(), row.Slot, retirement); err != nil {
		t.Fatalf("replace retired peer: %v", err)
	}
	after := readFounderSlot(t, fixture, ledger, row.Slot)
	if after.Head.Attempt != 2 || after.Head.Generation != 2 || after.Result == nil ||
		after.Head.ResultDigest == "" || after.Head.RetirementDigest != digest(retirement) ||
		after.Result.InstanceOCID == before.Result.InstanceOCID ||
		!strings.HasSuffix(after.Result.InstanceOCID, row.Slot+"-a2") ||
		after.Intent.Node != before.Intent.Node || after.Intent.PeerRowDigest != before.Intent.PeerRowDigest ||
		after.Intent.CreateKey == before.Intent.CreateKey || fake.launches != launches+1 {
		t.Fatalf("replacement did not complete the next attempt: head=%+v result=%+v launches=%d",
			after.Head, after.Result, fake.launches-launches)
	}
	summaries, err := SummarizeControllerSlots(t.Context(), ledger, fixture.accepted.DeploymentID,
		fixture.accepted.Cell, []string{row.Slot})
	if err != nil || !summaries[row.Slot].Complete || summaries[row.Slot].Attempt != 2 ||
		summaries[row.Slot].InstanceOCID != after.Result.InstanceOCID {
		t.Fatalf("slot summary = %+v, %v", summaries, err)
	}
	// Replaying the same evidence resumes the admitted successor only.
	if err := caller.replacePeer(t.Context(), row.Slot, retirement); err != nil {
		t.Fatalf("replay replacement: %v", err)
	}
	if fake.launches != launches+1 {
		t.Fatalf("replay launched again: %d", fake.launches-launches)
	}
	// Evidence for the retired attempt can never retire its successor.
	stale := signedSlotRetirementFor(t, fixture, before)
	if err := caller.replacePeer(t.Context(), row.Slot, stale); !errors.Is(err, ErrFounderReplacement) {
		t.Fatalf("stale retirement error = %v", err)
	}
	if fake.launches != launches+1 {
		t.Fatal("stale retirement launched")
	}
}

func signedSlotRetirementFor(t *testing.T, fixture *founderSignerFixture, state bootstrap.SlotState) []byte {
	t.Helper()
	candidate, err := bootstrap.SlotRetirementCandidate(state, replacementObservedDigest, "authority-epoch-8",
		fixture.now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := bootstrap.SignSlotRetirement(candidate, fixture.now.Add(-30*time.Second),
		fixture.now.Add(time.Hour), fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestFounderReplacementRequiresRootSignedRetirement(t *testing.T) {
	fixture, caller, fake, ledger := founderReplacementFixture(t)
	row := fixture.plan.Peers[0]
	_, untrusted, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	launches := fake.launches
	if err := caller.replacePeer(t.Context(), row.Slot,
		signedSlotRetirement(t, fixture, ledger, row.Slot, untrusted)); err == nil {
		t.Fatal("untrusted retirement advanced the slot")
	}
	if state := readFounderSlot(t, fixture, ledger, row.Slot); state.Head.Attempt != 1 || fake.launches != launches {
		t.Fatalf("untrusted retirement changed slot: attempt=%d launches=%d", state.Head.Attempt, fake.launches-launches)
	}
	// Evidence for one slot cannot be replayed against another slot.
	other := fixture.plan.Peers[1]
	if err := caller.replacePeer(t.Context(), other.Slot,
		signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)); !errors.Is(err, ErrFounderReplacement) {
		t.Fatalf("cross-slot retirement error = %v", err)
	}
	if err := caller.replacePeer(t.Context(), fixture.plan.SeedSlot,
		signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)); !errors.Is(err, ErrFounderReplacement) {
		t.Fatalf("seed retirement error = %v", err)
	}
	if fake.launches != launches {
		t.Fatal("rejected retirement launched")
	}
}

func TestObserveLifecycleReportsTerminatedWithoutVNIC(t *testing.T) {
	const id = "ocid1.instance.oc1.sa-saopaulo-1.controller-b"
	compute := &fakeComputeObservation{instance: core.GetInstanceResponse{Instance: core.Instance{
		Id: new(id), LifecycleState: core.InstanceLifecycleStateTerminated}}}
	observer := &OCIInstanceObserver{compute: compute, network: &fakeNetworkObservation{}}
	state, err := observer.ObserveLifecycle(t.Context(), id)
	if err != nil || state != "TERMINATED" {
		t.Fatalf("lifecycle = %q, %v", state, err)
	}
	if _, err := observer.ObserveLifecycle(t.Context(), "ocid1.instance.oc1.sa-saopaulo-1.other"); err == nil {
		t.Fatal("a different returned instance was accepted")
	}
	if _, err := observer.ObserveLifecycle(t.Context(), "not-an-ocid"); err == nil {
		t.Fatal("malformed instance OCID was read")
	}
}

func TestFounderReplacementInstanceIsAdmittedForMatchingAttempt(t *testing.T) {
	fixture, caller, _, ledger := founderReplacementFixture(t)
	row := fixture.plan.Peers[0]
	if err := caller.replacePeer(t.Context(), row.Slot,
		signedSlotRetirement(t, fixture, ledger, row.Slot, fixture.root)); err != nil {
		t.Fatalf("replace retired peer: %v", err)
	}
	replacementID := "ocid1.instance.oc1.sa-saopaulo-1." + row.Slot + "-a2"
	reader := &founderAdmissionLedger{ledger: ledger}
	gate, material, credentials := newFounderPeerGateForInstance(t, fixture, reader, row, replacementID)
	accepted, err := gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("replacement instance was not admitted: %v", err)
	}
	if accepted.InstanceOCID != replacementID || accepted.HeadAttempt != 2 || accepted.HeadGeneration != 2 ||
		accepted.Slot != row.Slot || material.initialCalls != 1 || credentials.calls != 1 {
		t.Fatalf("replacement marker = %+v material=%d credentials=%d", accepted, material.initialCalls, credentials.calls)
	}

	// The retired instance can no longer pass first-install admission.
	retired := &founderAdmissionLedger{ledger: ledger}
	oldGate, _, _ := newFounderPeerGate(t, fixture, retired, row)
	if _, err := oldGate.AdmitInitial(context.WithoutCancel(t.Context())); err == nil {
		t.Fatal("retired instance passed admission after replacement")
	}
}
