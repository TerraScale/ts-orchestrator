package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func completedManagedSlotForRetirement() SlotState {
	result := strings.Repeat("c", 64)
	return SlotState{
		Intent: Intent{SchemaVersion: 2, Mode: IntentModeManaged, DeploymentID: "deployment-1", Cell: "GRU",
			Environment: "production", Role: roleController, Slot: "controller-b", Attempt: 1, Generation: 1,
			CreateKey: "founder-controller-b-0123456789abcdef01234567"},
		Head: SlotHead{SchemaVersion: 2, Slot: "controller-b", Attempt: 1, Generation: 1,
			IntentDigest: strings.Repeat("a", 64), ResultDigest: result, CandidateDigest: strings.Repeat("d", 64)},
		Result:       &Result{InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.controller-b", Attempt: 1},
		ResultRecord: &StoredRecord{SHA256: result},
	}
}

func TestSlotRetirementCandidateBindsCompletedAttempt(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	state := completedManagedSlotForRetirement()
	candidate, err := SlotRetirementCandidate(state, strings.Repeat("e", 64), "authority-epoch-3", now)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.PreviousAttempt != 1 || candidate.PreviousGeneration != 1 ||
		candidate.PreviousResultDigest != state.Head.ResultDigest ||
		candidate.PriorInstanceOCID != state.Result.InstanceOCID || candidate.PriorCreateKey != state.Intent.CreateKey ||
		candidate.Disposition != SlotRetirementDisposition || candidate.Slot != "controller-b" {
		t.Fatalf("candidate = %+v", candidate)
	}
	pending := state
	pending.Head.ResultDigest = ""
	if _, err := SlotRetirementCandidate(pending, strings.Repeat("e", 64), "authority-epoch-3", now); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("pending slot retirement error = %v", err)
	}
	seed := state
	seed.Intent.Mode = IntentModeExternalSeed
	if _, err := SlotRetirementCandidate(seed, strings.Repeat("e", 64), "authority-epoch-3", now); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("external seed retirement error = %v", err)
	}
	if _, err := SlotRetirementCandidate(state, "not-a-digest", "authority-epoch-3", now); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("unbound observation error = %v", err)
	}
}

func TestSignSlotRetirementRoundTripAndBounds(t *testing.T) {
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	candidate, err := SlotRetirementCandidate(completedManagedSlotForRetirement(), strings.Repeat("e", 64),
		"authority-epoch-3", now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignSlotRetirement(candidate, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSlotRetirementCandidate(wire)
	if err != nil || decoded != candidate {
		t.Fatalf("decoded = %+v, %v", decoded, err)
	}
	if _, err := SignSlotRetirement(candidate, now.Add(-time.Minute), now.Add(time.Hour), root); err == nil {
		t.Fatal("retirement signed before its observation")
	}
	if _, err := SignSlotRetirement(candidate, now, now.Add(48*time.Hour), root); err == nil {
		t.Fatal("retirement signed beyond the ledger lifetime")
	}
	handoff := candidate
	handoff.Disposition = "seed-handoff"
	if _, err := SignSlotRetirement(handoff, now, now.Add(time.Hour), root); err == nil {
		t.Fatal("seed handoff signed as managed slot retirement")
	}
	other, err := trust.Sign(envelope.Payload, trust.Scope{Domain: domainSeedHandoff, DeploymentID: candidate.DeploymentID,
		Cell: candidate.Cell, Environment: candidate.Environment, Role: roleController, Slot: candidate.Slot},
		now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	otherWire, err := trust.EncodeEnvelope(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSlotRetirementCandidate(otherWire); !errors.Is(err, ErrRetirementInvalid) {
		t.Fatalf("wrong-domain decode error = %v", err)
	}
}

func TestReplacementSlotHeadFollowsCompletedAttempt(t *testing.T) {
	state := completedManagedSlotForRetirement()
	intent := state.Intent
	intent.Attempt, intent.Generation = 2, 2
	head, err := ReplacementSlotHead(state, intent, []byte("intent"), []byte("retirement"))
	if err != nil {
		t.Fatal(err)
	}
	if head.Attempt != 2 || head.PreviousAttempt != 1 || head.PreviousResultDigest != state.Head.ResultDigest ||
		head.PreviousCandidateDigest != state.Head.CandidateDigest || head.ResultDigest != "" ||
		head.IntentDigest != objectDigest([]byte("intent")) || head.RetirementDigest != objectDigest([]byte("retirement")) {
		t.Fatalf("successor head = %+v", head)
	}
	intent.Attempt = 3
	if _, err := ReplacementSlotHead(state, intent, []byte("intent"), []byte("retirement")); err == nil {
		t.Fatal("successor head skipped an attempt")
	}
}
