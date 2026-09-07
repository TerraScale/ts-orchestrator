package main

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

func removalFenceProof(t *testing.T) placementtransition.Proof {
	t.Helper()
	request := placementtransition.Request{OperationID: "remove-1", ScopeID: "prod/cluster", PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []placementtransition.Member{{Identity: "member-b", Region: "GRU", PlacementDigest: strings.Repeat("a", 64)}, {Identity: "member-c", Region: "GRU", PlacementDigest: strings.Repeat("b", 64)}}}
	digest, err := placementtransition.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := placementtransition.DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: "member-a", ScopeID: request.ScopeID, PriorEpoch: 1, PriorGeneration: 1, RequestDigest: digest, FrontierDigest: strings.Repeat("c", 64)}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return placementtransition.Proof{Kind: "accepted_epoch", Request: request, RequestDigest: digest, PriorGeneration: 1, DrainReceipts: []placementtransition.Signed{{Payload: encoded}}}
}

func TestRemovalFenceRequiresExclusionFromAcceptedSuccessor(t *testing.T) {
	proof := removalFenceProof(t)
	if !proofFencesMember(proof, "member-a") {
		t.Fatal("exact removed member fence rejected")
	}
	proof.Request.Members[0].Identity = "member-a"
	proof.RequestDigest, _ = placementtransition.RequestDigest(proof.Request)
	var receipt placementtransition.DrainReceipt
	if err := json.Unmarshal(proof.DrainReceipts[0].Payload, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.RequestDigest = proof.RequestDigest
	proof.DrainReceipts[0].Payload, _ = json.Marshal(receipt)
	if proofFencesMember(proof, "member-a") {
		t.Fatal("drain followed by readmission authorized host deletion")
	}
}

func TestRemovalFenceRejectsReceiptFromAnotherTransition(t *testing.T) {
	for _, field := range []string{"kind", "request", "generation", "scope", "epoch"} {
		t.Run(field, func(t *testing.T) {
			proof := removalFenceProof(t)
			var receipt placementtransition.DrainReceipt
			if err := json.Unmarshal(proof.DrainReceipts[0].Payload, &receipt); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "kind":
				receipt.Kind = "prepared_epoch"
			case "request":
				receipt.RequestDigest = strings.Repeat("d", 64)
			case "generation":
				receipt.PriorGeneration++
			case "scope":
				receipt.ScopeID = "prod/other"
			case "epoch":
				receipt.PriorEpoch++
			}
			proof.DrainReceipts[0].Payload, _ = json.Marshal(receipt)
			if proofFencesMember(proof, "member-a") {
				t.Fatal("unrelated receipt authorized host deletion")
			}
		})
	}
}
