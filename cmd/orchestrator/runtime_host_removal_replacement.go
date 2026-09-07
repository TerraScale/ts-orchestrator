package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func newPlacementStageRequest(data []byte) *pb.PlacementStageRequest {
	request := new(pb.PlacementStageRequest)
	if len(data) == 0 || proto.Unmarshal(data, request) != nil {
		return nil
	}
	return request
}

func signedDigest(s placementtransition.Signed) string {
	sum := sha256.Sum256(s.Payload)
	return hex.EncodeToString(sum[:])
}

func containsMember(members []placementtransition.Member, identity string) bool {
	for _, member := range members {
		if member.Identity == identity {
			return true
		}
	}
	return false
}

func proofFencesMember(proof placementtransition.Proof, identity string) bool {
	// A drain receipt fences the previous epoch only. A routine transition can
	// readmit the same member, so it cannot authorize deleting that host.
	if identity == "" || proof.Kind != "accepted_epoch" || proof.Request.PriorEpoch == 0 || proof.PriorGeneration == 0 || containsMember(proof.Request.Members, identity) {
		return false
	}
	digest, err := placementtransition.RequestDigest(proof.Request)
	if err != nil || digest != proof.RequestDigest {
		return false
	}
	for _, signed := range proof.DrainReceipts {
		var receipt placementtransition.DrainReceipt
		if json.Unmarshal(signed.Payload, &receipt, json.RejectUnknownMembers(true)) == nil && receipt.Kind == "old_epoch_drained_fenced" && receipt.MemberIdentity == identity && receipt.ScopeID == proof.Request.ScopeID && receipt.PriorEpoch == proof.Request.PriorEpoch && receipt.PriorGeneration == proof.PriorGeneration && receipt.RequestDigest == proof.RequestDigest {
			return true
		}
	}
	return false
}
