package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"slices"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func (w *productionHostRelocation) beginPlan(ctx context.Context, request hostremoval.RemovalRequest, plan placementrelocation.Plan) error {
	if len(plan.Records) > 0 {
		return w.Admission.BeginPlacementRelocation(ctx, plan.OperationID, plan.Records)
	}
	binding := databaseadmission.UnusedHostRemoval{OperationID: plan.OperationID, ScopeID: plan.Request.ScopeID, MemberIdentity: request.Member.Identity, ResourceID: request.Member.ResourceID, Generation: request.Generation, InventoryDigest: databaseadmission.PlacementInventoryDigest(nil), Head: plan.PriorProof}
	return w.Admission.BeginEmptyPlacementRelocation(ctx, binding, w.ProofKey)
}

// Empty completion still requires every real successor member's accepted tuple.
// This creates placement evidence only; there is no synthetic database record.
func emptyRelocationTargets(op placementrelocation.Operation) ([]databaseadmission.PlacementTarget, error) {
	if len(op.Plan.Records) != 0 || len(op.Acceptances) != len(op.Plan.Targets) || placementrelocation.ValidateOperation(op) != nil {
		return nil, placementrelocation.ErrInvalid
	}
	proof, err := json.Marshal(op.Accepted)
	if err != nil {
		return nil, err
	}
	targets := make([]databaseadmission.PlacementTarget, 0, len(op.Plan.Targets))
	for _, target := range op.Plan.Targets {
		stage := newPlacementStageRequest(target.Proposal)
		receipt := new(pb.PlacementAcceptanceResponse)
		if stage == nil || stage.Proposal == nil || len(stage.Proposal.Assignments) != 0 || len(stage.Declarations) != 0 || proto.Unmarshal(op.Acceptances[target.ServerIdentity], receipt) != nil {
			return nil, placementrelocation.ErrInvalid
		}
		targets = append(targets, databaseadmission.PlacementTarget{ServerIdentity: target.ServerIdentity, MemberID: target.MemberID, Region: target.Region, Proposal: slices.Clone(target.Proposal), Proposed: true, AcceptedReceipt: slices.Clone(op.Acceptances[target.ServerIdentity]), AcceptedProof: slices.Clone(proof), AcceptedRevision: receipt.ProposalRevision, AcceptedEpoch: receipt.Epoch, AcceptedGeneration: receipt.Generation, AcceptedProofDigest: receipt.ProofDigest})
	}
	return targets, nil
}

func (w *productionHostRelocation) verifyEmptyCommitted(ctx context.Context, op placementrelocation.Operation) error {
	committed, found, err := w.Admission.EmptyPlacementRelocation(ctx, op.Plan.OperationID)
	if err != nil {
		return err
	}
	if !found || committed.Binding.OperationID != op.Plan.OperationID || committed.Binding.ScopeID != op.Plan.Request.ScopeID || committed.Binding.MemberIdentity != op.Plan.RemovedIdentity || signedDigest(committed.Binding.Head) != signedDigest(op.Plan.PriorProof) || !bytes.Equal(committed.Accepted.Payload, op.Accepted.Payload) || !bytes.Equal(committed.Accepted.Signature, op.Accepted.Signature) || committed.Accepted.KeyID != op.Accepted.KeyID {
		return placementrelocation.ErrConflict
	}
	targets, err := emptyRelocationTargets(op)
	if err != nil {
		return err
	}
	expected, err := placementrelocation.Digest(targets)
	if err != nil {
		return err
	}
	actual, err := placementrelocation.Digest(committed.Targets)
	if err != nil || expected != actual {
		return placementrelocation.ErrConflict
	}
	records, err := w.Admission.RelocationRecords(ctx)
	if err != nil {
		return err
	}
	if len(records) != 0 {
		return placementrelocation.ErrConflict
	}
	return nil
}
