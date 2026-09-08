package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// productionRelocationPlanner uses admitted identities and authoritative pending
// journal receipts. Unknown remote outcomes never become revision zero.
func productionRelocationPlanner(
	configuredScope string,
	head func(context.Context, string) (placementtransition.Signed, error),
	proofKey ed25519.PublicKey,
	pending placementpublisher.Journal,
	resolve func(context.Context, string) (placementrelocation.Target, hostremoval.MemberObservation, error),
) func(context.Context, hostremoval.RemovalRequest, []databaseadmission.Record) (placementrelocation.Plan, error) {
	return func(ctx context.Context, request hostremoval.RemovalRequest, records []databaseadmission.Record) (placementrelocation.Plan, error) {
		if head == nil || pending == nil || resolve == nil || len(proofKey) != ed25519.PublicKeySize || configuredScope == "" {
			return placementrelocation.Plan{}, placementrelocation.ErrInvalid
		}
		scope := configuredScope
		for _, record := range records {
			for _, target := range record.PlacementTargets {
				stage := newPlacementStageRequest(target.Proposal)
				if stage == nil || stage.Proposal == nil {
					return placementrelocation.Plan{}, placementrelocation.ErrInvalid
				}
				candidate := stage.Proposal.Environment + "/" + stage.Proposal.Cluster
				if scope != "" && scope != candidate {
					return placementrelocation.Plan{}, placementrelocation.ErrConflict
				}
				scope = candidate
			}
		}
		signed, err := head(ctx, scope)
		if err != nil {
			return placementrelocation.Plan{}, err
		}
		if !ed25519.Verify(proofKey, append([]byte("terrabase-placement-transition-v1\x00"), signed.Payload...), signed.Signature) {
			return placementrelocation.Plan{}, placementrelocation.ErrInvalid
		}
		var proof placementtransition.Proof
		if json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.Kind != "accepted_epoch" || proof.Request.ScopeID != scope || !containsMember(proof.Request.Members, request.Member.Identity) {
			return placementrelocation.Plan{}, placementrelocation.ErrConflict
		}
		var priorStage []byte
		for _, record := range records {
			for _, target := range record.PlacementTargets {
				stage := newPlacementStageRequest(target.Proposal)
				if stage.Proposal.Epoch == proof.Request.Epoch && stage.Proposal.Generation == proof.Request.Generation {
					priorStage = slices.Clone(target.Proposal)
				}
			}
		}
		if len(priorStage) == 0 && len(records) == 0 {
			// Empty active inventory has no record carrying the last proposal.
			// Recover exact acknowledged Stage bytes from the authoritative
			// publisher journal and bind them to the signed accepted head.
			for _, member := range proof.Request.Members {
				retained, loadErr := pending.Load(ctx, member.Identity)
				if loadErr != nil {
					return placementrelocation.Plan{}, loadErr
				}
				stage := newPlacementStageRequest(retained.Request)
				receipt := new(pb.PlacementProposalResponse)
				if stage == nil || len(retained.Receipt) == 0 || proto.Unmarshal(retained.Receipt, receipt) != nil || tbep.ValidatePlacementReceipt(receipt, stage.Proposal) != nil || stage.ExpectedRevision == ^uint64(0) || receipt.Revision != stage.ExpectedRevision+1 {
					return placementrelocation.Plan{}, errors.New("runtime relocation: prior empty-scope Stage outcome unresolved")
				}
				if stage.Proposal.Environment+"/"+stage.Proposal.Cluster != scope || stage.Proposal.Epoch != proof.Request.Epoch || stage.Proposal.Generation != proof.Request.Generation {
					return placementrelocation.Plan{}, placementrelocation.ErrConflict
				}
				priorStage = slices.Clone(retained.Request)
				break
			}
		}
		if len(priorStage) == 0 {
			return placementrelocation.Plan{}, placementrelocation.ErrConflict
		}
		candidates := slices.Clone(request.Survivors)
		slices.SortFunc(candidates, func(a, b hostremoval.MemberObservation) int { return cmp.Compare(a.Identity, b.Identity) })
		var replacement placementrelocation.Target
		for _, candidate := range candidates {
			if candidate.Region != request.Member.Region || containsMember(proof.Request.Members, candidate.Identity) {
				continue
			}
			target, observed, resolveErr := resolve(ctx, candidate.Identity)
			if resolveErr != nil {
				return placementrelocation.Plan{}, resolveErr
			}
			if observed.ResourceID != candidate.ResourceID || observed.Identity != candidate.Identity || observed.Generation != candidate.Generation || observed.Region != candidate.Region || observed.Slot != candidate.Slot || target.ServerIdentity != candidate.Identity || target.Region != strings.ToUpper(candidate.Region) {
				return placementrelocation.Plan{}, placementrelocation.ErrConflict
			}
			replacement = target
			break
		}
		if replacement.ServerIdentity == "" {
			return placementrelocation.Plan{}, errors.New("runtime relocation: no admitted unused same-Region successor")
		}
		revisions := map[string]uint64{}
		identities := []string{replacement.ServerIdentity}
		for _, member := range proof.Request.Members {
			if member.Identity != request.Member.Identity {
				identities = append(identities, member.Identity)
			}
		}
		for _, identity := range identities {
			target, _, resolveErr := resolve(ctx, identity)
			if resolveErr != nil {
				return placementrelocation.Plan{}, resolveErr
			}
			if target.ServerIdentity != identity {
				return placementrelocation.Plan{}, placementrelocation.ErrConflict
			}
			retained, loadErr := pending.Load(ctx, identity)
			if errors.Is(loadErr, placementpublisher.ErrIntentMissing) && identity == replacement.ServerIdentity {
				// Resolve established a new admitted incarnation, excluded from every
				// prior seat. A missing durable intent proves no Stage was authorized.
				revisions[identity] = 0
				continue
			}
			if loadErr != nil {
				return placementrelocation.Plan{}, loadErr
			}
			stage := newPlacementStageRequest(retained.Request)
			receipt := new(pb.PlacementProposalResponse)
			if stage == nil || len(retained.Receipt) == 0 || proto.Unmarshal(retained.Receipt, receipt) != nil || tbep.ValidatePlacementReceipt(receipt, stage.Proposal) != nil || stage.ExpectedRevision == ^uint64(0) || receipt.Revision != stage.ExpectedRevision+1 {
				return placementrelocation.Plan{}, errors.New("runtime relocation: prior Stage outcome unresolved")
			}
			if identity != replacement.ServerIdentity && (stage.Proposal.Epoch != proof.Request.Epoch || stage.Proposal.Generation != proof.Request.Generation) {
				return placementrelocation.Plan{}, placementrelocation.ErrConflict
			}
			revisions[identity] = receipt.Revision
		}
		return placementrelocation.Build(placementrelocation.BuildInput{OperationID: request.OperationID + "/placement", RemovedIdentity: request.Member.Identity, Replacement: replacement, PriorProof: signed, PriorStage: priorStage, Records: records, Revisions: revisions, AuthoritativeEmptyInventory: len(records) == 0})
	}
}
