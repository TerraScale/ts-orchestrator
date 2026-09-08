package databaseadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// EmptyPlacementRelocation retains a genuine signed topology successor when
// no active database remains. It never manufactures database readiness.
type EmptyPlacementRelocation struct {
	Binding  UnusedHostRemoval
	Accepted placementtransition.Signed
	Targets  []PlacementTarget
}

func emptyPrior(value UnusedHostRemoval, key ed25519.PublicKey) (placementtransition.Proof, error) {
	var prior placementtransition.Proof
	if value.OperationID == "" || value.ScopeID == "" || value.MemberIdentity == "" || value.ResourceID == "" || value.Generation == 0 || value.InventoryDigest != placementRecordDigest(nil) || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), value.Head.Payload...), value.Head.Signature) || json.Unmarshal(value.Head.Payload, &prior, json.RejectUnknownMembers(true)) != nil || prior.Kind != "accepted_epoch" || prior.SchemaVersion != 1 || prior.Request.ScopeID != value.ScopeID {
		return prior, ErrInvalid
	}
	digest, err := placementtransition.RequestDigest(prior.Request)
	if err != nil || digest != prior.RequestDigest {
		return prior, ErrInvalid
	}
	for _, member := range prior.Request.Members {
		if member.Identity == value.MemberIdentity {
			return prior, nil
		}
	}
	return prior, ErrConflict
}
func (j *NATSJournal) BeginEmptyPlacementRelocation(ctx context.Context, value UnusedHostRemoval, key ed25519.PublicKey) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	if _, err := emptyPrior(value, key); err != nil {
		return err
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if prior, ok := s.EmptyPlacementRelocations[value.OperationID]; ok {
			a, _ := json.Marshal(prior.Binding, json.Deterministic(true))
			b, _ := json.Marshal(value, json.Deterministic(true))
			if !bytes.Equal(a, b) {
				return ErrConflict
			}
			return nil
		}
		if err := beginPlacementRelocation(s, value.OperationID, nil); err != nil {
			return err
		}
		if s.EmptyPlacementRelocations == nil {
			s.EmptyPlacementRelocations = map[string]EmptyPlacementRelocation{}
		}
		s.EmptyPlacementRelocations[value.OperationID] = EmptyPlacementRelocation{Binding: value}
		return nil
	})
}
func (j *NATSJournal) EmptyPlacementRelocation(ctx context.Context, operation string) (value EmptyPlacementRelocation, found bool, err error) {
	if j == nil || j.journal == nil {
		return value, false, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error { value, found = s.EmptyPlacementRelocations[operation]; return nil })
	return value, found, err
}
func (j *NATSJournal) CommitEmptyPlacementRelocation(ctx context.Context, operation string, accepted placementtransition.Signed, targets []PlacementTarget, key ed25519.PublicKey) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		return commitEmptyPlacementRelocation(s, operation, accepted, targets, key)
	})
}
func commitEmptyPlacementRelocation(s *journalState, operation string, accepted placementtransition.Signed, targets []PlacementTarget, key ed25519.PublicKey) error {
	retained, ok := s.EmptyPlacementRelocations[operation]
	if !ok || len(relocationRecords(*s)) != 0 || operation == "" {
		return ErrConflict
	}
	prior, err := emptyPrior(retained.Binding, key)
	if err != nil {
		return err
	}
	if err := validateEmptySuccessor(retained.Binding, prior, accepted, targets, key); err != nil {
		return err
	}
	sum := sha256.Sum256(accepted.Payload)
	digest := hex.EncodeToString(sum[:])
	if completed, ok := s.CompletedRelocations[operation]; ok {
		if completed == digest {
			return nil
		}
		return ErrConflict
	}
	if s.PlacementRelocation != operation || !s.PlacementRelocationStarted {
		return ErrConflict
	}
	retained.Accepted = accepted
	retained.Targets = slices.Clone(targets)
	s.EmptyPlacementRelocations[operation] = retained
	if s.CompletedRelocations == nil {
		s.CompletedRelocations = map[string]string{}
	}
	s.CompletedRelocations[operation] = digest
	return nil
}
func validateEmptySuccessor(binding UnusedHostRemoval, prior placementtransition.Proof, accepted placementtransition.Signed, targets []PlacementTarget, key ed25519.PublicKey) error {
	if len(targets) == 0 {
		return ErrInvalid
	}
	var proof placementtransition.Proof
	if json.Unmarshal(accepted.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.Kind != "accepted_epoch" || proof.Request.ScopeID != binding.ScopeID {
		return ErrInvalid
	}
	oldRegions, newRegions := map[string]int{}, map[string]int{}
	for _, member := range prior.Request.Members {
		oldRegions[member.Region]++
	}
	for _, member := range proof.Request.Members {
		if member.Identity == binding.MemberIdentity {
			return ErrConflict
		}
		newRegions[member.Region]++
	}
	if !maps.Equal(oldRegions, newRegions) {
		return ErrConflict
	}
	sum := sha256.Sum256(binding.Head.Payload)
	old := Record{PlacementTargets: []PlacementTarget{{AcceptedEpoch: prior.Request.Epoch, AcceptedGeneration: prior.Request.Generation, AcceptedProofDigest: hex.EncodeToString(sum[:])}}}
	current := Record{PlacementTargets: targets}
	encoded, err := json.Marshal(accepted)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if seen[target.ServerIdentity] || !bytes.Equal(target.AcceptedProof, encoded) {
			return ErrInvalid
		}
		seen[target.ServerIdentity] = true
		stage := new(pb.PlacementStageRequest)
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil || len(stage.Proposal.Assignments) != 0 || len(stage.Declarations) != 0 || stage.ExpectedRevision == ^uint64(0) || target.AcceptedRevision != stage.ExpectedRevision+1 || target.ServerIdentity != "spiffe://terrascale.tech/"+stage.Proposal.Environment+"/terrabase-member/"+stage.Proposal.Cluster+"/"+target.MemberID {
			return ErrInvalid
		}
	}
	return verifySuccessorPlacement(old, current, binding.OperationID, key)
}
