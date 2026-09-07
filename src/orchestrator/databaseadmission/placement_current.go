package databaseadmission

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"reflect"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// CurrentRecords is the accepted placement view. Records remains the immutable
// admission history; relocation and deletion serialize on this same journal.
func (j *NATSJournal) CurrentRecords(ctx context.Context) (out []Record, err error) {
	if j == nil || j.journal == nil {
		return nil, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error { out = currentPlacementRecords(*s); return nil })
	return out, err
}
func currentPlacementRecords(s journalState) []Record {
	out := make([]Record, 0, len(s.Records))
	for key, record := range s.Records {
		if current, ok := s.CurrentPlacements[key]; ok {
			record = current
		}
		out = append(out, record)
	}
	slices.SortFunc(out, func(a, b Record) int { return cmp.Compare(ScopeKey(a.Request), ScopeKey(b.Request)) })
	return out
}
func placementRecordDigest(records []Record) string {
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b Record) int { return cmp.Compare(ScopeKey(a.Request), ScopeKey(b.Request)) })
	data, err := json.Marshal(records)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func sameAdmissionIdentity(original, current Record) bool {
	original.Targets, original.PlacementTargets = nil, nil
	current.Targets, current.PlacementTargets = nil, nil
	return reflect.DeepEqual(original, current)
}
func validateCurrentPlacements(s journalState) error {
	for key, current := range s.CurrentPlacements {
		original, ok := s.Records[key]
		if !ok || !sameAdmissionIdentity(original, current) || ValidateRecord(current) != nil {
			return ErrInvalid
		}
	}
	return nil
}
func beginPlacementRelocation(s *journalState, operation string, expected []Record) error {
	if operation == "" || len(expected) == 0 {
		return ErrInvalid
	}
	if _, completed := s.CompletedRelocations[operation]; completed {
		return nil
	}
	if s.PlacementRelocation != "" && s.PlacementRelocation != operation {
		return ErrConflict
	}
	current := currentPlacementRecords(*s)
	if placementRecordDigest(current) != placementRecordDigest(expected) {
		return ErrConflict
	}
	for _, r := range current {
		if r.State != "ready" {
			return ErrConflict
		}
	}
	// A deletion captures regional preparation and stop effects. Its current
	// member targets must remain fixed until its retained cleanup is complete.
	if len(s.Deletions) != 0 {
		return ErrConflict
	}
	s.PlacementRelocation = operation
	return nil
}
func (j *NATSJournal) BeginPlacementRelocation(ctx context.Context, operation string, expected []Record) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error { return beginPlacementRelocation(s, operation, expected) })
}
func (j *NATSJournal) CommitPlacementRelocation(ctx context.Context, operation string, records []Record, proofKey ed25519.PublicKey) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error { return commitPlacementRelocation(s, operation, records, proofKey) })
}
func commitPlacementRelocation(s *journalState, operation string, records []Record, proofKey ed25519.PublicKey) error {
	digest := placementRecordDigest(records)
	if prior, ok := s.CompletedRelocations[operation]; ok {
		if prior == digest {
			return nil
		}
		return ErrConflict
	}
	if operation == "" || s.PlacementRelocation != operation || len(records) != len(s.Records) || len(proofKey) != ed25519.PublicKeySize {
		return ErrConflict
	}
	prior := currentPlacementRecords(*s)
	previous := map[string]Record{}
	for _, record := range prior {
		previous[ScopeKey(record.Request)] = record
	}
	next := make(map[string]Record, len(records))
	for _, record := range records {
		key := ScopeKey(record.Request)
		old, ok := previous[key]
		if !ok || next[key].DatabaseID != "" || !sameAdmissionIdentity(old, record) || ValidateRecord(record) != nil {
			return ErrConflict
		}
		if err := verifySuccessorPlacement(old, record, operation, proofKey); err != nil {
			return err
		}
		next[key] = record
	}
	s.CurrentPlacements = next
	if s.CompletedRelocations == nil {
		s.CompletedRelocations = map[string]string{}
	}
	s.CompletedRelocations[operation] = digest
	s.PlacementRelocation = ""
	return nil
}
func verifySuccessorPlacement(old, current Record, operation string, key ed25519.PublicKey) error {
	if len(old.PlacementTargets) == 0 || len(current.PlacementTargets) == 0 {
		return ErrInvalid
	}
	previous := old.PlacementTargets[0]
	for _, target := range old.PlacementTargets {
		if target.AcceptedEpoch != previous.AcceptedEpoch || target.AcceptedGeneration != previous.AcceptedGeneration || target.AcceptedProofDigest != previous.AcceptedProofDigest {
			return ErrConflict
		}
	}
	var shared string
	for _, target := range current.PlacementTargets {
		var signed placementtransition.Signed
		var proof placementtransition.Proof
		receipt := new(pb.PlacementAcceptanceResponse)
		stage := new(pb.PlacementStageRequest)
		if json.Unmarshal(target.AcceptedProof, &signed, json.RejectUnknownMembers(true)) != nil || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), signed.Payload...), signed.Signature) || json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.Kind != "accepted_epoch" || proof.Request.OperationID != operation || proof.Request.PriorEpoch != previous.AcceptedEpoch || proof.PreviousProofDigest != previous.AcceptedProofDigest || proof.PriorGeneration != previous.AcceptedGeneration || proof.Request.Generation <= previous.AcceptedGeneration {
			return ErrInvalid
		}
		requestDigest, err := placementtransition.RequestDigest(proof.Request)
		if err != nil || requestDigest != proof.RequestDigest || proof.SchemaVersion != 1 {
			return ErrInvalid
		}
		sum := sha256.Sum256(signed.Payload)
		digest := hex.EncodeToString(sum[:])
		if shared != "" && shared != digest {
			return ErrConflict
		}
		shared = digest
		if proto.Unmarshal(target.AcceptedReceipt, receipt) != nil || receipt.Status != pb.PlacementAcceptanceStatus_PLACEMENT_ACCEPTANCE_STATUS_ADMITTED_CATCHING_UP || receipt.ProposalRevision != target.AcceptedRevision || receipt.Epoch != proof.Request.Epoch || receipt.Generation != proof.Request.Generation || receipt.ProofDigest != digest || target.AcceptedEpoch != receipt.Epoch || target.AcceptedGeneration != receipt.Generation || target.AcceptedProofDigest != digest || receipt.ProposalRevision == 0 {
			return ErrInvalid
		}
		if proto.Unmarshal(target.Proposal, stage) != nil || stage.Proposal == nil || stage.Proposal.Epoch != receipt.Epoch || stage.Proposal.Generation != receipt.Generation || proof.Request.ScopeID != stage.Proposal.Environment+"/"+stage.Proposal.Cluster {
			return ErrInvalid
		}
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(stage.Proposal)
		if err != nil {
			return err
		}
		proposalSum := sha256.Sum256(data)
		found := false
		for _, member := range proof.Request.Members {
			if member.Identity == target.ServerIdentity && member.Region == target.Region && member.PlacementDigest == hex.EncodeToString(proposalSum[:]) {
				found = true
			}
		}
		if !found || len(proof.Request.Members) != len(current.PlacementTargets) {
			return ErrInvalid
		}
	}
	return nil
}

// AllocateRelocationStreams advances usage stream authority only for a fully
// accepted successor while its admission fence still excludes deletion. The
// immutable admission map is used only as history and is never overwritten.
func (j *NATSJournal) AllocateRelocationStreams(ctx context.Context, operation string, records []Record, proofKey ed25519.PublicKey, now time.Time) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if s.PlacementRelocation != operation || operation == "" {
			return ErrConflict
		}
		candidate, err := cloneState(*s)
		if err != nil {
			return err
		}
		if err := commitPlacementRelocation(&candidate, operation, records, proofKey); err != nil {
			return err
		}
		// Validation above authenticates every scope and target before the first
		// stream change. Allocation sees that complete accepted candidate view.
		candidate.Records = candidate.CurrentPlacements
		for _, record := range records {
			if err := allocatePlacementStreams(&candidate, record, record.PlacementTargets[0].AcceptedProofDigest, now); err != nil {
				return err
			}
		}
		s.Lifecycle = candidate.Lifecycle
		return nil
	})
}
