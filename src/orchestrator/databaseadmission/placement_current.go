package databaseadmission

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
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
	// Readiness belongs to the accepted placement incarnation. The original
	// admission evidence stays in Records; current readiness is separately bound
	// to the signed successor operation by validateCurrentReadiness.
	original.ReadinessNonce, original.ReadyEvidence = "", nil
	current.ReadinessNonce, current.ReadyEvidence = "", nil
	original.Targets, original.PlacementTargets = nil, nil
	current.Targets, current.PlacementTargets = nil, nil
	a, err := json.Marshal(original, json.Deterministic(true))
	if err != nil {
		return false
	}
	b, err := json.Marshal(current, json.Deterministic(true))
	return err == nil && bytes.Equal(a, b)
}
func validateCurrentPlacements(s journalState) error {
	for operation, canceled := range s.CanceledPlacementRelocations {
		if operation == "" || !canceled || s.PlacementRelocation == operation || s.CompletedRelocations[operation] != "" {
			return ErrInvalid
		}
	}
	for operation, empty := range s.EmptyPlacementRelocations {
		if operation != empty.Binding.OperationID || empty.Binding.ScopeID == "" || empty.Binding.MemberIdentity == "" || empty.Binding.ResourceID == "" || empty.Binding.Generation == 0 || empty.Binding.InventoryDigest != placementRecordDigest(nil) {
			return ErrInvalid
		}
		if len(empty.Accepted.Payload) > 0 {
			sum := sha256.Sum256(empty.Accepted.Payload)
			if s.CompletedRelocations[operation] != hex.EncodeToString(sum[:]) || len(empty.Targets) == 0 {
				return ErrInvalid
			}
		}
	}
	for operation, removal := range s.UnusedHostRemovals {
		if operation != removal.OperationID || validateUnusedHostRemoval(removal) != nil {
			return ErrInvalid
		}
	}
	if s.PlacementRelocationStarted && s.PlacementRelocation == "" {
		return ErrInvalid
	}
	for key, current := range s.CurrentPlacements {
		original, ok := s.Records[key]
		if !ok || !sameAdmissionIdentity(original, current) || ValidateRecord(current) != nil || validateCurrentReadiness(original, current) != nil {
			return ErrInvalid
		}
	}
	return nil
}
func beginPlacementRelocation(s *journalState, operation string, expected []Record) error {
	if s.CanceledPlacementRelocations[operation] {
		return ErrConflict
	}
	if operation == "" {
		return ErrInvalid
	}
	if _, completed := s.CompletedRelocations[operation]; completed {
		return nil
	}
	if s.PlacementRelocation != "" && s.PlacementRelocation != operation {
		return ErrConflict
	}
	current := relocationRecords(*s)
	if placementRecordDigest(current) != placementRecordDigest(expected) {
		return ErrConflict
	}
	for _, r := range current {
		for _, resource := range s.Lifecycle.Resources {
			if resource.DatabaseID == r.DatabaseID && (!resource.DeletedAt.IsZero() || resource.AccessRevoked || !resource.UsageStoppedAt.IsZero()) {
				return ErrConflict
			}
		}
		if r.State != "ready" {
			return ErrConflict
		}
	}
	// A deletion captures regional preparation and stop effects. Its current
	// member targets must remain fixed until its retained cleanup is complete.
	for _, deletion := range s.Deletions {
		// A cancelled deletion has no pending stop or cleanup effects and
		// must not fence estate-wide placement work forever.
		if deletion.State == "cancelled" {
			continue
		}
		if len(deletion.Targets) == 0 {
			return ErrConflict
		}
		for _, target := range deletion.Targets {
			completed := false
			for _, resource := range s.Lifecycle.Resources {
				if resource.Identity == target.Stop.Identity && inactivePlacementResource(resource) {
					completed = true
				}
			}
			if !completed {
				return ErrConflict
			}
		}
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
	if operation == "" || len(records) == 0 || s.PlacementRelocation != operation || !s.PlacementRelocationStarted || len(records) != len(relocationRecords(*s)) || len(proofKey) != ed25519.PublicKeySize {
		return ErrConflict
	}
	prior := relocationRecords(*s)
	previous := map[string]Record{}
	for _, record := range prior {
		previous[ScopeKey(record.Request)] = record
	}
	next := maps.Clone(s.CurrentPlacements)
	if next == nil {
		next = map[string]Record{}
	}
	seen := map[string]bool{}
	var acceptedDigest string
	for _, record := range records {
		key := ScopeKey(record.Request)
		old, ok := previous[key]
		if !ok || seen[key] || !sameAdmissionIdentity(old, record) || ValidateRecord(record) != nil {
			return ErrConflict
		}
		if len(record.PlacementTargets) == 0 {
			return ErrInvalid
		}
		candidateDigest := record.PlacementTargets[0].AcceptedProofDigest
		if acceptedDigest != "" && candidateDigest != acceptedDigest {
			return ErrConflict
		}
		acceptedDigest = candidateDigest
		if err := validateCurrentReadiness(old, record); err != nil {
			return err
		}
		if err := verifySuccessorPlacement(old, record, operation, proofKey); err != nil {
			return err
		}
		next[key] = record
		seen[key] = true
	}
	s.CurrentPlacements = next
	if s.CompletedRelocations == nil {
		s.CompletedRelocations = map[string]string{}
	}
	s.CompletedRelocations[operation] = digest
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
	return j.journal.Transact(ctx, true, func(s *journalState) error { return allocateRelocationStreams(s, operation, records, proofKey, now) })
}
func allocateRelocationStreams(s *journalState, operation string, records []Record, proofKey ed25519.PublicKey, now time.Time) error {
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
	candidate.Records = maps.Clone(candidate.Records)
	for key, record := range candidate.CurrentPlacements {
		candidate.Records[key] = record
	}
	for _, record := range records {
		if err := allocatePlacementStreams(&candidate, record, record.PlacementTargets[0].AcceptedProofDigest, now); err != nil {
			return err
		}
	}
	s.Lifecycle = candidate.Lifecycle
	return nil
}

// RelocationRecords excludes only databases whose physical retained cleanup is
// authoritatively complete. Stopped usage or revoked access alone is insufficient.
func (j *NATSJournal) RelocationRecords(ctx context.Context) (out []Record, err error) {
	if j == nil || j.journal == nil {
		return nil, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error { out = relocationRecords(*s); return nil })
	return out, err
}
func inactivePlacementResource(r databaselifecycle.Resource) bool {
	return !r.DeletedAt.IsZero() && r.AccessRevoked && !r.UsageStoppedAt.IsZero() && !r.EffectsCompletedAt.IsZero() && !r.EffectsCompletedAt.Before(r.DeletedAt)
}
func relocationRecords(s journalState) []Record {
	records := currentPlacementRecords(s)
	return slices.DeleteFunc(records, func(record Record) bool {
		for _, resource := range s.Lifecycle.Resources {
			if resource.Environment == record.Request.Environment && resource.OrganizationID == record.Request.TenantID && resource.ProjectID == record.Request.ProjectID && resource.DatabaseID == record.DatabaseID && inactivePlacementResource(resource) {
				return true
			}
		}
		return false
	})
}

// FinishPlacementRelocation releases the admission fence after the caller has
// observed the durable terminal host-removal result. A committed successor
// alone does not prove that destructive host effects are complete.
func (j *NATSJournal) FinishPlacementRelocation(ctx context.Context, operation string) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if operation == "" || s.CompletedRelocations[operation] == "" {
			return ErrConflict
		}
		if s.PlacementRelocation == "" {
			return nil
		}
		if s.PlacementRelocation != operation {
			return ErrConflict
		}
		s.PlacementRelocation = ""
		s.PlacementRelocationStarted = false
		return nil
	})
}

// MarkPlacementRelocationStarted is the same-CAS authorization boundary before
// the first remote effect. A concurrent unstarted abort must win or lose here.
func (j *NATSJournal) MarkPlacementRelocationStarted(ctx context.Context, operation string) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if operation == "" || s.PlacementRelocation != operation {
			return ErrConflict
		}
		s.PlacementRelocationStarted = true
		return nil
	})
}
func (j *NATSJournal) AbortUnstartedPlacementRelocation(ctx context.Context, operation string, expected []Record) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if operation == "" || s.PlacementRelocation != operation || s.PlacementRelocationStarted || s.CompletedRelocations[operation] != "" || placementRecordDigest(relocationRecords(*s)) != placementRecordDigest(expected) {
			return ErrConflict
		}
		s.PlacementRelocation = ""
		return nil
	})
}

// Pinned member signatures and freshness are checked by the runtime Ready
// collector before commit. Retained current evidence must continue to match
// the exact accepted successor operation, placement tuple and RF2 boundary.
func validateCurrentReadiness(original, current Record) error {
	a, err := json.Marshal(original.ReadyEvidence, json.Deterministic(true))
	if err != nil {
		return err
	}
	b, err := json.Marshal(current.ReadyEvidence, json.Deterministic(true))
	if err != nil {
		return err
	}
	if original.ReadinessNonce == current.ReadinessNonce && bytes.Equal(a, b) {
		return nil
	}
	if len(current.PlacementTargets) == 0 {
		return ErrInvalid
	}
	var signed placementtransition.Signed
	var proof placementtransition.Proof
	if json.Unmarshal(current.PlacementTargets[0].AcceptedProof, &signed, json.RejectUnknownMembers(true)) != nil || json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.Kind != "accepted_epoch" {
		return ErrInvalid
	}
	return validateReadinessOperation(current, proof.Request.OperationID, current.ReadyEvidence, current.ReadinessNonce, nil, time.Time{})
}

// CancelUnstartedPlacementRelocation tombstones a never-frozen operation before
// its pending host reservation is removed. Freeze-before-plan ordering makes
// cancellation and initial capture mutually exclusive in this same CAS.
func (j *NATSJournal) CancelUnstartedPlacementRelocation(ctx context.Context, operation string) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error {
		if operation == "" || s.PlacementRelocation == operation || s.CompletedRelocations[operation] != "" || s.UnusedHostRemovals[operation].OperationID != "" || s.EmptyPlacementRelocations[operation].Binding.OperationID != "" {
			return ErrConflict
		}
		if s.CanceledPlacementRelocations == nil {
			s.CanceledPlacementRelocations = map[string]bool{}
		}
		s.CanceledPlacementRelocations[operation] = true
		return nil
	})
}

func (j *NATSJournal) PlacementRelocationCancelled(ctx context.Context, operation string) (canceled bool, err error) {
	if j == nil || j.journal == nil {
		return false, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error { canceled = s.CanceledPlacementRelocations[operation]; return nil })
	return canceled, err
}
