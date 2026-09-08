package databaseadmission

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"

	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

// UnusedHostRemoval proves exclusion from the signed accepted scope rather
// than inventing database readiness for an unassigned capacity host.
type UnusedHostRemoval struct {
	OperationID     string
	ScopeID         string
	MemberIdentity  string
	ResourceID      string
	Generation      uint64
	InventoryDigest string
	Head            placementtransition.Signed
}

func validateUnusedHostRemoval(value UnusedHostRemoval) error {
	if value.OperationID == "" || value.ScopeID == "" || value.MemberIdentity == "" || value.ResourceID == "" || value.Generation == 0 || !validDigest(value.InventoryDigest) {
		return ErrInvalid
	}
	var proof placementtransition.Proof
	if json.Unmarshal(value.Head.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.Kind != "accepted_epoch" || proof.SchemaVersion != 1 || proof.Request.ScopeID != value.ScopeID {
		return ErrInvalid
	}
	digest, err := placementtransition.RequestDigest(proof.Request)
	if err != nil || digest != proof.RequestDigest {
		return ErrInvalid
	}
	for _, member := range proof.Request.Members {
		if member.Identity == value.MemberIdentity {
			return ErrConflict
		}
	}
	return nil
}
func beginUnusedHostRemoval(s *journalState, value UnusedHostRemoval, expected []Record, key ed25519.PublicKey) error {
	if validateUnusedHostRemoval(value) != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), value.Head.Payload...), value.Head.Signature) || value.InventoryDigest != placementRecordDigest(expected) {
		return ErrInvalid
	}
	if prior, found := s.UnusedHostRemovals[value.OperationID]; found {
		a, _ := json.Marshal(prior, json.Deterministic(true))
		b, _ := json.Marshal(value, json.Deterministic(true))
		if string(a) != string(b) {
			return ErrConflict
		}
		return nil
	}
	if err := beginPlacementRelocation(s, value.OperationID, expected); err != nil {
		return err
	}
	for _, record := range relocationRecords(*s) {
		for _, target := range record.PlacementTargets {
			if target.ServerIdentity == value.MemberIdentity {
				return ErrConflict
			}
		}
		for _, target := range record.Targets {
			if target.ServerIdentity == value.MemberIdentity {
				return ErrConflict
			}
		}
	}
	if s.UnusedHostRemovals == nil {
		s.UnusedHostRemovals = map[string]UnusedHostRemoval{}
	}
	s.UnusedHostRemovals[value.OperationID] = value
	if s.CompletedRelocations == nil {
		s.CompletedRelocations = map[string]string{}
	}
	// There are no serving placement effects. The admission fence nevertheless
	// stays held until the ordinary host-removal owner records exact termination.
	s.CompletedRelocations[value.OperationID] = value.InventoryDigest
	return nil
}
func (j *NATSJournal) BeginUnusedHostRemoval(ctx context.Context, value UnusedHostRemoval, expected []Record, key ed25519.PublicKey) error {
	if j == nil || j.journal == nil {
		return ErrJournalUnavailable
	}
	return j.journal.Transact(ctx, true, func(s *journalState) error { return beginUnusedHostRemoval(s, value, expected, key) })
}
func (j *NATSJournal) UnusedHostRemoval(ctx context.Context, operation string) (value UnusedHostRemoval, found bool, err error) {
	if j == nil || j.journal == nil {
		return value, false, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(s *journalState) error { value, found = s.UnusedHostRemovals[operation]; return nil })
	return value, found, err
}

// PlacementInventoryDigest binds the complete, canonically ordered snapshot
// returned by RelocationRecords, including the authoritative empty snapshot.
func PlacementInventoryDigest(records []Record) string { return placementRecordDigest(records) }
