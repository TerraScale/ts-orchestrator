package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
)

type productionUnusedHostRemoval struct {
	Scope     string
	Admission *databaseadmission.NATSJournal
	Removal   *hostremoval.Journal
	Head      func(context.Context, string) (placementtransition.Signed, error)
	ProofKey  ed25519.PublicKey
	Check     func(context.Context) error
}

func (u *productionUnusedHostRemoval) capture(ctx context.Context, request hostremoval.RemovalRequest) (uint64, bool, error) {
	if u == nil {
		return 0, false, nil
	}
	if u.Admission == nil || u.Removal == nil || u.Head == nil || u.Check == nil || len(u.ProofKey) != ed25519.PublicKeySize || u.Scope == "" {
		return 0, true, hostremoval.ErrInvalid
	}
	if err := u.Check(ctx); err != nil {
		return 0, true, err
	}
	operation := request.OperationID + "/placement"
	retained, found, err := u.Admission.UnusedHostRemoval(ctx, operation)
	if err != nil {
		return 0, true, err
	}
	if found {
		if retained.MemberIdentity != request.Member.Identity || retained.ResourceID != request.Member.ResourceID || retained.Generation != request.Generation {
			return 0, true, hostremoval.ErrConflict
		}
		records, err := u.Admission.RelocationRecords(ctx)
		if err != nil {
			return 0, true, err
		}
		revision, err := removalInventoryRevision(records)
		if err != nil {
			return 0, true, err
		}
		return revision, true, u.verify(ctx, retained)
	}
	signed, err := u.Head(ctx, u.Scope)
	if err != nil {
		return 0, true, err
	}
	proof, err := unusedRemovalProof(signed, u.ProofKey, u.Scope, request)
	if err != nil {
		return 0, true, err
	}
	for _, member := range proof.Request.Members {
		if member.Identity == request.Member.Identity {
			return 0, false, nil
		}
	}
	records, err := u.Admission.RelocationRecords(ctx)
	if err != nil {
		return 0, true, err
	}
	revision, err := removalInventoryRevision(records)
	if err != nil {
		return 0, true, err
	}
	if err := u.Removal.CheckFill(ctx, request.OperationID, request.Member, request.Generation, revision, nil, request.Survivors); err != nil {
		return 0, true, err
	}
	retained = databaseadmission.UnusedHostRemoval{OperationID: operation, ScopeID: u.Scope, MemberIdentity: request.Member.Identity, ResourceID: request.Member.ResourceID, Generation: request.Generation, InventoryDigest: databaseadmission.PlacementInventoryDigest(records), Head: signed}
	if err := u.Admission.BeginUnusedHostRemoval(ctx, retained, records, u.ProofKey); err != nil {
		return 0, true, err
	}
	return revision, true, u.verify(ctx, retained)
}
func unusedRemovalProof(signed placementtransition.Signed, key ed25519.PublicKey, scope string, request hostremoval.RemovalRequest) (placementtransition.Proof, error) {
	var proof placementtransition.Proof
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("terrabase-placement-transition-v1\x00"), signed.Payload...), signed.Signature) || json.Unmarshal(signed.Payload, &proof, json.RejectUnknownMembers(true)) != nil || proof.SchemaVersion != 1 || proof.Kind != "accepted_epoch" || proof.Request.ScopeID != scope {
		return proof, hostremoval.ErrInvalid
	}
	digest, err := placementtransition.RequestDigest(proof.Request)
	if err != nil || digest != proof.RequestDigest {
		return proof, hostremoval.ErrInvalid
	}
	if request.Member.ResourceID == "" || request.Generation == 0 || request.Generation != request.Member.Generation || request.Member.Slot < 1 {
		return proof, hostremoval.ErrInvalid
	}
	survivors := map[string]bool{}
	sameRegion := 0
	for _, member := range request.Survivors {
		if member.Identity == request.Member.Identity || survivors[member.Identity] || member.ResourceID == "" || member.Generation == 0 || member.Slot < 1 {
			return proof, hostremoval.ErrInvalid
		}
		survivors[member.Identity] = true
		if strings.EqualFold(member.Region, request.Member.Region) {
			sameRegion++
		}
	}
	if sameRegion < 2 {
		return proof, hostremoval.ErrConflict
	}
	// Both admitted RF2 seats in this Region must survive. An unused host never
	// substitutes an unaccepted peer for a signed serving seat.
	for _, member := range proof.Request.Members {
		if strings.EqualFold(member.Region, request.Member.Region) && member.Identity != request.Member.Identity && !survivors[member.Identity] {
			return proof, hostremoval.ErrConflict
		}
	}
	return proof, nil
}
func (u *productionUnusedHostRemoval) verify(ctx context.Context, value databaseadmission.UnusedHostRemoval) error {
	if err := u.Check(ctx); err != nil {
		return err
	}
	head, err := u.Head(ctx, value.ScopeID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(u.ProofKey, append([]byte("terrabase-placement-transition-v1\x00"), head.Payload...), head.Signature) || signedDigest(head) != signedDigest(value.Head) || head.KeyID != value.Head.KeyID {
		return hostremoval.ErrConflict
	}
	records, err := u.Admission.RelocationRecords(ctx)
	if err != nil {
		return err
	}
	if databaseadmission.PlacementInventoryDigest(records) != value.InventoryDigest {
		return hostremoval.ErrConflict
	}
	return nil
}
func (u *productionUnusedHostRemoval) revalidate(ctx context.Context, operation, member string, revision uint64) (bool, error) {
	if u == nil {
		return false, nil
	}
	value, found, err := u.Admission.UnusedHostRemoval(ctx, operation+"/placement")
	if err != nil || !found {
		return found, err
	}
	retained, err := u.Removal.Load(ctx, operation)
	if err != nil {
		return true, err
	}
	if value.MemberIdentity != member || value.ResourceID != retained.ResourceID || value.Generation != retained.Generation || retained.InventoryRevision != revision {
		return true, hostremoval.ErrConflict
	}
	return true, u.verify(ctx, value)
}
