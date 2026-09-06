package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// productionHostRemovalCallbacks binds removal to the same placement
// producers used by normal admission. Replacement first persists and
// reconciles the candidate on every target, then activates its retained
// transition proof. Fencing prepares and issues a fresh transition so the
// old RF2 seats contribute authenticated drain receipts.
func productionHostRemovalCallbacks(ports hostRemovalTransitionPorts) (func(context.Context, hostremoval.Replacement) error, func(context.Context, string, string, []hostremoval.Replacement) error, error) {
	if ports.Admission == nil || ports.Placement == nil || ports.Transition == nil || ports.Transition.issuer == nil {
		return nil, nil, errors.New("runtime host removal: placement admission and transition owners are required")
	}
	replace := func(ctx context.Context, replacement hostremoval.Replacement) error {
		record, err := loadReplacementRecord(ctx, ports.Admission, replacement)
		if err != nil {
			return err
		}
		for _, target := range record.PlacementTargets {
			stage := newPlacementStageRequest(target.Proposal)
			if stage == nil {
				return placementtransition.ErrInvalid
			}
			if _, err := ports.Placement.AcceptReceipt(ctx, target.ServerIdentity, replacement.IssuerOperationID, stage); err != nil {
				return err
			}
		}
		if err := ports.Transition.activate(ctx, record, replacement.IssuerOperationID); err != nil {
			return err
		}
		proof, err := ports.Transition.issuer.Load(ctx, replacement.IssuerOperationID)
		if err != nil {
			return err
		}
		if signedDigest(proof) != replacement.ProposalDigest {
			return placementtransition.ErrConflict
		}
		return nil
	}
	fence := func(ctx context.Context, operationID, member string, replacements []hostremoval.Replacement) error {
		if operationID == "" || member == "" || len(replacements) == 0 {
			return placementtransition.ErrInvalid
		}
		seen := map[string]bool{}
		for _, replacement := range replacements {
			if seen[replacement.IssuerOperationID] {
				continue
			}
			seen[replacement.IssuerOperationID] = true
			proof, err := ports.Transition.issuer.Load(ctx, replacement.IssuerOperationID)
			if err != nil {
				return err
			}
			if signedDigest(proof) != replacement.ProposalDigest {
				return placementtransition.ErrConflict
			}
			var accepted placementtransition.Proof
			if json.Unmarshal(proof.Payload, &accepted, json.RejectUnknownMembers(true)) != nil || accepted.Kind != "accepted_epoch" || accepted.Request.OperationID != replacement.IssuerOperationID {
				return placementtransition.ErrInvalid
			}
			if !proofFencesMember(accepted, member) {
				return placementtransition.ErrConflict
			}
		}
		return nil
	}
	return replace, fence, nil
}

func newPlacementStageRequest(data []byte) *pb.PlacementStageRequest {
	request := new(pb.PlacementStageRequest)
	if len(data) == 0 || proto.Unmarshal(data, request) != nil {
		return nil
	}
	return request
}

func loadReplacementRecord(ctx context.Context, journal *databaseadmission.NATSJournal, replacement hostremoval.Replacement) (databaseadmission.Record, error) {
	if replacement.DatabaseID == "" || replacement.IssuerOperationID == "" || replacement.ProposalDigest == "" {
		return databaseadmission.Record{}, placementtransition.ErrInvalid
	}
	records, err := journal.List(ctx)
	if err != nil {
		return databaseadmission.Record{}, err
	}
	for _, record := range records {
		if record.DatabaseID == replacement.DatabaseID && databaseadmission.PlacementOperationID(record.Request) == replacement.IssuerOperationID {
			if databaseadmission.ValidateRecord(record) != nil {
				return databaseadmission.Record{}, placementtransition.ErrInvalid
			}
			return record, nil
		}
	}
	return databaseadmission.Record{}, placementtransition.ErrMissing
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
	for _, signed := range proof.DrainReceipts {
		var receipt placementtransition.DrainReceipt
		if json.Unmarshal(signed.Payload, &receipt, json.RejectUnknownMembers(true)) == nil && receipt.MemberIdentity == identity && receipt.ScopeID == proof.Request.ScopeID && receipt.PriorEpoch == proof.Request.PriorEpoch {
			return true
		}
	}
	return false
}
