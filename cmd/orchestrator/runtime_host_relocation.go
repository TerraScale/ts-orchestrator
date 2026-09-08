package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/placementrelocation"
	"terrascale.tech/orchestrator/src/orchestrator/placementtransition"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

// productionHostRelocation moves a complete scope under one retained successor
// request. Admission remains frozen through authenticated RF2 readiness, the
// current-placement overlay commit, and durable termination of the old host.
type productionHostRelocation struct {
	Unused    *productionUnusedHostRemoval
	Removal   *hostremoval.Journal
	Journal   *placementrelocation.Journal
	Admission *databaseadmission.NATSJournal
	Issuer    interface {
		Head(context.Context, string) (placementtransition.Signed, error)
		Load(context.Context, string) (placementtransition.Signed, error)
		Prepare(context.Context, placementtransition.Request) (placementtransition.Signed, error)
		Issue(context.Context, placementtransition.Request, *placementtransition.Signed, []placementtransition.Signed) (placementtransition.Signed, error)
	}
	ProofKey ed25519.PublicKey
	Check    func(context.Context) error
	Plan     func(context.Context, hostremoval.RemovalRequest, []databaseadmission.Record) (placementrelocation.Plan, error)
	Install  func(context.Context, placementrelocation.Plan) error
	Stage    func(context.Context, string, string, *pb.PlacementStageRequest) (*pb.PlacementProposalResponse, error)
	Drain    func(context.Context, placementtransition.Request, placementtransition.Proof) ([]placementtransition.Signed, error)
	Deliver  func(context.Context, string, string, uint64, placementtransition.Signed) (*pb.PlacementAcceptanceResponse, error)
	Usage    func(context.Context, string, []databaseadmission.Record) error
	Ready    func(context.Context, string, []databaseadmission.Record) ([]databaseadmission.Record, error)
}

func (w *productionHostRelocation) valid() bool {
	return w != nil && w.Journal != nil && w.Admission != nil && w.Issuer != nil && len(w.ProofKey) == ed25519.PublicKeySize && w.Check != nil && w.Plan != nil && w.Install != nil && w.Stage != nil && w.Drain != nil && w.Deliver != nil && w.Usage != nil && w.Ready != nil
}

func (w *productionHostRelocation) Capture(ctx context.Context, request hostremoval.RemovalRequest, _ []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
	if !w.valid() || w.Removal == nil {
		return 0, nil, placementrelocation.ErrInvalid
	}
	if w.Unused != nil {
		if revision, handled, err := w.Unused.capture(ctx, request); handled {
			return revision, nil, err
		}
	}
	id := request.OperationID + "/placement"
	op, err := w.Journal.Load(ctx, id)
	if errors.Is(err, placementrelocation.ErrMissing) {
		records, readErr := w.Admission.RelocationRecords(ctx)
		if readErr != nil {
			return 0, nil, readErr
		}
		plan, planErr := w.Plan(ctx, request, records)
		if planErr != nil {
			return 0, nil, planErr
		}
		if plan.OperationID != id || plan.RemovedIdentity != request.Member.Identity {
			return 0, nil, placementrelocation.ErrConflict
		}
		revision, replacements, inventoryErr := relocationInventory(plan)
		if inventoryErr != nil {
			return 0, nil, inventoryErr
		}
		// The removal owner durably reserved this request before Capture.
		// Validate the exact final inventory against that reserved capacity
		// before acquiring the admission freeze or persisting relocation intent.
		if err = w.Removal.CheckFill(ctx, request.OperationID, request.Member, request.Generation, revision, replacements, request.Survivors); err != nil {
			return 0, nil, err
		}
		// Freeze the exact admission snapshot before retaining an immutable
		// plan. A concurrent admission can reject this attempt without leaving
		// a stale relocation operation that can never be retried.
		if err = w.Admission.BeginPlacementRelocation(ctx, id, plan.Records); err != nil {
			return 0, nil, err
		}
		op, err = w.Journal.Begin(ctx, plan)
		if errors.Is(err, placementrelocation.ErrInvalid) {
			// Only a definitive rejected write plus an authoritative absence
			// permits releasing an unstarted freeze. An unknown write remains
			// retained, and the admission started CAS protects concurrent work.
			if _, loadErr := w.Journal.Load(ctx, id); errors.Is(loadErr, placementrelocation.ErrMissing) {
				if abortErr := w.Admission.AbortUnstartedPlacementRelocation(ctx, id, plan.Records); abortErr != nil {
					return 0, nil, errors.Join(err, abortErr)
				}
			}
		}
	}
	if err != nil {
		return 0, nil, err
	}
	if op.Plan.RemovedIdentity != request.Member.Identity {
		return 0, nil, placementrelocation.ErrConflict
	}
	// Reassert the retained freeze on restart before any placement effect.
	if err = w.Admission.BeginPlacementRelocation(ctx, id, op.Plan.Records); err != nil {
		return 0, nil, err
	}
	return relocationInventory(op.Plan)
}

func relocationInventory(plan placementrelocation.Plan) (uint64, []hostremoval.Replacement, error) {
	revision, err := removalInventoryRevision(plan.Records)
	if err != nil {
		return 0, nil, err
	}
	digest, err := placementtransition.RequestDigest(plan.Request)
	if err != nil {
		return 0, nil, err
	}
	replacements := make([]hostremoval.Replacement, 0, len(plan.Records))
	for _, record := range plan.Records {
		replacements = append(replacements, hostremoval.Replacement{DatabaseID: record.DatabaseID, IssuerOperationID: plan.OperationID, ProposalDigest: digest})
	}
	return revision, replacements, nil
}

func (w *productionHostRelocation) Replace(ctx context.Context, replacement hostremoval.Replacement) error {
	if !w.valid() {
		return placementrelocation.ErrInvalid
	}
	op, err := w.Journal.Load(ctx, replacement.IssuerOperationID)
	if err != nil {
		return err
	}
	digest, err := placementtransition.RequestDigest(op.Plan.Request)
	if err != nil || digest != replacement.ProposalDigest {
		return placementrelocation.ErrConflict
	}
	found := false
	for _, r := range op.Plan.Records {
		found = found || r.DatabaseID == replacement.DatabaseID
	}
	if !found {
		return placementrelocation.ErrConflict
	}
	if op.Ready {
		return w.verifyCommitted(ctx, op)
	}
	// A lost commit response must not require the now-released old snapshot
	// freeze. The authenticated current overlay is durable completion evidence.
	if len(op.Acceptances) == len(op.Plan.Targets) && len(op.Accepted.Payload) > 0 && w.verifyCommitted(ctx, op) == nil {
		_, err = w.Journal.MarkReady(ctx, op.Plan.OperationID)
		return err
	}
	if err = w.Admission.BeginPlacementRelocation(ctx, op.Plan.OperationID, op.Plan.Records); err != nil {
		return err
	}
	if err = w.Admission.MarkPlacementRelocationStarted(ctx, op.Plan.OperationID); err != nil {
		return err
	}
	if err = w.Check(ctx); err != nil {
		return err
	}
	if len(op.Prepared.Payload) == 0 {
		prepared, prepareErr := w.Issuer.Prepare(ctx, op.Plan.Request)
		if prepareErr != nil {
			return prepareErr
		}
		op, err = w.Journal.RecordPrepared(ctx, op.Plan.OperationID, prepared)
		if err != nil {
			return err
		}
	}
	if len(op.Accepted.Payload) == 0 {
		if err = w.Install(ctx, op.Plan); err != nil {
			return err
		}
		for _, target := range op.Plan.Targets {
			if err = w.Check(ctx); err != nil {
				return err
			}
			stage := newPlacementStageRequest(target.Proposal)
			if stage == nil {
				return placementrelocation.ErrInvalid
			}
			receipt, stageErr := w.Stage(ctx, target.ServerIdentity, op.Plan.OperationID, stage)
			if stageErr != nil {
				return stageErr
			}
			if receipt == nil || receipt.Revision != stage.ExpectedRevision+1 || tbep.ValidatePlacementReceipt(receipt, stage.Proposal) != nil {
				return placementrelocation.ErrConflict
			}
		}
		signed, loadErr := w.Issuer.Load(ctx, op.Plan.OperationID)
		if errors.Is(loadErr, placementtransition.ErrMissing) {
			var prior placementtransition.Proof
			if json.Unmarshal(op.Plan.PriorProof.Payload, &prior, json.RejectUnknownMembers(true)) != nil {
				return placementrelocation.ErrInvalid
			}
			receipts, drainErr := w.Drain(ctx, op.Plan.Request, prior)
			if drainErr != nil {
				return drainErr
			}
			if err = w.Check(ctx); err != nil {
				return err
			}
			signed, loadErr = w.Issuer.Issue(ctx, op.Plan.Request, nil, receipts)
		}
		if loadErr != nil {
			return loadErr
		}
		op, err = w.Journal.RecordAccepted(ctx, op.Plan.OperationID, signed)
		if err != nil {
			return err
		}
	}
	if err = w.verifyProof(op); err != nil {
		return err
	}
	for _, target := range op.Plan.Targets {
		if len(op.Acceptances[target.ServerIdentity]) > 0 {
			continue
		}
		if err = w.Check(ctx); err != nil {
			return err
		}
		stage := newPlacementStageRequest(target.Proposal)
		if stage == nil {
			return placementrelocation.ErrInvalid
		}
		receipt, deliverErr := w.Deliver(ctx, target.ServerIdentity, op.Plan.OperationID, stage.ExpectedRevision+1, op.Accepted)
		if deliverErr != nil {
			return deliverErr
		}
		encoded, encodeErr := proto.Marshal(receipt)
		if encodeErr != nil {
			return encodeErr
		}
		op, err = w.Journal.RecordAcceptance(ctx, op.Plan.OperationID, target.ServerIdentity, encoded)
		if err != nil {
			return err
		}
	}
	records, err := relocatedDatabaseRecords(op)
	if err != nil {
		return err
	}
	if err = w.Admission.AllocateRelocationStreams(ctx, op.Plan.OperationID, records, w.ProofKey, time.Now().UTC()); err != nil {
		return err
	}
	if err = w.Check(ctx); err != nil {
		return err
	}
	if err = w.Usage(ctx, op.Plan.OperationID, records); err != nil {
		return err
	}
	records, err = w.Ready(ctx, op.Plan.OperationID, records)
	if err != nil {
		return err
	}
	if err = w.Check(ctx); err != nil {
		return err
	}
	if err = w.Admission.CommitPlacementRelocation(ctx, op.Plan.OperationID, records, w.ProofKey); err != nil {
		return err
	}
	_, err = w.Journal.MarkReady(ctx, op.Plan.OperationID)
	return err
}

func (w *productionHostRelocation) verifyProof(op placementrelocation.Operation) error {
	if !ed25519.Verify(w.ProofKey, append([]byte("terrabase-placement-transition-v1\x00"), op.Accepted.Payload...), op.Accepted.Signature) {
		return placementrelocation.ErrInvalid
	}
	var proof placementtransition.Proof
	if json.Unmarshal(op.Accepted.Payload, &proof, json.RejectUnknownMembers(true)) != nil || !proofFencesMember(proof, op.Plan.RemovedIdentity) {
		return placementrelocation.ErrConflict
	}
	return placementrelocation.ValidateOperation(op)
}
func (w *productionHostRelocation) verifyCommitted(ctx context.Context, op placementrelocation.Operation) error {
	if err := w.verifyProof(op); err != nil {
		return err
	}
	records, err := w.Admission.RelocationRecords(ctx)
	if err != nil {
		return err
	}
	if len(records) != len(op.Plan.Records) {
		return placementrelocation.ErrConflict
	}
	for _, record := range records {
		found := false
		for _, old := range op.Plan.Records {
			found = found || old.DatabaseID == record.DatabaseID
		}
		if !found {
			return placementrelocation.ErrConflict
		}
		for _, target := range record.PlacementTargets {
			if target.AcceptedProofDigest != signedDigest(op.Accepted) || target.AcceptedEpoch != op.Plan.Request.Epoch || target.AcceptedGeneration != op.Plan.Request.Generation || target.ServerIdentity == op.Plan.RemovedIdentity {
				return placementrelocation.ErrConflict
			}
		}
	}
	return nil
}
func (w *productionHostRelocation) Revalidate(ctx context.Context, operation, member string, revision uint64) error {
	if handled, err := w.Unused.revalidate(ctx, operation, member, revision); handled || err != nil {
		return err
	}
	op, err := w.Journal.Load(ctx, operation+"/placement")
	if err != nil {
		return err
	}
	expected, err := removalInventoryRevision(op.Plan.Records)
	if err != nil {
		return err
	}
	if !op.Ready || op.Plan.RemovedIdentity != member || revision != expected {
		return placementrelocation.ErrConflict
	}
	return w.verifyCommitted(ctx, op)
}
func (w *productionHostRelocation) Fence(ctx context.Context, operation, member string, replacements []hostremoval.Replacement) error {
	if w.Unused != nil && len(replacements) == 0 {
		retained, err := w.Removal.Load(ctx, operation)
		if err != nil {
			return err
		}
		if handled, err := w.Unused.revalidate(ctx, operation, member, retained.InventoryRevision); handled || err != nil {
			return err
		}
	}
	op, err := w.Journal.Load(ctx, operation+"/placement")
	if err != nil {
		return err
	}
	if !op.Ready || op.Plan.RemovedIdentity != member || len(replacements) != len(op.Plan.Records) {
		return placementrelocation.ErrConflict
	}
	return w.verifyCommitted(ctx, op)
}
