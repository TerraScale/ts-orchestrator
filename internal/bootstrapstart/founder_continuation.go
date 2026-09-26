package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

var ErrFounderPeerContinuation = errors.New("current founder peer continuation is unavailable")

// FounderPeerContinuation verifies a current selected plan against an already
// accepted, historically completed peer. It grants no OCI or ledger effects.
type FounderPeerContinuation struct {
	reader     *CurrentFounderAuthorityReader
	floor      *FounderSelectionFloorStore
	serviceUID uint32
	serviceGID uint32
	now        func() time.Time
}

func NewOCIFounderPeerContinuation(baked BakedInputs, accepted AcceptedInstall,
	serviceUID, serviceGID uint32,
) (*FounderPeerContinuation, error) {
	if serviceUID == 0 || serviceGID == 0 || accepted.Slot == accepted.SeedSlot {
		return nil, ErrFounderPeerContinuation
	}
	floor, err := NewServiceFounderSelectionFloorStore(serviceUID)
	if err != nil {
		return nil, err
	}
	reader, err := NewOCICurrentFounderAuthorityReader(baked, accepted, floor)
	if err != nil {
		return nil, err
	}
	return &FounderPeerContinuation{reader: reader, floor: floor,
		serviceUID: serviceUID, serviceGID: serviceGID, now: time.Now}, nil
}

// Initialize is called only after first-install Gate checks, before its
// accepted marker is published. A crash can replay or advance the floor, but
// a missing or rolled-back current selector cannot create a marker.
func (checker *FounderPeerContinuation) Initialize(ctx context.Context, marker AcceptedInstall,
	state bootstrap.SlotState, now time.Time,
) error {
	if checker == nil || checker.reader == nil || checker.floor == nil ||
		checker.serviceUID == 0 || checker.serviceGID == 0 || checker.now == nil ||
		now.IsZero() || now.Location() != time.UTC {
		return ErrFounderPeerContinuation
	}
	started := time.Now()
	selected, err := checker.reader.readCurrentPeerInitial(ctx, now)
	if err != nil {
		return fmt.Errorf("%w: read current selected founder proof: %v", ErrFounderPeerContinuation, err)
	}
	if err := checker.checkBindings(marker, state, selected, now); err != nil {
		return err
	}
	if err := prepareFounderFloorOwner(checker.floor, checker.serviceUID, checker.serviceGID); err != nil {
		return fmt.Errorf("%w: prepare peer selection floor: %v", ErrFounderPeerContinuation, err)
	}
	if err := checker.floor.InitializePeerForService(selected.SelectionGeneration, selected.SelectionSHA256,
		checker.serviceGID); err != nil {
		return fmt.Errorf("%w: publish peer selection floor: %v", ErrFounderPeerContinuation, err)
	}
	if err := checker.reader.confirmCurrentPeerSelection(ctx, selected,
		func() time.Time { return checker.now().Round(0).UTC().Add(time.Since(started)) }); err != nil {
		return fmt.Errorf("%w: selector changed after floor publication: %v", ErrFounderPeerContinuation, err)
	}
	return nil
}

func (checker *FounderPeerContinuation) VerifyCurrentContinuation(ctx context.Context,
	marker AcceptedInstall, observed InstanceObservation, state bootstrap.SlotState,
) error {
	if checker == nil || checker.reader == nil || checker.floor == nil || checker.now == nil ||
		observed.InstanceOCID != marker.InstanceOCID {
		return ErrFounderPeerContinuation
	}
	now := checker.now().Round(0).UTC()
	selected, err := checker.reader.readCurrentPeerContinuation(ctx, now)
	if err != nil {
		return fmt.Errorf("%w: read floor-checked current selection: %v", ErrFounderPeerContinuation, err)
	}
	if err := checker.checkBindings(marker, state, selected, now); err != nil {
		return err
	}
	if err := checker.reader.confirmCurrentPeerSelection(ctx, selected, checker.now); err != nil {
		return fmt.Errorf("%w: selected founder proof changed: %v", ErrFounderPeerContinuation, err)
	}
	return nil
}

func (checker *FounderPeerContinuation) checkBindings(marker AcceptedInstall, state bootstrap.SlotState,
	selected currentFounderPeerSelection, now time.Time,
) error {
	if marker.validate() != nil || marker.Slot == marker.SeedSlot ||
		checker.reader.accepted.Slot != marker.Slot ||
		checker.reader.accepted.SeedSlot != marker.SeedSlot ||
		checker.reader.accepted.AnchorSHA256 != marker.AnchorSHA256 ||
		checker.reader.accepted.ManifestSHA256 != marker.ManifestSHA256 ||
		!selected.Anchor.IsVerified() || !selected.Plan.IsVerified() ||
		selected.Anchor.Digest() != marker.AnchorSHA256 ||
		selected.Plan.Digest() != state.Intent.FounderPlanSHA256 ||
		state.Intent.SchemaVersion != 2 || state.Intent.Mode != bootstrap.IntentModeManaged ||
		state.Head.SchemaVersion != 2 || state.Head.ResultDigest != marker.ResultSHA256 ||
		state.Result == nil || state.ResultRecord == nil || state.Candidate == nil || state.CandidateRecord == nil ||
		state.ManifestRecord == nil || state.PeerReceiptRecord == nil ||
		state.ResultRecord.SHA256 != marker.ResultSHA256 ||
		state.PeerReceiptRecord.SHA256 != marker.ReceiptSHA256 ||
		state.ManifestRecord.SHA256 != marker.ManifestSHA256 ||
		state.Head.CandidateDigest != state.CandidateRecord.SHA256 ||
		state.Head.ResultDigest != state.ResultRecord.SHA256 ||
		state.Candidate.InstanceOCID != marker.InstanceOCID || state.Result.InstanceOCID != marker.InstanceOCID ||
		state.Result.Mode != bootstrap.IntentModeManaged ||
		state.Intent.DeploymentID != marker.DeploymentID || state.Intent.Cell != marker.Cell ||
		state.Intent.Slot != marker.Slot || state.Intent.ManifestDigest != marker.ManifestSHA256 ||
		state.Result.DeploymentID != marker.DeploymentID || state.Result.Cell != marker.Cell ||
		state.Result.Slot != marker.Slot || state.Candidate.DeploymentID != marker.DeploymentID ||
		state.Candidate.Cell != marker.Cell || state.Candidate.Slot != marker.Slot ||
		state.Intent.ImageOCID != marker.ImageOCID ||
		state.Head.Attempt != marker.HeadAttempt || state.Head.Generation != marker.HeadGeneration ||
		state.Candidate.IntentDigest != state.IntentRecord.SHA256 ||
		state.Result.IntentDigest != state.IntentRecord.SHA256 ||
		state.Candidate.FounderPlanSHA256 != state.Intent.FounderPlanSHA256 ||
		state.Candidate.PeerRowDigest != state.Intent.PeerRowDigest ||
		state.Candidate.ManifestDigest != state.Intent.ManifestDigest {
		return ErrFounderPeerContinuation
	}
	if selected.Plan.SeedSlot() != marker.SeedSlot ||
		selected.SelectionGeneration == 0 || !now.Before(selected.SelectionExpiresAt) ||
		!selected.Plan.StoredCompletionBeforeLaunchDeadline(state.ResultRecord.LastModified,
			state.HeadRecord.LastModified) ||
		digestWire(selected.ManifestWires[marker.Slot]) != marker.ManifestSHA256 {
		return ErrFounderPeerContinuation
	}
	row, ok := selected.Plan.PeerRow(marker.Slot)
	if ok {
		rowDigest, err := bootstrap.FounderPeerRowDigest(row)
		if err == nil && rowDigest == state.Intent.PeerRowDigest &&
			row.ManifestSHA256 == marker.ManifestSHA256 && row.ImageOCID == marker.ImageOCID &&
			row.CompartmentOCID == state.Intent.CompartmentOCID {
			return nil
		}
	}
	return ErrFounderPeerContinuation
}
