package bootstrapstart

import (
	"context"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

func NewDerivedCurrentFounderAuthorityReaderContext(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	authority bootstrap.DerivedStartupAuthority, floor *FounderSelectionFloorStore,
) (*CurrentFounderAuthorityReader, error) {
	if floor == nil || accepted.validate() != nil || !authority.IsVerified() ||
		authority.AnchorDigest() != accepted.AnchorSHA256 || authority.Digest() != accepted.ManifestSHA256 ||
		authority.Manifest().Slot != accepted.Slot || authority.Manifest().SeedSlot != accepted.SeedSlot ||
		accepted.DeploymentID != baked.Identity.DeploymentID || accepted.Cell != string(baked.Identity.Cell) {
		return nil, ErrFounderSelection
	}
	anchor, err := baked.verifyHistoricalOriginAnchor(ctx, accepted.AcceptedAt)
	if err != nil || anchor.Digest() != accepted.AnchorSHA256 || !slices.Contains(anchor.Anchor().ControllerSlots, accepted.Slot) {
		return nil, ErrFounderSelection
	}
	identity := anchor.Anchor()
	if _, err := authority.OriginalLaunch(); err == nil {
		identity = authority.Template().StartupIdentity()
	}
	return &CurrentFounderAuthorityReader{baked: baked, accepted: accepted,
		acceptedClusterID: identity.ClusterID, acceptedSlots: identity.ControllerSlots,
		domain: authority.StorageDomain(), floor: floor, derived: new(authority)}, nil
}

func (reader *CurrentFounderAuthorityReader) readDerivedCurrent(ctx context.Context, now time.Time, useFloor bool) (CurrentFounderAuthority, error) {
	if reader == nil || reader.derived == nil || reader.floor == nil || now.IsZero() || now.Location() != time.UTC {
		return CurrentFounderAuthority{}, ErrFounderSelection
	}
	anchor, err := reader.baked.VerifyOriginAnchor(ctx, now)
	if err != nil || anchor.Digest() != reader.accepted.AnchorSHA256 {
		return CurrentFounderAuthority{}, ErrFounderSelection
	}
	seed, err := bootstrap.LoadSeedStartupAuthority(ctx, *reader.derived, now)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	plan, err := bootstrap.NewDerivedFounderPlan(ctx, seed, now)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	plan, err = plan.RevalidateCurrent(ctx, reader.baked.Roots, now)
	if err != nil {
		return CurrentFounderAuthority{}, err
	}
	local, ok := plan.Authority(reader.accepted.Slot)
	if !ok || local.Digest() != reader.accepted.ManifestSHA256 || plan.Plan().SeedSlot != reader.accepted.SeedSlot || plan.Plan().AnchorSHA256 != anchor.Digest() {
		return CurrentFounderAuthority{}, ErrFounderSelection
	}
	if useFloor {
		if err := reader.floor.Check(plan.SelectionGeneration(), plan.SelectionDigest()); err != nil {
			return CurrentFounderAuthority{}, err
		}
	}
	wires := make(map[string][]byte, len(plan.Plan().ControllerSlots))
	for _, slot := range plan.Plan().ControllerSlots {
		authority, ok := plan.Authority(slot)
		if !ok {
			return CurrentFounderAuthority{}, ErrFounderSelection
		}
		wires[slot] = authority.Wire()
	}
	if err := seed.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return CurrentFounderAuthority{}, err
	}
	if useFloor {
		if err := reader.floor.Observe(plan.SelectionGeneration(), plan.SelectionDigest()); err != nil {
			return CurrentFounderAuthority{}, err
		}
	}
	return CurrentFounderAuthority{SelectionGeneration: plan.SelectionGeneration(), SelectionSHA256: plan.SelectionDigest(),
		SelectionExpiresAt: seed.ExpiresAt(), Plan: plan, Derived: new(plan), Anchor: anchor,
		AnchorWire: anchor.Wire(), ManifestWires: wires}, nil
}

func (reader *CurrentFounderAuthorityReader) readDerivedCompletedPeer(ctx context.Context, now time.Time, useFloor bool) (currentFounderPeerSelection, error) {
	selected, err := reader.readDerivedCurrent(ctx, now, useFloor)
	if err != nil {
		return currentFounderPeerSelection{}, err
	}
	continuation, err := selected.Derived.ForCompletedPeerContinuation(ctx, now)
	if err != nil {
		return currentFounderPeerSelection{}, err
	}
	return currentFounderPeerSelection{SelectionGeneration: selected.SelectionGeneration, SelectionSHA256: selected.SelectionSHA256,
		SelectionExpiresAt: selected.SelectionExpiresAt, Plan: continuation, Anchor: selected.Anchor,
		AnchorWire: selected.AnchorWire, ManifestWires: selected.ManifestWires, derived: selected.Derived}, nil
}

// ProvisionInitialDerivedFounderFloor binds first seed admission to the same
// durable floor used by the admitted founder runner and peer continuation.
func ProvisionInitialDerivedFounderFloor(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	authority bootstrap.DerivedStartupAuthority, floor *FounderSelectionFloorStore,
	serviceUID, serviceGID uint32, now time.Time, clockCheck func() error,
) error {
	if accepted.validate() != nil || accepted.Slot != accepted.SeedSlot || accepted.HeadAttempt != 1 || accepted.HeadGeneration != 1 ||
		serviceUID == 0 || serviceGID == 0 || floor == nil || floor.ownerUID != serviceUID || clockCheck == nil {
		return ErrFounderProvision
	}
	reader, err := NewDerivedCurrentFounderAuthorityReaderContext(ctx, baked, accepted, authority, floor)
	if err != nil {
		return err
	}
	selected, err := reader.readDerivedCurrent(ctx, now, false)
	if err != nil {
		return err
	}
	ledger, err := authority.OpenLedger(ctx, baked.Roots)
	if err != nil {
		return err
	}
	return reader.provisionDerivedInitial(ctx, selected, ledger, serviceUID, serviceGID, clockCheck)
}

func (reader *CurrentFounderAuthorityReader) provisionDerivedInitial(ctx context.Context, selected CurrentFounderAuthority,
	ledger *bootstrap.Ledger, serviceUID, serviceGID uint32, clockCheck func() error,
) error {
	if reader == nil || reader.derived == nil || reader.floor == nil || ledger == nil || clockCheck == nil || serviceUID == 0 || serviceGID == 0 || reader.floor.ownerUID != serviceUID {
		return ErrFounderProvision
	}
	accepted, floor := reader.accepted, reader.floor
	state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{DeploymentID: accepted.DeploymentID, Cell: accepted.Cell, Slot: accepted.Slot})
	if err != nil || state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Head.Attempt != accepted.HeadAttempt || state.Head.Generation != accepted.HeadGeneration ||
		state.Head.ResultDigest != accepted.ResultSHA256 || state.ResultRecord == nil || state.ResultRecord.SHA256 != accepted.ResultSHA256 ||
		state.ManifestRecord == nil || state.ManifestRecord.SHA256 != accepted.ManifestSHA256 || state.SeedReceiptRecord == nil || state.SeedReceiptRecord.SHA256 != accepted.ReceiptSHA256 {
		return ErrFounderProvision
	}
	if err := prepareFounderFloorOwner(floor, serviceUID, serviceGID); err != nil {
		return err
	}
	if err := clockCheck(); err != nil {
		return err
	}
	if err := reader.confirmCurrentSelection(ctx, selected, time.Now().UTC()); err != nil {
		return err
	}
	present, err := founderFloorPresent(floor)
	if err != nil {
		return err
	}
	if present {
		if err := floor.Observe(selected.SelectionGeneration, selected.SelectionSHA256); err != nil {
			return err
		}
	} else if err := floor.initializeForService(selected.SelectionGeneration, selected.SelectionSHA256, serviceGID, false); err != nil {
		return err
	}
	return reader.confirmCurrentSelection(ctx, selected, time.Now().UTC())
}
