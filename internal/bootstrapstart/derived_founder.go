package bootstrapstart

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

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
