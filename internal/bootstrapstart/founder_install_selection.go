package bootstrapstart

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

// currentFounderInstallSelection is deliberately limited to a signed selector
// and one immutable read-only proof. It cannot be used as founder launch input.
type currentFounderInstallSelection struct {
	selection          FounderSelection
	selectionSHA256    string
	selectionExpiresAt time.Time
	proofWire          []byte
	proofSHA256        string
}

func (reader *CurrentFounderAuthorityReader) readCurrentInstallContinuation(ctx context.Context,
	now time.Time,
) (currentFounderInstallSelection, error) {
	if reader == nil || reader.objects == nil || reader.floor == nil ||
		now.IsZero() || now.Location() != time.UTC {
		return currentFounderInstallSelection{}, ErrFounderSelection
	}
	started := time.Now()
	key := FounderSelectionObjectName(reader.domain, reader.baked.Identity.DeploymentID,
		string(reader.baked.Identity.Cell), reader.baked.Identity.Environment)
	wire, etag, err := reader.getExact(ctx, reader.domain.HeadBucket, key, founderSelectionMaxBytes)
	if err != nil {
		return currentFounderInstallSelection{}, err
	}
	selection, selectionSHA256, expiresAt, err := reader.verifySelection(wire, now)
	if err != nil || selection.SchemaVersion != 2 || len(reader.acceptedSlots) != 3 {
		return currentFounderInstallSelection{}, ErrFounderSelection
	}
	if err := reader.floor.Check(selection.Generation, selectionSHA256); err != nil {
		return currentFounderInstallSelection{}, err
	}
	var proofSHA256 string
	for _, pin := range selection.Continuities {
		if !slices.Contains(reader.acceptedSlots, pin.Slot) {
			return currentFounderInstallSelection{}, ErrFounderSelection
		}
		if pin.Slot == reader.accepted.Slot {
			proofSHA256 = pin.SHA256
		}
	}
	if proofSHA256 == "" {
		return currentFounderInstallSelection{}, ErrFounderSelection
	}
	proofKey := FounderImmutableObjectName(reader.domain, selection.DeploymentID, selection.Cell,
		selection.Environment, proofSHA256)
	proofWire, _, err := reader.getExact(ctx, reader.domain.LedgerBucket, proofKey, bootstrap.MaxInstallContinuityWireBytes)
	if err != nil || digestWire(proofWire) != proofSHA256 {
		return currentFounderInstallSelection{}, fmt.Errorf("%w: selected continuity proof is unavailable or changed: %v", ErrFounderSelection, err)
	}
	if err := reader.confirmSelector(ctx, key, wire, etag); err != nil {
		return currentFounderInstallSelection{}, err
	}
	selected := currentFounderInstallSelection{selection: selection, selectionSHA256: selectionSHA256,
		selectionExpiresAt: expiresAt, proofWire: bytes.Clone(proofWire), proofSHA256: proofSHA256}
	if err := reader.confirmCurrentInstallSelection(ctx, selected,
		func() time.Time { return now.Add(time.Since(started)) }); err != nil {
		return currentFounderInstallSelection{}, err
	}
	return selected, nil
}

func (reader *CurrentFounderAuthorityReader) confirmCurrentInstallSelection(ctx context.Context,
	selected currentFounderInstallSelection, clock func() time.Time,
) error {
	if reader == nil || clock == nil || ctx.Err() != nil || selected.selection.SchemaVersion != 2 ||
		!validFounderDigest(selected.selectionSHA256) || !validFounderDigest(selected.proofSHA256) ||
		digestWire(selected.proofWire) != selected.proofSHA256 {
		return ErrFounderSelection
	}
	key := FounderSelectionObjectName(reader.domain, reader.baked.Identity.DeploymentID,
		string(reader.baked.Identity.Cell), reader.baked.Identity.Environment)
	wire, _, err := reader.getExact(ctx, reader.domain.HeadBucket, key, founderSelectionMaxBytes)
	if err != nil {
		return err
	}
	now := clock().Round(0).UTC()
	if now.IsZero() {
		return ErrFounderSelection
	}
	selection, digest, expiresAt, err := reader.verifySelection(wire, now)
	if err != nil || digest != selected.selectionSHA256 ||
		selection.Generation != selected.selection.Generation ||
		!now.Before(expiresAt) {
		return ErrFounderSelection
	}
	for _, pin := range selection.Continuities {
		if pin.Slot == reader.accepted.Slot && pin.SHA256 == selected.proofSHA256 {
			return nil
		}
	}
	return ErrFounderSelection
}
