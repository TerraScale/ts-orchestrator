package bootstrapstart

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
)

// FounderFloorArtifact describes one fixed-path guest artifact. Offline image
// tooling can stage these verified bytes under an isolated guest root. Runtime
// admission writes the same canonical floor encoding through its locked,
// service-owned store and never accepts an arbitrary floor path.
type FounderFloorArtifact struct {
	Path      string
	Bytes     []byte
	Mode      os.FileMode
	UID       uint32
	GID       uint32
	Directory bool
}

// BuildVerifiedPeerFloorArtifacts is for offline image and fixture staging.
// Its state must be the historically verified exact slot from Ledger.ReadSlot;
// production admission never trusts caller-supplied state at this boundary.
func BuildVerifiedPeerFloorArtifacts(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	state bootstrap.SlotState, objects FounderSelectionObjectReader,
	serviceUID, serviceGID uint32, now time.Time,
) ([]FounderFloorArtifact, error) {
	if serviceUID == 0 || serviceGID == 0 || accepted.Slot == accepted.SeedSlot {
		return nil, ErrFounderPeerContinuation
	}
	reader, err := NewCurrentFounderAuthorityReader(baked, accepted, objects, new(FounderSelectionFloorStore))
	if err != nil {
		return nil, err
	}
	started := time.Now()
	selected, err := reader.readCurrentPeerInitial(ctx, now)
	if err != nil {
		return nil, err
	}
	checker := FounderPeerContinuation{reader: reader}
	if err := checker.checkBindings(accepted, state, selected, now); err != nil {
		return nil, err
	}
	if err := reader.confirmCurrentPeerSelection(ctx, selected,
		func() time.Time { return now.Add(time.Since(started)) }); err != nil {
		return nil, err
	}
	return founderFloorArtifacts(selected.SelectionGeneration, selected.SelectionSHA256, serviceUID, serviceGID)
}

// BuildVerifiedSeedFloorArtifacts is the corresponding offline staging path
// for a generation-one accepted external seed. The live seed still uses its
// own root-admission provisioner and durable floor initialization.
func BuildVerifiedSeedFloorArtifacts(ctx context.Context, baked BakedInputs, accepted AcceptedInstall,
	state bootstrap.SlotState, objects FounderSelectionObjectReader,
	serviceUID, serviceGID uint32, now time.Time,
) ([]FounderFloorArtifact, error) {
	if serviceUID == 0 || serviceGID == 0 || accepted.validate() != nil ||
		accepted.Slot != accepted.SeedSlot || accepted.HeadAttempt != 1 || accepted.HeadGeneration != 1 ||
		state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Head.ResultDigest != accepted.ResultSHA256 ||
		state.ResultRecord == nil || state.ResultRecord.SHA256 != accepted.ResultSHA256 ||
		state.ManifestRecord == nil || state.ManifestRecord.SHA256 != accepted.ManifestSHA256 {
		return nil, ErrFounderProvision
	}
	reader, err := NewCurrentFounderAuthorityReader(baked, accepted, objects, new(FounderSelectionFloorStore))
	if err != nil {
		return nil, err
	}
	selected, err := reader.readCurrent(ctx, now, false)
	if err != nil || selected.SelectionGeneration != 1 || selected.Anchor.Digest() != accepted.AnchorSHA256 ||
		selected.Plan.Plan().SeedManifestSHA256 != accepted.ManifestSHA256 {
		return nil, ErrFounderProvision
	}
	if err := reader.confirmCurrentSelection(ctx, selected, now); err != nil {
		return nil, err
	}
	return founderFloorArtifacts(selected.SelectionGeneration, selected.SelectionSHA256, serviceUID, serviceGID)
}

func founderFloorArtifacts(generation uint64, selectorDigest string, serviceUID, serviceGID uint32) ([]FounderFloorArtifact, error) {
	wire, err := encodeFounderSelectionFloor(generation, selectorDigest)
	if err != nil || serviceUID == 0 || serviceGID == 0 {
		return nil, ErrFounderSelectionFloor
	}
	return []FounderFloorArtifact{
		{Path: FounderSelectionFloorDirectory, Mode: 0o700, UID: serviceUID, GID: serviceGID, Directory: true},
		{Path: filepath.Join(FounderSelectionFloorDirectory, founderSelectionLockName),
			Mode: 0o600, UID: serviceUID, GID: serviceGID},
		{Path: filepath.Join(FounderSelectionFloorDirectory, founderSelectionFloorName),
			Bytes: wire, Mode: 0o600, UID: serviceUID, GID: serviceGID},
	}, nil
}
