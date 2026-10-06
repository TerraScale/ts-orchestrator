package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var ErrFounderInstallContinuation = errors.New("current founder install continuation is unavailable")

// FounderInstallContinuation authorizes only read-only restart of one accepted
// seed or managed peer. It has no launch, ledger-write, materialization, or
// Vault capability.
type FounderInstallContinuation struct {
	reader          *CurrentFounderAuthorityReader
	credentialBound func(AcceptedInstall, bootstrap.SlotState) (CredentialBound, error)
	now             func() time.Time
}

func NewOCIFounderInstallContinuation(baked BakedInputs, accepted AcceptedInstall,
	credentials LiveCredentials, serviceUID uint32,
) (*FounderInstallContinuation, error) {
	floor, err := NewServiceFounderSelectionFloorStore(serviceUID)
	if err != nil {
		return nil, err
	}
	reader, err := NewOCICurrentFounderAuthorityReader(baked, accepted, floor)
	if err != nil {
		return nil, err
	}
	return &FounderInstallContinuation{reader: reader,
		credentialBound: func(marker AcceptedInstall, state bootstrap.SlotState) (CredentialBound, error) {
			manifest, err := pinnedCredentialManifest(marker, state)
			if err != nil {
				return CredentialBound{}, err
			}
			return credentials.CurrentCredentialBound(marker.MaterialSHA256, manifest, baked.Roots, marker.PrimaryPrivateIP)
		}, now: time.Now}, nil
}

func pinnedCredentialManifest(marker AcceptedInstall, state bootstrap.SlotState) (bootstrap.Manifest, error) {
	// Gate authenticated this manifest at installation. The root-owned marker
	// pins its exact envelope bytes across historical restart and continuation.
	if state.ManifestRecord == nil || len(state.ManifestRecord.Bytes) == 0 ||
		state.ManifestRecord.SHA256 != marker.ManifestSHA256 ||
		digestWire(state.ManifestRecord.Bytes) != marker.ManifestSHA256 {
		return bootstrap.Manifest{}, ErrFounderInstallContinuation
	}
	envelope, err := trust.DecodeEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		return bootstrap.Manifest{}, ErrFounderInstallContinuation
	}
	var manifest bootstrap.Manifest
	if err := protocol.DecodeStrict(envelope.Payload, &manifest, bootstrap.MaxManifestBytes); err != nil ||
		manifest.Slot != marker.Slot || manifest.SeedSlot != marker.SeedSlot {
		return bootstrap.Manifest{}, ErrFounderInstallContinuation
	}
	return manifest, nil
}

func (checker *FounderInstallContinuation) VerifyCurrentContinuation(ctx context.Context,
	marker AcceptedInstall, observed InstanceObservation, state bootstrap.SlotState,
) error {
	if checker == nil || checker.reader == nil || checker.reader.floor == nil ||
		checker.credentialBound == nil || checker.now == nil {
		return ErrFounderInstallContinuation
	}
	if err := checker.checkHistoricalBindings(marker, observed, state); err != nil {
		return err
	}
	bound, err := checker.credentialBound(marker, state)
	if err != nil || !validFounderDigest(bound.SHA256) || bound.ValidUntil.IsZero() {
		return fmt.Errorf("%w: live credential inventory: %v", ErrFounderInstallContinuation, err)
	}
	now := checker.now().Round(0).UTC()
	selected, err := checker.reader.readCurrentInstallContinuation(ctx, now)
	if err != nil {
		return fmt.Errorf("%w: read current selected continuity: %v", ErrFounderInstallContinuation, err)
	}
	markerWire, err := protocol.EncodeJSON(marker)
	if err != nil {
		return ErrFounderInstallContinuation
	}
	region, err := checker.reader.baked.Identity.Cell.OCIRegion()
	if err != nil {
		return ErrFounderInstallContinuation
	}
	proof := bootstrap.InstallContinuity{
		SchemaVersion: 1, DeploymentID: marker.DeploymentID,
		Environment: checker.reader.baked.Identity.Environment,
		ClusterID:   checker.reader.acceptedClusterID,
		Cell:        checker.reader.baked.Identity.Cell, OCIRegion: region, Slot: marker.Slot,
		GenesisAnchorSHA256: marker.AnchorSHA256, AcceptedMarkerSHA256: digestWire(markerWire),
		ManifestSHA256: marker.ManifestSHA256, ResultSHA256: marker.ResultSHA256,
		ReceiptSHA256: marker.ReceiptSHA256, ImageReceiptSHA256: marker.ImageReceiptSHA256,
		ImageOCID: marker.ImageOCID, InstanceOCID: marker.InstanceOCID,
		PrimaryVNICOCID: marker.PrimaryVNICOCID, PrimaryPrivateIP: marker.PrimaryPrivateIP,
		LedgerAttempt: marker.HeadAttempt, LedgerGeneration: marker.HeadGeneration,
		AcceptedAt: marker.AcceptedAt, BinarySHA256: marker.BinarySHA256,
		MaterialSHA256: marker.MaterialSHA256, CredentialSHA256: bound.SHA256,
		CredentialValidUntil: bound.ValidUntil, SelectorGeneration: selected.selection.Generation,
		MaterialGenerationSHA256: bound.Generation,
	}
	envelope, err := trust.DecodeEnvelope(selected.proofWire)
	if err != nil {
		return fmt.Errorf("%w: decode selected continuity: %v", ErrFounderInstallContinuation, err)
	}
	verified, err := bootstrap.VerifyCurrentInstallContinuity(envelope, checker.reader.baked.Roots,
		bootstrap.InstallContinuityExpectation{Install: proof,
			SelectorGeneration: selected.selection.Generation, SelectorSHA256: selected.selectionSHA256,
			PinnedContinuitySHA256: selected.proofSHA256}, now, bootstrap.InstallContinuityTrustPolicy())
	if err != nil {
		return fmt.Errorf("%w: selected proof does not bind accepted install: %v", ErrFounderInstallContinuation, err)
	}
	if err := checker.reader.floor.Observe(selected.selection.Generation, selected.selectionSHA256); err != nil {
		return fmt.Errorf("%w: observe selector floor: %v", ErrFounderInstallContinuation, err)
	}
	finalBound, err := checker.credentialBound(marker, state)
	if err != nil || finalBound != bound || ctx.Err() != nil {
		return ErrFounderInstallContinuation
	}
	if err := checker.reader.confirmCurrentInstallSelection(ctx, selected, checker.now); err != nil {
		return fmt.Errorf("%w: final selector read: %v", ErrFounderInstallContinuation, err)
	}
	if err := checker.reader.floor.Check(selected.selection.Generation, selected.selectionSHA256); err != nil {
		return fmt.Errorf("%w: final selector floor: %v", ErrFounderInstallContinuation, err)
	}
	finalNow := checker.now().Round(0).UTC()
	if err := verified.FinalRecheck(finalNow, selected.selection.Generation, selected.selectionSHA256); err != nil ||
		!finalNow.Before(finalBound.ValidUntil) || ctx.Err() != nil {
		return fmt.Errorf("%w: selected proof expired during restart: %v", ErrFounderInstallContinuation, err)
	}
	return nil
}

func (checker *FounderInstallContinuation) checkHistoricalBindings(marker AcceptedInstall,
	observed InstanceObservation, state bootstrap.SlotState,
) error {
	if marker.validate() != nil || checker.reader.accepted.validate() != nil {
		return ErrFounderInstallContinuation
	}
	markerWire, markerErr := protocol.EncodeJSON(marker)
	acceptedWire, acceptedErr := protocol.EncodeJSON(checker.reader.accepted)
	if markerErr != nil || acceptedErr != nil || !bytes.Equal(markerWire, acceptedWire) ||
		observed.InstanceOCID != marker.InstanceOCID || observed.ImageOCID != marker.ImageOCID ||
		observed.PrimaryVNICOCID != marker.PrimaryVNICOCID ||
		observed.PrimaryPrivateIP != marker.PrimaryPrivateIP ||
		state.Head.Attempt != marker.HeadAttempt || state.Head.Generation != marker.HeadGeneration ||
		state.Head.ResultDigest != marker.ResultSHA256 ||
		state.ResultRecord == nil || state.ResultRecord.SHA256 != marker.ResultSHA256 ||
		state.ManifestRecord == nil || state.ManifestRecord.SHA256 != marker.ManifestSHA256 ||
		state.Intent.DeploymentID != marker.DeploymentID || state.Intent.Cell != marker.Cell ||
		state.Intent.Slot != marker.Slot || state.Intent.ImageOCID != marker.ImageOCID ||
		state.Intent.ManifestDigest != marker.ManifestSHA256 ||
		state.Intent.ReleaseReceiptDigest != marker.ImageReceiptSHA256 ||
		state.Result == nil || state.Result.InstanceOCID != marker.InstanceOCID {
		return ErrFounderInstallContinuation
	}
	if marker.Slot == marker.SeedSlot {
		if state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.SeedReceiptRecord == nil ||
			state.SeedReceiptRecord.SHA256 != marker.ReceiptSHA256 {
			return ErrFounderInstallContinuation
		}
	} else if state.Intent.Mode != bootstrap.IntentModeManaged || state.PeerReceiptRecord == nil ||
		state.PeerReceiptRecord.SHA256 != marker.ReceiptSHA256 {
		return ErrFounderInstallContinuation
	}
	return nil
}
