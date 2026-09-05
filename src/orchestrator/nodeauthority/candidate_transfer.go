package nodeauthority

import (
	"context"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

// VerifyPublishedCandidateRequest verifies transfer authority using the original
// bootstrap owner's key in the root-owned preparation publication. No key from
// the incoming request or a configurable replacement file supplies trust.
func VerifyPublishedCandidateRequest(ctx context.Context, config transitiongrant.Config, raw []byte) (preliminarytransfer.VerifiedCandidate, CandidatePreparationReceipt, error) {
	return verifyCandidateRequest(ctx, config, raw, CandidatePreparationDirectory, 0)
}

func verifyCandidateRequest(ctx context.Context, config transitiongrant.Config, raw []byte, directory string, uid uint32) (preliminarytransfer.VerifiedCandidate, CandidatePreparationReceipt, error) {
	bad := errors.New("nodeauthority: preliminary transfer differs from original candidate admission")
	publication, err := readPublishedCandidate(ctx, config, directory, uid)
	if err != nil {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, err
	}
	if config.Sync == nil {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	now := time.Now().UTC()
	verified, err := preliminarytransfer.VerifyCandidateRequest(publication.PublicKey, raw, now)
	if err != nil {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	prepared, err := transitiongrant.VerifyGrant(publication.PublicKey, publication.SignedGrant)
	if err != nil {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	scope, authorization := verified.Scope.Scope, verified.Authorization
	receipt := publication.Receipt
	if scope.TransitionID != config.TransitionID || scope.PreparationGrantSHA256 != receipt.GrantSHA256 || scope.SourceNodeID != prepared.Grant.Source.NodeID || scope.InitialGrantSHA256 != prepared.Grant.Source.InitialGrantSHA256 || scope.StoreScopeSHA256 != prepared.Grant.Source.StoreScopeSHA256 || authorization.NodeID != config.NodeID || authorization.IssuedAt.Before(prepared.Grant.IssuedAt) || authorization.ExpiresAt.After(receipt.ExpiresAt) || scope.MaxSnapshotBytes > config.Sync.MaxSnapshotBytes || scope.MaxTotalBytes > config.Sync.MaxTotalBytes || scope.MaxRestoreBytes > config.Sync.MaxRestoreBytes {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	captureEpoch, err := verified.Scope.CaptureEpoch()
	if err != nil || captureEpoch < prepared.Grant.MinimumControlEpoch {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	destinationFound := false
	for _, destination := range scope.Destinations {
		if destination.Region == config.Region {
			destinationFound = destination.OCIRegion == config.Sync.Identity.Region
		}
	}
	if !destinationFound {
		return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
	}
	for _, candidate := range scope.Candidates {
		if candidate.Region == config.Region && candidate.NodeID == config.NodeID && candidate.ServerName == config.ServerName && candidate.BootstrapGrantSHA256 == receipt.BootstrapGrantSHA256 && candidate.ManifestSHA256 == receipt.ManifestSHA256 && candidate.ReceiptPublicKeyPEM == config.Sync.ReceiptPublicKeyPEM {
			return verified, receipt, ctx.Err()
		}
	}
	return preliminarytransfer.VerifiedCandidate{}, CandidatePreparationReceipt{}, bad
}
