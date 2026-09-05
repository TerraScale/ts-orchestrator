package candidatesync

import (
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

// TransitionCandidateBinding names the exact signed evidence that passed the
// preliminary synchronization prerequisite. It is not a retirement receipt.
type TransitionCandidateBinding struct {
	PlanSHA256       string `json:"planSha256"`
	ScopeSHA256      string `json:"scopeSha256"`
	SFOReceiptSHA256 string `json:"sfoReceiptSha256"`
	FRAReceiptSHA256 string `json:"fraReceiptSha256"`
	CaptureEpoch     uint64 `json:"captureEpoch"`
}

type VerifiedTransitionCandidates struct {
	plan    controltransition.VerifiedPlan
	binding TransitionCandidateBinding
}

// Binding returns immutable digest values only. It refuses an expired plan.
func (v VerifiedTransitionCandidates) Binding(now time.Time) (TransitionCandidateBinding, error) {
	if err := v.plan.Check(now); err != nil {
		return TransitionCandidateBinding{}, err
	}
	return v.binding, nil
}

// VerifyTransitionCandidates requires SFO then FRA receipts from the exact
// preliminary transfer named by the owner plan. The source must still obtain
// durable host preparation receipts and prove all other retirement gates.
func VerifyTransitionCandidates(plan controltransition.VerifiedPlan, scope preliminarytransfer.VerifiedScope, signedReceipts [][]byte, now time.Time) (VerifiedTransitionCandidates, error) {
	var zero VerifiedTransitionCandidates
	bad := errors.New("candidatesync: transition preliminary evidence differs")
	if err := plan.Check(now); err != nil {
		return zero, err
	}
	if err := scope.Check(); err != nil {
		return zero, err
	}
	p, err := plan.Plan()
	if err != nil {
		return zero, err
	}
	s := scope.Scope
	if len(signedReceipts) != 2 || scope.Digest != p.PreliminaryScopeSHA256 || scope.OwnerKeyID != plan.OwnerKeyID() || s.TransitionID != p.TransitionID || s.SourceNodeID != p.Source.NodeID || s.InitialGrantSHA256 != p.Source.BootstrapGrantSHA256 || s.StoreScopeSHA256 != p.Source.StoreScopeSHA256 || s.ProfileSHA256 != p.Source.ProfileSHA256 || s.MaxRestoreBytes > p.Limits.MaxRestoreBytes || s.MaxSnapshotBytes > p.Limits.MaxSnapshotBytes || s.MaxTotalBytes > p.Limits.MaxTransferBytes {
		return zero, bad
	}
	var transferred int64
	for _, object := range s.Objects {
		if object.Size > p.Limits.MaxTransferBytes-transferred {
			return zero, bad
		}
		transferred += object.Size
	}
	epoch, err := scope.CaptureEpoch()
	if err != nil {
		return zero, err
	}
	if epoch > uint64(p.GlobalElectionFloor) {
		return zero, bad
	}
	capture, err := scope.HistoricalCapture()
	if err != nil {
		return zero, err
	}
	// Account roles may use different names on R3. Match the SOURCE names and
	// complete stream inventory; destination account renaming is a later phase.
	if len(capture.Request.Accounts) != len(p.Accounts) {
		return zero, bad
	}
	for _, account := range p.Accounts {
		found := false
		for _, source := range capture.Request.Accounts {
			if source.Account != account.SourceName {
				continue
			}
			if len(source.Streams) != len(account.Streams) {
				return zero, bad
			}
			for i, stream := range source.Streams {
				if stream != account.Streams[i].Name {
					return zero, bad
				}
			}
			found = true
		}
		if !found {
			return zero, bad
		}
	}
	for i, region := range []string{"sfo", "fra"} {
		candidate := s.Candidates[i]
		destination := p.Destinations[i+1]
		if candidate.Region != region || candidate.NodeID != destination.NodeID || candidate.ServerName != destination.ServerName || candidate.BootstrapGrantSHA256 != destination.BootstrapGrantSHA256 || candidate.ManifestSHA256 != destination.PreparedManifestSHA256 {
			return zero, bad
		}
		if _, err := verifyScopedReceipt(scope, region, signedReceipts[i], now); err != nil {
			return zero, err
		}
	}
	return VerifiedTransitionCandidates{plan: plan, binding: TransitionCandidateBinding{PlanSHA256: plan.Digest(), ScopeSHA256: scope.Digest, SFOReceiptSHA256: preliminarytransfer.Digest(signedReceipts[0]), FRAReceiptSHA256: preliminarytransfer.Digest(signedReceipts[1]), CaptureEpoch: epoch}}, nil
}
