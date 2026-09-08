package vmqualsuite

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/candidatesync"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type qualificationLaunchTransitionBinding interface {
	QualificationLaunchTransition(context.Context, string) (vmqual.LaunchTransitionObservation, error)
}

func (proof *runtimeControlProof) addFiniteLaunchCandidate(ctx context.Context, region string) (ControlCandidateProof, error) {
	var result ControlCandidateProof
	bad := bootstrap.ErrControlPromotionNotReady
	if region != "sfo" && region != "fra" || region == "sfo" && proof.finiteLaunch != nil || region == "fra" && proof.finiteLaunch == nil || proof.state.Topology == bootstrap.ControlTopologyGlobalR3 {
		return result, ErrControlContractOrder
	}
	producer, ok := proof.stack.Config().VMFactory.(qualificationLaunchTransitionBinding)
	if !ok {
		return result, bootstrap.ErrControlRuntimeUnavailable
	}
	observed, err := producer.QualificationLaunchTransition(ctx, region)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(observed.OwnerPublicKey, proof.initial.OwnerPublicKey) {
		return result, bad
	}
	plan, err := controltransition.VerifyPlan(observed.OwnerPublicKey, observed.SignedPlan)
	if err != nil {
		return result, err
	}
	p, err := plan.Plan()
	if err != nil {
		return result, err
	}
	if p.Source.NodeID != proof.initial.SourceHost || p.Source.BootstrapGrantSHA256 != proof.initial.GrantSHA256[p.Source.NodeID] || p.Source.InitialManifestSHA256 != proof.initial.ManifestSHA256[p.Source.NodeID] || observed.JournalPath == "" || !filepath.IsAbs(observed.JournalPath) {
		return result, bad
	}
	scope, err := preliminarytransfer.VerifyScope(observed.OwnerPublicKey, observed.PreliminaryScope)
	if err != nil {
		return result, err
	}
	verified, err := candidatesync.VerifyTransitionCandidates(plan, scope, observed.CandidateReceipts, time.Now())
	if err != nil {
		return result, err
	}
	if _, err := verified.Binding(time.Now()); err != nil {
		return result, err
	}
	if previous := proof.finiteLaunch; previous != nil && (controltransition.Digest(previous.SignedPlan) != plan.Digest() || controltransition.Digest(previous.PreliminaryScope) != scope.Digest || previous.JournalPath != observed.JournalPath) {
		return result, bad
	}
	result.Region, result.SynchronizedBeforePromotion, result.JournalPaths = region, true, []string{observed.JournalPath}
	if region == "sfo" {
		if len(observed.SourceStateReceipt) != 0 || len(observed.CutReceipt) != 0 || len(observed.CaptureReceipt) != 0 || len(observed.RestoreReceipt) != 0 {
			return result, bad
		}
		proof.finiteLaunch = &observed
		return result, nil
	}
	if _, err := controltransition.VerifyRestoreReceipt(plan, observed.CutReceipt, observed.SourceStateReceipt, observed.CaptureReceipt, observed.RestoreReceipt); err != nil {
		return result, err
	}
	// Chained restore receipts are historical. Require actual restored runtime
	// authority and a current stream majority before admitting ordinary hosts.
	if err := proof.initialize(ctx); err != nil {
		return result, err
	}
	quorum, ok := proof.runtime.(controlQuorumAvailability)
	if !ok {
		return result, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := quorum.VerifyQuorumAvailability(ctx, p.TargetTopologyEpoch); err != nil {
		return result, errors.Join(bad, err)
	}
	proof.finiteLaunch = &observed
	proof.state = bootstrap.ControlPlaneState{Topology: bootstrap.ControlTopologyGlobalR3, Phase: bootstrap.ControlPhaseR3, Epoch: p.TargetTopologyEpoch, ControlRegions: []string{"gru", "sfo", "fra"}, MemberHosts: len(proof.stack.Guests())}
	result.State, result.Promoted, result.PromotionEpoch = cloneControlState(proof.state), true, p.TargetTopologyEpoch
	return result, nil
}
