package vmqualsuite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type scenarioControlProof interface {
	Bootstrap(context.Context) (ControlBootstrapProof, error)
	AddLaunchCandidate(context.Context, string) (ControlCandidateProof, error)
	VerifyPermanentR3(context.Context) (ControlR3Proof, error)
	VerifyRemoteRegion(context.Context, string) (ControlRemoteRegionProof, error)
	JournalRoot() string
}

// qualificationControlRuntimeBinding resolves guest-owned authenticated runtime
// inputs only when a scenario needs them, after the baseline guests have booted.
type qualificationControlRuntimeBinding interface {
	QualificationControlRuntime(context.Context) (bootstrap.ControlRuntime, []bootstrap.ControlRegionBinding, error)
}

type qualificationInitialControlBinding interface {
	QualificationInitialControl(context.Context) (vmqual.InitialControlObservation, error)
}

type controlQuorumAvailability interface {
	VerifyQuorumAvailability(context.Context, uint64) error
}

type runtimeControlProof struct {
	mu          sync.Mutex
	stack       *vmqual.Stack
	journalRoot string
	journal     *bootstrap.FileControlJournal
	runtime     bootstrap.ControlRuntime
	bindings    map[string]bootstrap.ControlRegionBinding
	provider    *runtimeControlProvider
	state       bootstrap.ControlPlaneState
	r3Checked   bool
	initial     *vmqual.InitialControlObservation
}

func (proof *runtimeControlProof) JournalRoot() string { return proof.journalRoot }
func (contract *ControlContract) JournalRoot() string  { return contract.journalRoot }

func (proof *runtimeControlProof) initialize(ctx context.Context) error {
	if proof.provider != nil {
		return nil
	}
	binder, ok := proof.stack.Config().VMFactory.(qualificationControlRuntimeBinding)
	if !ok {
		return fmt.Errorf("vmqual: factory lacks authenticated guest membership, authority lease, JetStream synchronization and hostcontrol runtime binding: %w", bootstrap.ErrControlRuntimeUnavailable)
	}
	runtime, bindings, err := binder.QualificationControlRuntime(ctx)
	if err != nil {
		return err
	}
	if runtime == nil {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	byRegion := make(map[string]bootstrap.ControlRegionBinding)
	ids := make(map[string]bool)
	for _, binding := range bindings {
		if binding.Code == "" || len(binding.MemberIDs) < 2 || byRegion[binding.Code].Code != "" {
			return ErrControlContractInvalid
		}
		for _, id := range binding.MemberIDs {
			if id == "" || ids[id] {
				return ErrControlContractInvalid
			}
			ids[id] = true
		}
		byRegion[binding.Code] = binding
	}
	for _, region := range []string{"gru", "sfo", "fra"} {
		if byRegion[region].Code == "" {
			return fmt.Errorf("vmqual: actual %s host identities are missing: %w", region, bootstrap.ErrControlRuntimeUnavailable)
		}
	}
	if len(byRegion) != 3 {
		return fmt.Errorf("vmqual: only launch Regions may be bound before expansion admission: %w", bootstrap.ErrControlRuntimeUnavailable)
	}
	journal, err := bootstrap.NewFileControlJournal(filepath.Join(proof.journalRoot, "control.json"))
	if err != nil {
		return err
	}
	proof.runtime, proof.bindings, proof.journal = runtime, byRegion, journal
	proof.provider = &runtimeControlProvider{runtime: runtime}
	return nil
}
func (proof *runtimeControlProof) execute(ctx context.Context, request bootstrap.ControlTransitionRequest) (bootstrap.ControlExecutionResult, error) {
	if err := proof.initialize(ctx); err != nil {
		return bootstrap.ControlExecutionResult{}, err
	}
	machine, err := bootstrap.NewControlStateMachine(proof.provider, proof.journal, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		return bootstrap.ControlExecutionResult{}, err
	}
	result, err := machine.Execute(ctx, proof.state, request)
	if err == nil {
		proof.state = cloneControlState(result.State)
	}
	return result, err
}
func (proof *runtimeControlProof) Bootstrap(ctx context.Context) (ControlBootstrapProof, error) {
	if ctx == nil {
		return ControlBootstrapProof{}, ErrControlContractInvalid
	}
	proof.mu.Lock()
	defer proof.mu.Unlock()
	if proof.state.Epoch != 0 || proof.initial != nil {
		return ControlBootstrapProof{}, ErrControlContractOrder
	}
	if source, ok := proof.stack.Config().VMFactory.(qualificationInitialControlBinding); ok {
		observed, err := source.QualificationInitialControl(ctx)
		if err != nil {
			return ControlBootstrapProof{}, err
		}
		if observed.SourceHost == "" || len(observed.GrantSHA256) != 2 || len(observed.ManifestSHA256) != 2 || observed.RegionalLease.Validate() != nil || observed.GlobalLease.Validate() != nil || observed.RegionalRevision == 0 || observed.GlobalRevision == 0 || observed.JournalPath == "" || observed.ObservedAt.IsZero() {
			return ControlBootstrapProof{}, ErrControlContractInvalid
		}
		proof.initial = &observed
		return ControlBootstrapProof{Initial: &observed, MemberHosts: len(observed.GrantSHA256), JournalPath: observed.JournalPath}, nil
	}
	result, err := proof.execute(ctx, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationBootstrap, Region: "gru", MemberHosts: 2})
	if err != nil {
		return ControlBootstrapProof{}, err
	}
	return ControlBootstrapProof{State: result.State, AcceptedEpoch: result.State.Epoch, MemberHosts: result.State.MemberHosts, Fenced: result.State.Phase == bootstrap.ControlPhaseR1, BootstrapAuthorized: result.State.BootstrapAuthorized, JournalPath: filepath.Join(proof.journalRoot, "control.json"), Calls: append([]ControlContractCall(nil), proof.provider.calls...)}, nil
}
func (proof *runtimeControlProof) AddLaunchCandidate(ctx context.Context, region string) (ControlCandidateProof, error) {
	if ctx == nil {
		return ControlCandidateProof{}, ErrControlContractInvalid
	}
	proof.mu.Lock()
	defer proof.mu.Unlock()
	if proof.provider == nil || proof.state.Phase != bootstrap.ControlPhaseR1 || (region != "sfo" && region != "fra") {
		return ControlCandidateProof{}, ErrControlContractOrder
	}
	start := len(proof.provider.calls)
	result, err := proof.execute(ctx, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationAddRegion, Region: region, MemberHosts: 2})
	if err != nil {
		return ControlCandidateProof{}, err
	}
	candidate := proof.provider.candidates[region]
	if !candidate.Ready() {
		return ControlCandidateProof{}, bootstrap.ErrControlPromotionNotReady
	}
	return ControlCandidateProof{Region: region, Candidate: candidate, State: result.State, SynchronizedBeforePromotion: true, Promoted: result.State.Topology == bootstrap.ControlTopologyGlobalR3, PromotionEpoch: result.State.Epoch, JournalPaths: []string{filepath.Join(proof.journalRoot, "control.json")}, Calls: append([]ControlContractCall(nil), proof.provider.calls[start:]...)}, nil
}
func (proof *runtimeControlProof) VerifyPermanentR3(ctx context.Context) (report ControlR3Proof, resultErr error) {
	if ctx == nil {
		return report, ErrControlContractInvalid
	}
	proof.mu.Lock()
	defer proof.mu.Unlock()
	if proof.provider == nil || proof.r3Checked || proof.state.Topology != bootstrap.ControlTopologyGlobalR3 {
		return report, ErrControlContractOrder
	}
	_, authorityErr := bootstrap.PlanControlTransition(proof.state, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationHandoff})
	_, downgradeErr := bootstrap.PlanControlTransition(proof.state, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationBootstrap, Region: "gru", MemberHosts: 2})
	stale := bootstrap.ControlPlaneState{Topology: bootstrap.ControlTopologyTemporaryR1, Phase: bootstrap.ControlPhaseR1, Epoch: 1, BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"}}
	machine, err := bootstrap.NewControlStateMachine(proof.provider, &bootstrap.MemoryControlJournal{Durable: true}, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		return report, err
	}
	_, regressionErr := machine.Execute(ctx, stale, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationAddRegion, Region: "sfo", MemberHosts: 2})
	if !errors.Is(authorityErr, bootstrap.ErrControlAuthorityRevoked) || !errors.Is(downgradeErr, bootstrap.ErrControlInvalid) || !errors.Is(regressionErr, bootstrap.ErrControlEpochRegression) {
		return report, ErrControlContractInvalid
	}
	quorum, ok := proof.runtime.(controlQuorumAvailability)
	if !ok {
		return report, fmt.Errorf("vmqual: runtime lacks fresh authority-lease and stream-majority availability observation: %w", bootstrap.ErrControlRuntimeUnavailable)
	}
	snapshot := proof.stack.Snapshot()
	var lost vmqual.VM
	for _, guest := range snapshot.Guests {
		if guest.Region == vmnet.FRA && guest.Control {
			lost = snapshot.VMs[guest.ID]
		}
	}
	if lost == nil {
		return report, fmt.Errorf("vmqual: actual FRA control guest is missing: %w", bootstrap.ErrControlRuntimeUnavailable)
	}
	if err := lost.Stop(ctx); err != nil {
		return report, err
	}
	defer func() {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		resultErr = errors.Join(resultErr, lost.StartReady(restoreCtx))
	}()
	observed, err := proof.runtime.Observe(ctx)
	if err != nil {
		return report, err
	}
	active := []string{}
	for _, region := range []string{"gru", "sfo", "fra"} {
		if observed[proof.bindings[region].MemberIDs[0]] {
			active = append(active, region)
		}
	}
	if len(active) != 2 || observed[proof.bindings["fra"].MemberIDs[0]] {
		return report, bootstrap.ErrControlQuorumNotVerified
	}
	if err := quorum.VerifyQuorumAvailability(ctx, proof.state.Epoch); err != nil {
		return report, err
	}
	proof.r3Checked = true
	return ControlR3Proof{State: cloneControlState(proof.state), AcceptedEpoch: proof.state.Epoch, GlobalReplicas: []string{"gru", "sfo", "fra"}, LostReplica: "fra", ActiveReplicasAfterLoss: active, QuorumAvailableAfterLoss: true, BootstrapAuthorityRetired: !proof.state.BootstrapAuthorized, BootstrapAuthorityReuseDenied: true, EpochRegressionDenied: true, DowngradeToR1Denied: true}, nil
}
func (proof *runtimeControlProof) VerifyRemoteRegion(ctx context.Context, region string) (ControlRemoteRegionProof, error) {
	if ctx == nil {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}
	proof.mu.Lock()
	defer proof.mu.Unlock()
	if !proof.r3Checked || proof.state.Topology != bootstrap.ControlTopologyGlobalR3 {
		return ControlRemoteRegionProof{}, ErrControlContractOrder
	}
	if err := proof.refreshRemoteBinding(ctx, region); err != nil {
		return ControlRemoteRegionProof{}, err
	}
	_, floorErr := bootstrap.PlanControlTransition(proof.state, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationAddRegion, Region: region, MemberHosts: 2, EligibleHosts: 2, RegionalControl: true})
	if !errors.Is(floorErr, bootstrap.ErrControlRegionalMembersFloor) {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}
	start := len(proof.provider.calls)
	result, err := proof.execute(ctx, bootstrap.ControlTransitionRequest{Operation: bootstrap.ControlOperationAddRegion, Region: region, MemberHosts: 2, EligibleHosts: 2})
	if err != nil {
		return ControlRemoteRegionProof{}, err
	}
	return ControlRemoteRegionProof{Region: region, MemberHosts: 2, GlobalState: result.State, RegionState: result.State, GlobalReplicas: append([]string(nil), result.State.ControlRegions...), RemoteManaged: true, HasGlobalReplica: false, RegionalR3BelowFloorRejected: true, JournalPath: filepath.Join(proof.journalRoot, "control.json"), Calls: append([]ControlContractCall(nil), proof.provider.calls[start:]...)}, nil
}

// The fourth Region is admitted by Stack.AdmitRegion immediately before this
// scenario. Reserved addresses are insufficient to create its control binding.
func (proof *runtimeControlProof) refreshRemoteBinding(ctx context.Context, region string) error {
	binder, ok := proof.stack.Config().VMFactory.(qualificationControlRuntimeBinding)
	if !ok {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	runtime, bindings, err := binder.QualificationControlRuntime(ctx)
	if err != nil || runtime == nil {
		return errors.Join(bootstrap.ErrControlRuntimeUnavailable, err)
	}
	next := make(map[string]bootstrap.ControlRegionBinding, len(bindings))
	identities := make(map[string]bool)
	for _, binding := range bindings {
		if binding.Code == "" || len(binding.MemberIDs) < 2 || next[binding.Code].Code != "" {
			return ErrControlContractInvalid
		}
		for _, id := range binding.MemberIDs {
			if id == "" || identities[id] {
				return ErrControlContractInvalid
			}
			identities[id] = true
		}
		if prior, exists := proof.bindings[binding.Code]; exists && (prior.OCIRegion != binding.OCIRegion || prior.CompartmentID != binding.CompartmentID || !slices.Equal(prior.MemberIDs, binding.MemberIDs)) {
			return ErrControlContractInvalid
		}
		binding.MemberIDs = slices.Clone(binding.MemberIDs)
		next[binding.Code] = binding
	}
	expectedRegions := len(proof.bindings)
	if proof.bindings[region].Code == "" {
		expectedRegions++
	}
	if next[region].Code == "" || len(next) != expectedRegions {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	for admitted := range proof.bindings {
		if next[admitted].Code == "" {
			return ErrControlContractInvalid
		}
	}
	proof.runtime, proof.bindings = runtime, next
	proof.provider.runtime = runtime
	return nil
}
