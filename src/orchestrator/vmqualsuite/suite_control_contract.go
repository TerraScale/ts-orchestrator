package vmqualsuite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

var (
	ErrControlContractInvalid = errors.New("vmqual: control contract is invalid")
	ErrControlContractOrder   = errors.New("vmqual: control contract step is out of order")
)

// ControlContractCall is one state-machine call observed at the provider
// boundary. Applied is a modeled fixture mutation flag; runtime-backed calls
// record fresh proof receipt without claiming an underlying mutation count.
type ControlContractCall struct {
	Sequence      uint64
	Kind          bootstrap.ControlActionKind
	Region        string
	ExpectedEpoch uint64
	TargetEpoch   uint64
	Applied       bool
}

// ControlBootstrapProof describes the accepted empty-to-R1 transition. Host
// health remains a VM/provider concern; this proof covers only control state.
type ControlBootstrapProof struct {
	Initial             *vmqual.InitialControlObservation
	State               bootstrap.ControlPlaneState
	AcceptedEpoch       uint64
	MemberHosts         int
	Fenced              bool
	BootstrapAuthorized bool
	JournalPath         string
	Calls               []ControlContractCall
}

// ControlCandidateProof describes the observed synchronization handshake for
// one launch Region and the state produced after accepting that observation.
type ControlCandidateProof struct {
	Region                      string
	Candidate                   bootstrap.CandidateEvidence
	State                       bootstrap.ControlPlaneState
	SynchronizedBeforePromotion bool
	Promoted                    bool
	PromotionEpoch              uint64
	JournalPaths                []string
	Calls                       []ControlContractCall
}

// ControlR3Proof contains negative and degraded-state checks against the
// permanent global control group.
type ControlR3Proof struct {
	State                         bootstrap.ControlPlaneState
	AcceptedEpoch                 uint64
	GlobalReplicas                []string
	LostReplica                   string
	ActiveReplicasAfterLoss       []string
	QuorumAvailableAfterLoss      bool
	BootstrapAuthorityRetired     bool
	BootstrapAuthorityReuseDenied bool
	EpochRegressionDenied         bool
	DowngradeToR1Denied           bool
}

// ControlRemoteRegionProof keeps the global R3 state distinct from the
// region-local topology returned by the remote-management transition.
type ControlRemoteRegionProof struct {
	Region                       string
	MemberHosts                  int
	GlobalState                  bootstrap.ControlPlaneState
	RegionState                  bootstrap.ControlPlaneState
	GlobalReplicas               []string
	RemoteManaged                bool
	HasGlobalReplica             bool
	RegionalR3BelowFloorRejected bool
	JournalPath                  string
	Calls                        []ControlContractCall
}

// ControlContract is portable unit-test support for the public bootstrap
// state machine. It is selected explicitly by unit tests; VM qualification
// instead resolves the factory's authenticated guest control runtime.
type ControlContract struct {
	mu          sync.Mutex
	journalRoot string
	journalPath string
	journal     *bootstrap.FileControlJournal
	journalUsed bool
	state       bootstrap.ControlPlaneState
	provider    *controlContractProvider
	launchReady map[string]bool
	r3Checked   bool
	remote      map[string]bool
}

// NewControlContract creates a staged control proof. journalRoot may be
// relative; it is converted to a clean absolute path before any journal write.
func NewControlContract(journalRoot string) (*ControlContract, error) {
	if strings.TrimSpace(journalRoot) == "" || strings.ContainsAny(journalRoot, "\r\n\x00") {
		return nil, ErrControlContractInvalid
	}
	absolute, err := filepath.Abs(filepath.Clean(journalRoot))
	if err != nil || absolute == string(filepath.Separator) {
		return nil, ErrControlContractInvalid
	}
	journalPath := filepath.Join(absolute, "control.json")
	journal, err := bootstrap.NewFileControlJournal(journalPath)
	if err != nil {
		return nil, ErrControlContractInvalid
	}
	return &ControlContract{
		journalRoot: absolute,
		journalPath: journalPath,
		journal:     journal,
		provider:    newControlContractProvider(),
		launchReady: make(map[string]bool),
		remote:      make(map[string]bool),
	}, nil
}

// State returns a detached copy of the accepted permanent control state.
func (c *ControlContract) State() bootstrap.ControlPlaneState {
	if c == nil {
		return bootstrap.ControlPlaneState{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneControlState(c.state)
}

// JournalPaths returns the one authoritative journal after its first use.
func (c *ControlContract) JournalPaths() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.journalUsed {
		return nil
	}
	return []string{c.journalPath}
}

// Bootstrap proves the empty-to-fenced-temporary-R1 control transition.
func (c *ControlContract) Bootstrap(ctx context.Context) (ControlBootstrapProof, error) {
	if c == nil || ctx == nil {
		return ControlBootstrapProof{}, ErrControlContractInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Epoch != 0 {
		return ControlBootstrapProof{}, ErrControlContractOrder
	}
	callStart := c.provider.callCount()
	result, journalPath, err := c.execute(ctx, "bootstrap-gru-r1", c.state, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationBootstrap,
		Region:      "gru",
		MemberHosts: 2,
	})
	if err != nil {
		return ControlBootstrapProof{}, err
	}
	snapshot := c.provider.snapshot()
	if result.State.Topology != bootstrap.ControlTopologyTemporaryR1 ||
		result.State.Phase != bootstrap.ControlPhaseR1 ||
		result.State.Epoch != 1 || result.State.MemberHosts != 2 ||
		len(result.State.ControlRegions) != 1 || result.State.ControlRegions[0] != "gru" ||
		!result.State.BootstrapAuthorized || !snapshot.r1Fenced ||
		snapshot.acceptedEpoch != result.State.Epoch {
		return ControlBootstrapProof{}, ErrControlContractInvalid
	}
	c.state = cloneControlState(result.State)
	return ControlBootstrapProof{
		State:               cloneControlState(result.State),
		AcceptedEpoch:       snapshot.acceptedEpoch,
		MemberHosts:         result.State.MemberHosts,
		Fenced:              snapshot.r1Fenced,
		BootstrapAuthorized: snapshot.bootstrapAuthorized,
		JournalPath:         journalPath,
		Calls:               c.provider.callsFrom(callStart),
	}, nil
}

// AddLaunchCandidate starts and synchronizes SFO or FRA. The state machine
// consumes the provider's observation directly and promotes after both
// candidates are durably ready.
func (c *ControlContract) AddLaunchCandidate(ctx context.Context, region string) (ControlCandidateProof, error) {
	if c == nil || ctx == nil {
		return ControlCandidateProof{}, ErrControlContractInvalid
	}
	region = strings.ToLower(strings.TrimSpace(region))
	if region != "sfo" && region != "fra" {
		return ControlCandidateProof{}, ErrControlContractInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Phase != bootstrap.ControlPhaseR1 || c.state.Epoch != 1 || c.launchReady[region] {
		return ControlCandidateProof{}, ErrControlContractOrder
	}
	if region == "fra" && !c.launchReady["sfo"] {
		return ControlCandidateProof{}, ErrControlContractOrder
	}

	callStart := c.provider.callCount()
	result, journalPath, err := c.execute(ctx, "add-"+region+"-candidate", c.state, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationAddRegion,
		Region:      region,
		MemberHosts: 2,
	})
	if err != nil {
		return ControlCandidateProof{}, err
	}
	snapshot := c.provider.snapshot()
	candidateState := snapshot.candidates[region]
	observed := candidateState.evidence()
	beforePromotion := candidateState.syncSequence > 0 &&
		(snapshot.promotionSequence == 0 || candidateState.syncSequence < snapshot.promotionSequence)
	if !beforePromotion || !observed.Ready() {
		return ControlCandidateProof{}, ErrControlContractInvalid
	}
	promoted := result.State.Topology == bootstrap.ControlTopologyGlobalR3
	if region == "sfo" && promoted {
		return ControlCandidateProof{}, ErrControlContractInvalid
	}
	if region == "fra" {
		if !promoted || result.State.Phase != bootstrap.ControlPhaseR3 || result.State.Epoch != 2 ||
			result.State.BootstrapAuthorized || !snapshot.quorumVerified || snapshot.bootstrapAuthorized {
			return ControlCandidateProof{}, ErrControlContractInvalid
		}
		for _, launchRegion := range []string{"sfo", "fra"} {
			candidate := snapshot.candidates[launchRegion]
			if !candidate.evidence().Ready() || candidate.syncSequence >= snapshot.promotionSequence {
				return ControlCandidateProof{}, ErrControlContractInvalid
			}
		}
	}
	c.launchReady[region] = true
	c.state = cloneControlState(result.State)
	return ControlCandidateProof{
		Region:                      region,
		Candidate:                   observed,
		State:                       cloneControlState(result.State),
		SynchronizedBeforePromotion: beforePromotion,
		Promoted:                    promoted,
		PromotionEpoch:              snapshot.acceptedEpoch,
		JournalPaths:                []string{journalPath},
		Calls:                       c.provider.callsFrom(callStart),
	}, nil
}

// VerifyPermanentR3 proves fail-closed epoch and authority behavior, then
// removes one modeled replica and checks that the remaining two retain quorum.
func (c *ControlContract) VerifyPermanentR3(ctx context.Context) (ControlR3Proof, error) {
	if c == nil || ctx == nil {
		return ControlR3Proof{}, ErrControlContractInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.r3Checked || !c.launchReady["sfo"] || !c.launchReady["fra"] ||
		c.state.Topology != bootstrap.ControlTopologyGlobalR3 || c.state.Phase != bootstrap.ControlPhaseR3 {
		return ControlR3Proof{}, ErrControlContractOrder
	}
	if err := ctx.Err(); err != nil {
		return ControlR3Proof{}, err
	}

	_, authorityErr := bootstrap.PlanControlTransition(c.state, bootstrap.ControlTransitionRequest{
		Operation: bootstrap.ControlOperationHandoff,
	})
	authorityDenied := errors.Is(authorityErr, bootstrap.ErrControlAuthorityRevoked)
	_, downgradeErr := bootstrap.PlanControlTransition(c.state, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationBootstrap,
		Region:      "gru",
		MemberHosts: 2,
	})
	downgradeDenied := errors.Is(downgradeErr, bootstrap.ErrControlInvalid)

	staleJournal := &bootstrap.MemoryControlJournal{Durable: true}
	staleMachine, err := bootstrap.NewControlStateMachine(c.provider, staleJournal, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		return ControlR3Proof{}, err
	}
	staleState := bootstrap.ControlPlaneState{
		Topology:            bootstrap.ControlTopologyTemporaryR1,
		Phase:               bootstrap.ControlPhaseR1,
		Epoch:               1,
		BootstrapAuthorized: true,
		MemberHosts:         2,
		ControlRegions:      []string{"gru"},
	}
	_, regressionErr := staleMachine.Execute(ctx, staleState, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationAddRegion,
		Region:      "sfo",
		MemberHosts: 2,
	})
	regressionDenied := errors.Is(regressionErr, bootstrap.ErrControlEpochRegression)
	if !authorityDenied || !downgradeDenied || !regressionDenied {
		return ControlR3Proof{}, ErrControlContractInvalid
	}

	if err := c.provider.loseReplica("fra"); err != nil {
		return ControlR3Proof{}, err
	}
	snapshot := c.provider.snapshot()
	active := snapshot.activeReplicas()
	quorum := snapshot.globalR3 && snapshot.acceptedEpoch == c.state.Epoch && len(active) >= 2
	if !quorum || snapshot.bootstrapAuthorized || !snapshot.quorumVerified {
		return ControlR3Proof{}, ErrControlContractInvalid
	}
	c.r3Checked = true
	return ControlR3Proof{
		State:                         cloneControlState(c.state),
		AcceptedEpoch:                 snapshot.acceptedEpoch,
		GlobalReplicas:                snapshot.globalReplicas(),
		LostReplica:                   "fra",
		ActiveReplicasAfterLoss:       active,
		QuorumAvailableAfterLoss:      quorum,
		BootstrapAuthorityRetired:     !snapshot.bootstrapAuthorized,
		BootstrapAuthorityReuseDenied: authorityDenied,
		EpochRegressionDenied:         regressionDenied,
		DowngradeToR1Denied:           downgradeDenied,
	}, nil
}

// VerifyRemoteRegion proves that a two-host later Region uses the permanent
// global group remotely and that regional R3 planning fails below three hosts.
func (c *ControlContract) VerifyRemoteRegion(ctx context.Context, region string) (ControlRemoteRegionProof, error) {
	if c == nil || ctx == nil {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" || region == "gru" || region == "sfo" || region == "fra" {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.r3Checked || c.remote[region] || c.state.Topology != bootstrap.ControlTopologyGlobalR3 {
		return ControlRemoteRegionProof{}, ErrControlContractOrder
	}

	_, floorErr := bootstrap.PlanControlTransition(c.state, bootstrap.ControlTransitionRequest{
		Operation:       bootstrap.ControlOperationAddRegion,
		Region:          region,
		MemberHosts:     2,
		EligibleHosts:   2,
		RegionalControl: true,
	})
	floorRejected := errors.Is(floorErr, bootstrap.ErrControlRegionalMembersFloor)
	if !floorRejected {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}

	callStart := c.provider.callCount()
	result, journalPath, err := c.execute(ctx, "remote-manage-"+region, c.state, bootstrap.ControlTransitionRequest{
		Operation:     bootstrap.ControlOperationAddRegion,
		Region:        region,
		MemberHosts:   2,
		EligibleHosts: 2,
	})
	if err != nil {
		return ControlRemoteRegionProof{}, err
	}
	snapshot := c.provider.snapshot()
	memberHosts, remoteManaged := snapshot.remoteRegions[region]
	hasGlobalReplica := snapshot.replicas[region]
	if result.State.Topology != bootstrap.ControlTopologyGlobalR3 || result.State.Phase != bootstrap.ControlPhaseR3 ||
		result.State.Epoch != c.state.Epoch || memberHosts != 2 || !remoteManaged || hasGlobalReplica ||
		!sameStrings(result.State.ControlRegions, c.state.ControlRegions) || !snapshot.globalR3 {
		return ControlRemoteRegionProof{}, ErrControlContractInvalid
	}
	c.remote[region] = true
	return ControlRemoteRegionProof{
		Region:                       region,
		MemberHosts:                  memberHosts,
		GlobalState:                  cloneControlState(c.state),
		RegionState:                  cloneControlState(result.State),
		GlobalReplicas:               snapshot.globalReplicas(),
		RemoteManaged:                remoteManaged,
		HasGlobalReplica:             hasGlobalReplica,
		RegionalR3BelowFloorRejected: floorRejected,
		JournalPath:                  journalPath,
		Calls:                        c.provider.callsFrom(callStart),
	}, nil
}

func (c *ControlContract) execute(ctx context.Context, label string, state bootstrap.ControlPlaneState, request bootstrap.ControlTransitionRequest) (bootstrap.ControlExecutionResult, string, error) {
	if err := ctx.Err(); err != nil {
		return bootstrap.ControlExecutionResult{}, "", err
	}
	_ = label
	if c.journal == nil || c.journalPath == "" {
		return bootstrap.ControlExecutionResult{}, "", ErrControlContractInvalid
	}
	machine, err := bootstrap.NewControlStateMachine(c.provider, c.journal, bootstrap.RetryPolicy{MaxAttempts: 1})
	if err != nil {
		return bootstrap.ControlExecutionResult{}, "", err
	}
	result, err := machine.Execute(ctx, state, request)
	if err != nil {
		return result, c.journalPath, err
	}
	record, err := c.journal.Load(ctx)
	if err != nil || record.PlanFingerprint != "" || len(record.Completed) != 0 || !reflect.DeepEqual(record.State, result.State) {
		return result, c.journalPath, ErrControlContractInvalid
	}
	c.journalUsed = true
	return result, c.journalPath, nil
}

type controlContractCandidate struct {
	region         string
	started        bool
	synchronized   bool
	identityReady  bool
	storageReady   bool
	healthReady    bool
	syncSequence   uint64
	identityDigest string
	storageDigest  string
	healthDigest   string
}

func (c controlContractCandidate) evidence() bootstrap.CandidateEvidence {
	return bootstrap.CandidateEvidence{
		Region:         c.region,
		IdentityDigest: c.identityDigest,
		StorageDigest:  c.storageDigest,
		HealthDigest:   c.healthDigest,
		CaughtUp:       c.synchronized,
		IdentityReady:  c.identityReady,
		StorageReady:   c.storageReady,
		HealthReady:    c.healthReady,
	}
}

type controlContractProvider struct {
	mu                  sync.Mutex
	sequence            uint64
	acceptedEpoch       uint64
	r1Started           bool
	r1Fenced            bool
	bootstrapAuthorized bool
	globalR3            bool
	quorumVerified      bool
	promotionSequence   uint64
	candidates          map[string]controlContractCandidate
	replicas            map[string]bool
	remoteRegions       map[string]int
	receipts            map[string]ControlContractCall
	calls               []ControlContractCall
}

func newControlContractProvider() *controlContractProvider {
	return &controlContractProvider{
		candidates:    make(map[string]controlContractCandidate),
		replicas:      make(map[string]bool),
		remoteRegions: make(map[string]int),
		receipts:      make(map[string]ControlContractCall),
	}
}

func (p *controlContractProvider) StartTemporaryR1(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionStartTemporaryR1, func() error {
		if p.acceptedEpoch != 0 || request.State.Epoch != 0 || request.State.Phase != bootstrap.ControlPhaseEmpty ||
			request.Action.Region != "gru" || request.Action.TargetEpoch != 1 {
			if p.acceptedEpoch > request.Action.TargetEpoch {
				return bootstrap.ErrControlEpochRegression
			}
			return ErrControlContractInvalid
		}
		p.r1Started = true
		return nil
	})
}

func (p *controlContractProvider) FenceTemporaryR1(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionFenceR1, func() error {
		if !p.r1Started || p.acceptedEpoch != 0 || request.Action.Region != "gru" || request.Action.TargetEpoch != 1 {
			return ErrControlContractInvalid
		}
		p.acceptedEpoch = 1
		p.r1Fenced = true
		p.bootstrapAuthorized = true
		p.replicas["gru"] = true
		return nil
	})
}

func (p *controlContractProvider) StartCandidate(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionStartCandidate, func() error {
		if !p.r1Fenced || !p.bootstrapAuthorized || p.globalR3 || request.State.Epoch != p.acceptedEpoch ||
			(request.Action.Region != "sfo" && request.Action.Region != "fra") {
			return ErrControlContractInvalid
		}
		candidate := p.candidates[request.Action.Region]
		candidate.region = request.Action.Region
		candidate.started = true
		candidate.identityReady = true
		candidate.identityDigest = controlContractDigest(request.Action.Region, "identity")
		p.candidates[request.Action.Region] = candidate
		return nil
	})
}

func (p *controlContractProvider) SyncCandidate(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionSyncCandidate, func() error {
		candidate := p.candidates[request.Action.Region]
		if !candidate.started || request.State.Epoch != p.acceptedEpoch || p.globalR3 {
			return ErrControlContractInvalid
		}
		candidate.synchronized = true
		candidate.storageReady = true
		candidate.healthReady = true
		candidate.storageDigest = controlContractDigest(request.Action.Region, "storage")
		candidate.healthDigest = controlContractDigest(request.Action.Region, "health")
		candidate.syncSequence = p.sequence + 1
		p.candidates[request.Action.Region] = candidate
		return nil
	})
}

func (p *controlContractProvider) VerifyCandidate(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.CandidateEvidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateControlCall(ctx, request, bootstrap.ControlActionVerifyCandidate); err != nil {
		return bootstrap.CandidateEvidence{}, err
	}
	if prior, ok := p.receipts[request.Action.IdempotencyKey]; ok {
		if !sameControlCall(prior, request.Action) {
			return bootstrap.CandidateEvidence{}, ErrControlContractInvalid
		}
		p.appendCall(request.Action, false)
		candidate := p.candidates[request.Action.Region]
		if !candidate.evidence().Ready() {
			return bootstrap.CandidateEvidence{}, ErrControlContractInvalid
		}
		return candidate.evidence(), nil
	}
	candidate := p.candidates[request.Action.Region]
	if request.State.Epoch != p.acceptedEpoch || !candidate.evidence().Ready() {
		return bootstrap.CandidateEvidence{}, ErrControlContractInvalid
	}
	call := p.appendCall(request.Action, true)
	p.receipts[request.Action.IdempotencyKey] = call
	return candidate.evidence(), nil
}

func (p *controlContractProvider) PromoteGlobalR3(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionPromoteR3, func() error {
		if !p.bootstrapAuthorized || p.globalR3 || request.Action.ExpectedEpoch != p.acceptedEpoch ||
			request.Action.TargetEpoch != p.acceptedEpoch+1 {
			return ErrControlContractInvalid
		}
		for _, region := range []string{"sfo", "fra"} {
			if !p.candidates[region].evidence().Ready() {
				return bootstrap.ErrControlPromotionNotReady
			}
		}
		p.acceptedEpoch = request.Action.TargetEpoch
		p.globalR3 = true
		p.replicas = map[string]bool{"gru": true, "sfo": true, "fra": true}
		p.promotionSequence = p.sequence + 1
		return nil
	})
}

func (p *controlContractProvider) VerifyGlobalR3(ctx context.Context, request bootstrap.ControlActionRequest) error {
	_, err := p.mutate(ctx, request, bootstrap.ControlActionVerifyQuorum, func() error {
		if !p.globalR3 || request.Action.TargetEpoch != p.acceptedEpoch || len(p.activeReplicasLocked()) < 2 {
			return bootstrap.ErrControlQuorumNotVerified
		}
		p.quorumVerified = true
		return nil
	})
	return err
}

func (p *controlContractProvider) RevokeBootstrapAuthority(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionRevokeBootstrap, func() error {
		if !p.globalR3 || !p.quorumVerified || request.Action.TargetEpoch != p.acceptedEpoch || !p.bootstrapAuthorized {
			return ErrControlContractInvalid
		}
		p.bootstrapAuthorized = false
		return nil
	})
}

func (p *controlContractProvider) RemoteManageRegion(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	return p.mutate(ctx, request, bootstrap.ControlActionRemoteManage, func() error {
		region := request.Action.Region
		if !p.globalR3 || p.bootstrapAuthorized || len(p.activeReplicasLocked()) < 2 ||
			request.State.Topology != bootstrap.ControlTopologyGlobalR3 || request.State.MemberHosts != 2 ||
			region == "" || p.replicas[region] {
			return ErrControlContractInvalid
		}
		p.remoteRegions[region] = request.State.MemberHosts
		return nil
	})
}

func (p *controlContractProvider) StartRegionalR3(context.Context, bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	// ControlActionRequest does not carry EligibleHosts. The public planner must
	// enforce that floor before this provider method can safely run.
	return bootstrap.ControlReceipt{}, ErrControlContractInvalid
}

func (p *controlContractProvider) mutate(ctx context.Context, request bootstrap.ControlActionRequest, kind bootstrap.ControlActionKind, change func() error) (bootstrap.ControlReceipt, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateControlCall(ctx, request, kind); err != nil {
		return bootstrap.ControlReceipt{}, err
	}
	if request.Action.TargetEpoch < p.acceptedEpoch {
		return bootstrap.ControlReceipt{}, bootstrap.ErrControlEpochRegression
	}
	if prior, ok := p.receipts[request.Action.IdempotencyKey]; ok {
		if !sameControlCall(prior, request.Action) {
			return bootstrap.ControlReceipt{}, ErrControlContractInvalid
		}
		p.appendCall(request.Action, false)
		return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
	}
	if err := change(); err != nil {
		return bootstrap.ControlReceipt{}, err
	}
	call := p.appendCall(request.Action, true)
	p.receipts[request.Action.IdempotencyKey] = call
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func validateControlCall(ctx context.Context, request bootstrap.ControlActionRequest, kind bootstrap.ControlActionKind) error {
	if ctx == nil {
		return ErrControlContractInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if request.Action.Kind != kind || request.Action.ID == "" || request.Action.IdempotencyKey == "" ||
		request.PlanFingerprint == "" || request.Action.ExpectedEpoch > request.Action.TargetEpoch {
		return ErrControlContractInvalid
	}
	if err := request.State.Validate(); err != nil {
		return err
	}
	return nil
}

func (p *controlContractProvider) appendCall(action bootstrap.ControlAction, applied bool) ControlContractCall {
	p.sequence++
	call := ControlContractCall{
		Sequence:      p.sequence,
		Kind:          action.Kind,
		Region:        action.Region,
		ExpectedEpoch: action.ExpectedEpoch,
		TargetEpoch:   action.TargetEpoch,
		Applied:       applied,
	}
	p.calls = append(p.calls, call)
	return call
}

func (p *controlContractProvider) observeCandidate(region string) (bootstrap.CandidateEvidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	candidate := p.candidates[region].evidence()
	if !candidate.Ready() {
		return bootstrap.CandidateEvidence{}, ErrControlContractInvalid
	}
	return candidate, nil
}

func (p *controlContractProvider) loseReplica(region string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.globalR3 || !p.replicas[region] || len(p.activeReplicasLocked()) != 3 {
		return ErrControlContractInvalid
	}
	p.replicas[region] = false
	if len(p.activeReplicasLocked()) < 2 {
		return bootstrap.ErrControlQuorumNotVerified
	}
	return nil
}

func (p *controlContractProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *controlContractProvider) callsFrom(start int) []ControlContractCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if start < 0 || start > len(p.calls) {
		return nil
	}
	return append([]ControlContractCall(nil), p.calls[start:]...)
}

type controlContractProviderSnapshot struct {
	acceptedEpoch       uint64
	r1Fenced            bool
	bootstrapAuthorized bool
	globalR3            bool
	quorumVerified      bool
	promotionSequence   uint64
	candidates          map[string]controlContractCandidate
	replicas            map[string]bool
	remoteRegions       map[string]int
}

func (p *controlContractProvider) snapshot() controlContractProviderSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := controlContractProviderSnapshot{
		acceptedEpoch:       p.acceptedEpoch,
		r1Fenced:            p.r1Fenced,
		bootstrapAuthorized: p.bootstrapAuthorized,
		globalR3:            p.globalR3,
		quorumVerified:      p.quorumVerified,
		promotionSequence:   p.promotionSequence,
		candidates:          make(map[string]controlContractCandidate, len(p.candidates)),
		replicas:            make(map[string]bool, len(p.replicas)),
		remoteRegions:       make(map[string]int, len(p.remoteRegions)),
	}
	for region, candidate := range p.candidates {
		snapshot.candidates[region] = candidate
	}
	for region, active := range p.replicas {
		snapshot.replicas[region] = active
	}
	for region, members := range p.remoteRegions {
		snapshot.remoteRegions[region] = members
	}
	return snapshot
}

func (s controlContractProviderSnapshot) activeReplicas() []string {
	regions := make([]string, 0, len(s.replicas))
	for region, active := range s.replicas {
		if active {
			regions = append(regions, region)
		}
	}
	sort.Strings(regions)
	return regions
}

func (s controlContractProviderSnapshot) globalReplicas() []string {
	regions := make([]string, 0, len(s.replicas))
	for region := range s.replicas {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	return regions
}

func (p *controlContractProvider) activeReplicasLocked() []string {
	regions := make([]string, 0, len(p.replicas))
	for region, active := range p.replicas {
		if active {
			regions = append(regions, region)
		}
	}
	sort.Strings(regions)
	return regions
}

func sameControlCall(prior ControlContractCall, action bootstrap.ControlAction) bool {
	return prior.Kind == action.Kind && prior.Region == action.Region && prior.ExpectedEpoch == action.ExpectedEpoch && prior.TargetEpoch == action.TargetEpoch
}

func controlContractDigest(region, kind string) string {
	sum := sha256.Sum256([]byte("vmqual/control/" + region + "/" + kind))
	return hex.EncodeToString(sum[:])
}

func cloneControlState(state bootstrap.ControlPlaneState) bootstrap.ControlPlaneState {
	state.ControlRegions = append([]string(nil), state.ControlRegions...)
	state.Candidates = append([]bootstrap.CandidateEvidence(nil), state.Candidates...)
	return state
}

func controlCandidateEqual(a, b bootstrap.CandidateEvidence) bool {
	return a.Region == b.Region && a.IdentityDigest == b.IdentityDigest && a.StorageDigest == b.StorageDigest &&
		a.HealthDigest == b.HealthDigest && a.CaughtUp == b.CaughtUp && a.IdentityReady == b.IdentityReady &&
		a.StorageReady == b.StorageReady && a.HealthReady == b.HealthReady
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
