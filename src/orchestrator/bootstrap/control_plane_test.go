package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type controlMachineProvider struct {
	mu       sync.Mutex
	calls    []ControlAction
	evidence map[string][]CandidateEvidence
}

func (p *controlMachineProvider) record(ctx context.Context, request ControlActionRequest, kind ControlActionKind) (ControlReceipt, error) {
	if ctx == nil || ctx.Err() != nil || request.Action.Kind != kind || request.PlanFingerprint == "" {
		return ControlReceipt{}, ErrControlInvalid
	}
	p.mu.Lock()
	p.calls = append(p.calls, request.Action)
	p.mu.Unlock()
	return ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (p *controlMachineProvider) StartTemporaryR1(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionStartTemporaryR1)
}

func (p *controlMachineProvider) FenceTemporaryR1(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionFenceR1)
}

func (p *controlMachineProvider) StartCandidate(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionStartCandidate)
}

func (p *controlMachineProvider) SyncCandidate(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionSyncCandidate)
}

func (p *controlMachineProvider) VerifyCandidate(ctx context.Context, request ControlActionRequest) (CandidateEvidence, error) {
	if _, err := p.record(ctx, request, ControlActionVerifyCandidate); err != nil {
		return CandidateEvidence{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := p.evidence[request.Action.Region]
	if len(values) == 0 {
		return CandidateEvidence{Region: request.Action.Region}, nil
	}
	value := values[0]
	if len(values) > 1 {
		p.evidence[request.Action.Region] = values[1:]
	}
	return value, nil
}

func (p *controlMachineProvider) PromoteGlobalR3(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionPromoteR3)
}

func (p *controlMachineProvider) VerifyGlobalR3(ctx context.Context, request ControlActionRequest) error {
	_, err := p.record(ctx, request, ControlActionVerifyQuorum)
	return err
}

func (p *controlMachineProvider) RevokeBootstrapAuthority(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionRevokeBootstrap)
}

func (p *controlMachineProvider) RemoteManageRegion(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionRemoteManage)
}

func (p *controlMachineProvider) StartRegionalR3(ctx context.Context, request ControlActionRequest) (ControlReceipt, error) {
	return p.record(ctx, request, ControlActionStartRegionalR3)
}

func (p *controlMachineProvider) snapshotCalls() []ControlAction {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ControlAction(nil), p.calls...)
}

func readyControlCandidate(region, marker string) CandidateEvidence {
	return CandidateEvidence{
		Region:         region,
		IdentityDigest: strings.Repeat(marker, 64),
		StorageDigest:  strings.Repeat(marker, 64),
		HealthDigest:   strings.Repeat(marker, 64),
		CaughtUp:       true,
		IdentityReady:  true,
		StorageReady:   true,
		HealthReady:    true,
	}
}

func newControlMachineForTest(t *testing.T, provider ControlPlaneProvider, journal ControlJournal, attempts int) *ControlStateMachine {
	t.Helper()
	machine, err := NewControlStateMachine(provider, journal, RetryPolicy{MaxAttempts: attempts})
	if err != nil {
		t.Fatal(err)
	}
	return machine
}

func TestControlStateMachineUsesOneJournalForBootstrapCandidatesAndPromotion(t *testing.T) {
	provider := &controlMachineProvider{evidence: map[string][]CandidateEvidence{
		"sfo": {readyControlCandidate("sfo", "a")},
		"fra": {readyControlCandidate("fra", "b")},
	}}
	journal := &MemoryControlJournal{Durable: true}
	machine := newControlMachineForTest(t, provider, journal, 1)
	ctx := context.Background()

	bootstrapResult, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{
		Operation: ControlOperationBootstrap, Region: "gru", MemberHosts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bootstrapResult.State.Topology != ControlTopologyTemporaryR1 || bootstrapResult.State.Epoch != 1 {
		t.Fatalf("bootstrap state = %#v", bootstrapResult.State)
	}

	sfo, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{
		Operation: ControlOperationAddRegion, Region: "sfo", MemberHosts: 2,
		Candidate: readyControlCandidate("sfo", "f"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if sfo.State.Topology != ControlTopologyTemporaryR1 || !controlCandidateMatches(sfo.State, readyControlCandidate("sfo", "a")) {
		t.Fatalf("SFO state did not contain provider evidence: %#v", sfo.State)
	}

	fra, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{
		Operation: ControlOperationAddRegion, Region: "fra", MemberHosts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fra.State.Topology != ControlTopologyGlobalR3 || fra.State.Phase != ControlPhaseR3 || fra.State.Epoch != 2 || fra.State.BootstrapAuthorized {
		t.Fatalf("promoted state = %#v", fra.State)
	}
	if !controlCandidateMatches(fra.State, readyControlCandidate("sfo", "a")) || !controlCandidateMatches(fra.State, readyControlCandidate("fra", "b")) {
		t.Fatalf("promoted state lost provider evidence: %#v", fra.State.Candidates)
	}
	record, err := journal.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if record.PlanFingerprint != "" || len(record.Completed) != 0 || !sameControlState(record.State, fra.State) {
		t.Fatalf("settled journal = %#v", record)
	}

	wantKinds := []ControlActionKind{
		ControlActionStartTemporaryR1, ControlActionFenceR1,
		ControlActionStartCandidate, ControlActionSyncCandidate, ControlActionVerifyCandidate,
		ControlActionStartCandidate, ControlActionSyncCandidate, ControlActionVerifyCandidate,
		ControlActionPromoteR3, ControlActionVerifyQuorum, ControlActionRevokeBootstrap,
	}
	if got := controlCallKinds(provider.snapshotCalls()); !reflect.DeepEqual(got, wantKinds) {
		t.Fatalf("control call order = %v, want %v", got, wantKinds)
	}
	before := len(provider.snapshotCalls())
	replayed, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{
		Operation: ControlOperationAddRegion, Region: "fra", MemberHosts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.State.Epoch != 2 || len(provider.snapshotCalls()) != before {
		t.Fatalf("completed replay changed state or provider calls: state=%#v calls=%d", replayed.State, len(provider.snapshotCalls()))
	}
}

func TestControlStateMachineReobservesCandidateUntilReady(t *testing.T) {
	provider := &controlMachineProvider{evidence: map[string][]CandidateEvidence{
		"sfo": {{Region: "sfo"}, readyControlCandidate("sfo", "c")},
	}}
	journal := &MemoryControlJournal{Durable: true}
	machine := newControlMachineForTest(t, provider, journal, 2)
	ctx := context.Background()
	if _, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationBootstrap, Region: "gru", MemberHosts: 2}); err != nil {
		t.Fatal(err)
	}
	result, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "sfo", MemberHosts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !controlCandidateMatches(result.State, readyControlCandidate("sfo", "c")) {
		t.Fatalf("candidate evidence = %#v", result.State.Candidates)
	}
	verifyCalls := 0
	for _, call := range provider.snapshotCalls() {
		if call.Kind == ControlActionVerifyCandidate && call.Region == "sfo" {
			verifyCalls++
		}
	}
	if verifyCalls != 2 {
		t.Fatalf("verify calls = %d, want 2", verifyCalls)
	}
}

func TestControlStateMachineRejectsConflictingActiveTransition(t *testing.T) {
	state := ControlPlaneState{
		Topology: ControlTopologyTemporaryR1, Phase: ControlPhaseR1, Epoch: 1,
		BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"},
	}
	sfoPlan, err := PlanControlTransition(state, executionControlRequest(state, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "sfo", MemberHosts: 2}))
	if err != nil {
		t.Fatal(err)
	}
	journal := &MemoryControlJournal{Durable: true, Record: ControlJournalRecord{
		PlanFingerprint: sfoPlan.Fingerprint, State: sfoPlan.From, Completed: []string{sfoPlan.Actions[0].ID},
	}}
	provider := &controlMachineProvider{evidence: map[string][]CandidateEvidence{"sfo": {readyControlCandidate("sfo", "d")}}}
	machine := newControlMachineForTest(t, provider, journal, 1)
	_, err = machine.Execute(context.Background(), ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "fra", MemberHosts: 2})
	if !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("conflicting transition error = %v", err)
	}
	if len(provider.snapshotCalls()) != 0 {
		t.Fatalf("conflicting transition reached provider: %v", provider.snapshotCalls())
	}
	record, loadErr := journal.Load(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if record.PlanFingerprint != sfoPlan.Fingerprint || !reflect.DeepEqual(record.Completed, []string{sfoPlan.Actions[0].ID}) {
		t.Fatalf("conflicting transition changed journal: %#v", record)
	}
}

type failFirstControlSave struct {
	inner  *MemoryControlJournal
	mu     sync.Mutex
	failed bool
}

func (j *failFirstControlSave) AuthoritativeDurable() bool { return true }
func (j *failFirstControlSave) Load(ctx context.Context) (ControlJournalRecord, error) {
	return j.inner.Load(ctx)
}
func (j *failFirstControlSave) Save(ctx context.Context, record ControlJournalRecord) error {
	j.mu.Lock()
	if !j.failed {
		j.failed = true
		j.mu.Unlock()
		return ErrControlJournalUnavailable
	}
	j.mu.Unlock()
	return j.inner.Save(ctx, record)
}

func TestControlStateMachinePersistsIntentBeforeProviderEffect(t *testing.T) {
	provider := &controlMachineProvider{}
	journal := &failFirstControlSave{inner: &MemoryControlJournal{Durable: true}}
	machine := newControlMachineForTest(t, provider, journal, 1)
	request := ControlTransitionRequest{Operation: ControlOperationBootstrap, Region: "gru", MemberHosts: 2}
	if _, err := machine.Execute(context.Background(), ControlPlaneState{}, request); !errors.Is(err, ErrControlJournalUnavailable) {
		t.Fatalf("first execute error = %v", err)
	}
	if len(provider.snapshotCalls()) != 0 {
		t.Fatalf("provider was called before intent durability: %v", provider.snapshotCalls())
	}
	result, err := machine.Execute(context.Background(), ControlPlaneState{}, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.State.Epoch != 1 || len(provider.snapshotCalls()) != 2 {
		t.Fatalf("recovered execution state=%#v calls=%v", result.State, provider.snapshotCalls())
	}
}

func TestFileControlJournalCarriesEqualEpochCandidateStateAcrossReopen(t *testing.T) {
	provider := &controlMachineProvider{evidence: map[string][]CandidateEvidence{
		"sfo": {readyControlCandidate("sfo", "e")},
		"fra": {readyControlCandidate("fra", "f")},
	}}
	path := filepath.Join(t.TempDir(), "control.json")
	ctx := context.Background()
	open := func() *ControlStateMachine {
		journal, err := NewFileControlJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		return newControlMachineForTest(t, provider, journal, 1)
	}
	if _, err := open().Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationBootstrap, Region: "gru", MemberHosts: 2}); err != nil {
		t.Fatal(err)
	}
	if result, err := open().Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "sfo", MemberHosts: 2}); err != nil {
		t.Fatal(err)
	} else if !controlCandidateMatches(result.State, readyControlCandidate("sfo", "e")) {
		t.Fatalf("reopened SFO state = %#v", result.State)
	}
	if result, err := open().Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "fra", MemberHosts: 2}); err != nil {
		t.Fatal(err)
	} else if result.State.Topology != ControlTopologyGlobalR3 || result.State.Epoch != 2 {
		t.Fatalf("reopened promoted state = %#v", result.State)
	}
}

func TestControlStateMachineSerializesConcurrentReplay(t *testing.T) {
	provider := &controlMachineProvider{evidence: map[string][]CandidateEvidence{"sfo": {readyControlCandidate("sfo", "a")}}}
	journal := &MemoryControlJournal{Durable: true}
	machine := newControlMachineForTest(t, provider, journal, 1)
	ctx := context.Background()
	if _, err := machine.Execute(ctx, ControlPlaneState{}, ControlTransitionRequest{Operation: ControlOperationBootstrap, Region: "gru", MemberHosts: 2}); err != nil {
		t.Fatal(err)
	}
	request := ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: "sfo", MemberHosts: 2}
	var wait sync.WaitGroup
	errorsByCall := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := machine.Execute(ctx, ControlPlaneState{}, request)
			errorsByCall <- err
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	var candidateCalls int
	for _, call := range provider.snapshotCalls() {
		if call.Region == "sfo" {
			candidateCalls++
		}
	}
	if candidateCalls != 3 {
		t.Fatalf("concurrent replay made %d candidate calls, want 3", candidateCalls)
	}
}

func controlCandidateMatches(state ControlPlaneState, want CandidateEvidence) bool {
	for _, candidate := range state.Candidates {
		if candidate.Region == want.Region {
			return candidate == want
		}
	}
	return false
}

func controlCallKinds(calls []ControlAction) []ControlActionKind {
	result := make([]ControlActionKind, 0, len(calls))
	for _, call := range calls {
		result = append(result, call.Kind)
	}
	return result
}

func TestRemoteAdmissionsPreservePermanentGlobalJournal(t *testing.T) {
	state := ControlPlaneState{Topology: ControlTopologyGlobalR3, Phase: ControlPhaseR3, Epoch: 2, MemberHosts: 2, ControlRegions: []string{"gru", "sfo", "fra"}}
	journal := &MemoryControlJournal{Durable: true}
	provider := &controlMachineProvider{}
	machine := newControlMachineForTest(t, provider, journal, 1)
	for _, region := range []string{"ord", "iad"} {
		result, err := machine.Execute(context.Background(), state, ControlTransitionRequest{Operation: ControlOperationAddRegion, Region: region, MemberHosts: 4})
		if err != nil {
			t.Fatalf("admit %s: %v", region, err)
		}
		if !sameControlState(result.State, state) {
			t.Fatalf("admitting %s changed global state: %+v", region, result.State)
		}
	}
	if len(provider.snapshotCalls()) != 2 {
		t.Fatalf("admissions: %+v", provider.snapshotCalls())
	}
}

func TestRemoteAdmissionRequiresPermanentLaunchQuorum(t *testing.T) {
	temporary := ControlPlaneState{Topology: ControlTopologyTemporaryR1, Phase: ControlPhaseR1, Epoch: 1, BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"}}
	for _, operation := range []ControlOperation{ControlOperationAddRegion, ControlOperationRemoteManage} {
		if _, err := PlanControlTransition(temporary, ControlTransitionRequest{Operation: operation, Region: "ord", MemberHosts: 2}); !errors.Is(err, ErrControlQuorumNotVerified) {
			t.Fatalf("%s: %v", operation, err)
		}
	}
	invalid := ControlPlaneState{Topology: ControlTopologyGlobalR3, Phase: ControlPhaseR3, Epoch: 2, MemberHosts: 2, ControlRegions: []string{"gru", "sfo", "ord"}}
	if err := invalid.Validate(); !errors.Is(err, ErrControlInvalid) {
		t.Fatalf("replacement global region: %v", err)
	}
}
