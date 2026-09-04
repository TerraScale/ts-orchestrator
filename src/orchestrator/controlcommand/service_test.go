package controlcommand

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

func TestProductionOptionsKeepCanonicalMutationPolicy(t *testing.T) {
	options := ProductionOptions()
	if options.ControlRetry.MaxAttempts != 8 || !options.AllowDeletes || options.ControlRetry.Backoff == nil {
		t.Fatalf("production options = %+v", options)
	}
}

func TestNewServiceRejectsIncompleteDependencies(t *testing.T) {
	if _, err := NewService(Dependencies{}, Options{ControlRetry: bootstrap.RetryPolicy{MaxAttempts: 1}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewService error = %v", err)
	}
}

func TestBootstrapUsesTypedProviderPathAndObservedControlState(t *testing.T) {
	control := newTestControl(bootstrap.ControlPlaneState{})
	var bootstrapped estate.Region
	service := newTestService(t, control, func(_ context.Context, request provider.BootstrapRequest, _ provider.BootstrapGateways, _ io.Writer) error {
		bootstrapped = request.Region
		return nil
	}, nil)

	result, err := service.Bootstrap(context.Background(), BootstrapRequest{
		Desired: estate.Default(),
		Provider: provider.BootstrapRequest{
			Region: estate.Region{Code: "caller-must-not-select-the-home-region"},
		},
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if bootstrapped.Code != "gru" || bootstrapped.OCIName != "sa-saopaulo-1" {
		t.Fatalf("bootstrap Region = %+v", bootstrapped)
	}
	if result.Execution.State.Topology != bootstrap.ControlTopologyTemporaryR1 ||
		result.Observation.State.Topology != bootstrap.ControlTopologyTemporaryR1 ||
		!result.Observation.BootstrapAuthorized {
		t.Fatalf("bootstrap result = %+v", result)
	}
	if got := control.callKinds(); len(got) != 2 || got[0] != bootstrap.ControlActionStartTemporaryR1 || got[1] != bootstrap.ControlActionFenceR1 {
		t.Fatalf("control calls = %v", got)
	}
}

func TestFourthRegionUsesRemoteManagementAndRefusesRegionalR3BelowFloor(t *testing.T) {
	desired := fourthRegionEstate(t)
	state := bootstrap.ControlPlaneState{
		Topology: bootstrap.ControlTopologyGlobalR3, Phase: bootstrap.ControlPhaseR3, Epoch: 2,
		ControlRegions: []string{"fra", "gru", "sfo"}, MemberHosts: 2,
	}
	control := newTestControl(state)
	control.observation.Replicas = []ControlReplica{
		{Region: "gru", MemberID: "ocid1.instance.oc1.gru.member1", Role: "global-r3", Epoch: 2, Active: true},
		{Region: "sfo", MemberID: "ocid1.instance.oc1.sfo.member1", Role: "global-r3", Epoch: 2, Active: true},
		{Region: "fra", MemberID: "ocid1.instance.oc1.fra.member1", Role: "global-r3", Epoch: 2, Active: true},
	}
	control.observation.QuorumAvailable = true
	var bootstrapCalls atomic.Int32
	service := newTestService(t, control, func(context.Context, provider.BootstrapRequest, provider.BootstrapGateways, io.Writer) error {
		bootstrapCalls.Add(1)
		return nil
	}, nil)

	added, err := service.AddRegion(context.Background(), AddRegionRequest{Desired: desired, Region: "ord"})
	if err != nil {
		t.Fatalf("AddRegion: %v", err)
	}
	if added.Execution.State.Topology != bootstrap.ControlTopologyGlobalR3 || added.Observation.State.Topology != bootstrap.ControlTopologyGlobalR3 {
		t.Fatalf("add result = %+v", added)
	}
	validated, err := service.ValidateRemoteRegion(context.Background(), RemoteRegionRequest{Desired: desired, Region: "ORD"})
	if err != nil {
		t.Fatalf("ValidateRemoteRegion: %v", err)
	}
	if !validated.RemoteManaged || validated.HasGlobalReplica || !validated.RegionalR3BelowFloorRejected || bootstrapCalls.Load() != 1 {
		t.Fatalf("remote validation = %+v; bootstrap calls = %d", validated, bootstrapCalls.Load())
	}
}

func TestReconcileUsesProvidedControllersAndDurableProgress(t *testing.T) {
	control := newTestControl(bootstrap.ControlPlaneState{})
	var controller *testReconciler
	source := ReconcilerSourceFunc(func(_ context.Context, desired estate.Spec) ([]reconcile.Reconciler, error) {
		declared, err := reconcile.Declared(desired)
		if err != nil {
			return nil, err
		}
		controller = &testReconciler{desired: declared, kinds: resourceKinds(declared)}
		return []reconcile.Reconciler{controller}, nil
	})
	service := newTestService(t, control, testBootstrapper, source)

	result, err := service.Reconcile(context.Background(), estate.Default())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !result.Converged || len(result.Applied.Actions) == 0 || !result.Remaining.Empty() || controller.applyCount() != 1 {
		t.Fatalf("reconcile result = %+v; applies = %d", result, controller.applyCount())
	}
}

func TestServiceSerializesConcurrentOperationsWithoutRaces(t *testing.T) {
	control := newTestControl(bootstrap.ControlPlaneState{})
	var sources atomic.Int32
	source := ReconcilerSourceFunc(func(_ context.Context, desired estate.Spec) ([]reconcile.Reconciler, error) {
		sources.Add(1)
		declared, err := reconcile.Declared(desired)
		if err != nil {
			return nil, err
		}
		return []reconcile.Reconciler{&testReconciler{state: declared, desired: declared, kinds: resourceKinds(declared)}}, nil
	})
	service := newTestService(t, control, testBootstrapper, source)

	const workers = 24
	start := make(chan struct{})
	errorsSeen := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, err := service.Reconcile(context.Background(), estate.Default()); err != nil {
				errorsSeen <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Errorf("concurrent Reconcile: %v", err)
	}
	if sources.Load() != workers {
		t.Fatalf("reconciler source calls = %d, want %d", sources.Load(), workers)
	}
}

func testBootstrapper(context.Context, provider.BootstrapRequest, provider.BootstrapGateways, io.Writer) error {
	return nil
}

func newTestService(t *testing.T, control *testControl, bootstrapper OCIBootstrapper, source ReconcilerSource) *Service {
	t.Helper()
	if source == nil {
		source = ReconcilerSourceFunc(func(_ context.Context, desired estate.Spec) ([]reconcile.Reconciler, error) {
			declared, err := reconcile.Declared(desired)
			if err != nil {
				return nil, err
			}
			return []reconcile.Reconciler{&testReconciler{state: declared, desired: declared, kinds: resourceKinds(declared)}}, nil
		})
	}
	progress, err := reconcile.NewFileProgressStore(filepath.Join(t.TempDir(), "reconcile-progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journalMu sync.Mutex
	journals := make(map[ControlJournalRequest]*bootstrap.MemoryControlJournal)
	journalFactory := ControlJournalFactoryFunc(func(_ context.Context, request ControlJournalRequest) (bootstrap.ControlJournal, error) {
		journalMu.Lock()
		defer journalMu.Unlock()
		journal := journals[request]
		if journal == nil {
			journal = &bootstrap.MemoryControlJournal{Durable: true}
			journals[request] = journal
		}
		return journal, nil
	})
	service, err := NewService(Dependencies{
		Bootstrapper: bootstrapper,
		BootstrapGateways: BootstrapGatewaySourceFunc(func(context.Context, estate.Region) (provider.BootstrapGateways, error) {
			return provider.BootstrapGateways{}, nil
		}),
		Control: control, ControlJournals: journalFactory,
		Reconcilers: source, Progress: progress,
		Audit: reconcile.NewLogAuditSink(io.Discard), Drift: reconcile.NewLogDriftSink(io.Discard),
	}, Options{ControlRetry: bootstrap.RetryPolicy{MaxAttempts: 1}, AllowDeletes: true})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type testControl struct {
	mu          sync.Mutex
	observation ControlObservation
	calls       []bootstrap.ControlActionKind
}

func newTestControl(state bootstrap.ControlPlaneState) *testControl {
	return &testControl{observation: ControlObservation{State: state, BootstrapAuthorized: state.BootstrapAuthorized}}
}

func (c *testControl) ObserveControl(ctx context.Context) (ControlObservation, error) {
	if err := ctx.Err(); err != nil {
		return ControlObservation{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.observation
	result.Replicas = append([]ControlReplica(nil), result.Replicas...)
	result.Candidates = append([]bootstrap.ControlCandidateObservation(nil), result.Candidates...)
	result.RemoteRegions = append([]string(nil), result.RemoteRegions...)
	result.State.ControlRegions = append([]string(nil), result.State.ControlRegions...)
	result.State.Candidates = append([]bootstrap.CandidateEvidence(nil), result.State.Candidates...)
	return result, nil
}

func (c *testControl) callKinds() []bootstrap.ControlActionKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]bootstrap.ControlActionKind(nil), c.calls...)
}

func (c *testControl) record(request bootstrap.ControlActionRequest) {
	c.calls = append(c.calls, request.Action.Kind)
}

func (c *testControl) StartTemporaryR1(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) FenceTemporaryR1(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	c.observation.State = bootstrap.ControlPlaneState{
		Topology: bootstrap.ControlTopologyTemporaryR1, Phase: bootstrap.ControlPhaseR1, Epoch: 1,
		BootstrapAuthorized: true, MemberHosts: 2, ControlRegions: []string{"gru"},
	}
	c.observation.BootstrapAuthorized = true
	c.observation.QuorumAvailable = true
	c.observation.Replicas = []ControlReplica{{Region: "gru", MemberID: "ocid1.instance.oc1.gru.member1", Role: "temporary-r1", Epoch: 1, Active: true}}
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) StartCandidate(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) SyncCandidate(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) VerifyCandidate(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.CandidateEvidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return bootstrap.CandidateEvidence{Region: request.Action.Region, IdentityDigest: digest, StorageDigest: digest, HealthDigest: digest, CaughtUp: true, IdentityReady: true, StorageReady: true, HealthReady: true}, nil
}

func (c *testControl) PromoteGlobalR3(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) VerifyGlobalR3(_ context.Context, request bootstrap.ControlActionRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return nil
}

func (c *testControl) RevokeBootstrapAuthority(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) RemoteManageRegion(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	c.observation.RemoteRegions = append(c.observation.RemoteRegions, request.Action.Region)
	if c.observation.RemoteHealth == nil {
		c.observation.RemoteHealth = make(map[string]bool)
	}
	c.observation.RemoteHealth[request.Action.Region] = true
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

func (c *testControl) StartRegionalR3(_ context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(request)
	return bootstrap.ControlReceipt{ID: request.Action.IdempotencyKey}, nil
}

type testReconciler struct {
	mu      sync.Mutex
	state   reconcile.State
	desired reconcile.State
	kinds   []estate.ResourceKind
	applies int
}

func (r *testReconciler) Kinds() []estate.ResourceKind {
	return append([]estate.ResourceKind(nil), r.kinds...)
}

func (r *testReconciler) Observe(context.Context) (reconcile.State, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return reconcile.State{Resources: append([]reconcile.Resource(nil), r.state.Resources...)}, nil
}

func (r *testReconciler) Apply(context.Context, reconcile.Plan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applies++
	r.state = reconcile.State{Resources: append([]reconcile.Resource(nil), r.desired.Resources...)}
	return nil
}

func (r *testReconciler) applyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applies
}

func resourceKinds(state reconcile.State) []estate.ResourceKind {
	seen := make(map[estate.ResourceKind]bool)
	var kinds []estate.ResourceKind
	for _, resource := range state.Resources {
		if !seen[resource.Ref.Kind] {
			seen[resource.Ref.Kind] = true
			kinds = append(kinds, resource.Ref.Kind)
		}
	}
	return kinds
}

func fourthRegionEstate(t *testing.T) estate.Spec {
	t.Helper()
	desired := estate.Default()
	region := desired.Regions[2]
	region.Code = "ord"
	region.OCIName = "us-ashburn-1"
	region.Members.ControlReplicas = 0
	region.Network.Subnets = append([]estate.Subnet(nil), region.Network.Subnets...)
	for index := range region.Network.Subnets {
		region.Network.Subnets[index].RegionCode = region.Code
	}
	desired.Regions = append(desired.Regions, region)
	if err := desired.Validate(); err != nil {
		t.Fatalf("fourth Region estate: %v", err)
	}
	return desired
}
