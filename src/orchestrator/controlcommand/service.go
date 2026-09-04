// Package controlcommand composes the production bootstrap, Region, control,
// and reconciliation paths without depending on the orchestrator command.
package controlcommand

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

var (
	ErrInvalidConfiguration = errors.New("controlcommand: invalid service configuration")
	ErrInvalidRequest       = errors.New("controlcommand: invalid request")
	ErrInvalidObservation   = errors.New("controlcommand: invalid control observation")
)

// OCIBootstrapper is the exact typed OCI bootstrap entry point. The
// production constructor always installs provider.RunOCIBootstrap.
type OCIBootstrapper func(context.Context, provider.BootstrapRequest, provider.BootstrapGateways, io.Writer) error

// BootstrapGatewaySource resolves the typed gateways for one declared OCI
// Region. Local qualification supplies HTTP-backed gateways here.
type BootstrapGatewaySource interface {
	BootstrapGateways(context.Context, estate.Region) (provider.BootstrapGateways, error)
}

type BootstrapGatewaySourceFunc func(context.Context, estate.Region) (provider.BootstrapGateways, error)

func (f BootstrapGatewaySourceFunc) BootstrapGateways(ctx context.Context, region estate.Region) (provider.BootstrapGateways, error) {
	if f == nil {
		return provider.BootstrapGateways{}, ErrInvalidConfiguration
	}
	return f(ctx, region)
}

type ControlReplica = bootstrap.ControlReplica
type ControlObservation = bootstrap.ControlObservation

// ControlProvider is the exact production mutation and observation boundary.
type ControlProvider interface {
	bootstrap.ControlPlaneProvider
	ObserveControl(context.Context) (bootstrap.ControlObservation, error)
}

// ControlJournalRequest gives a journal factory a stable, non-secret scope.
// A factory must return the same durable journal when the request repeats.
type ControlJournalRequest struct {
	Operation bootstrap.ControlOperation
	Region    string
	FromEpoch uint64
}

type ControlJournalFactory interface {
	ControlJournal(context.Context, ControlJournalRequest) (bootstrap.ControlJournal, error)
}

type ControlJournalFactoryFunc func(context.Context, ControlJournalRequest) (bootstrap.ControlJournal, error)

func (f ControlJournalFactoryFunc) ControlJournal(ctx context.Context, request ControlJournalRequest) (bootstrap.ControlJournal, error) {
	if f == nil {
		return nil, ErrInvalidConfiguration
	}
	return f(ctx, request)
}

// ReconcilerSource returns the exact provider controllers for the desired
// estate. A source may construct Region-scoped OCI controllers and the one
// Cloudflare controller against production or bounded local transports.
type ReconcilerSource interface {
	Reconcilers(context.Context, estate.Spec) ([]reconcile.Reconciler, error)
}

type ReconcilerSourceFunc func(context.Context, estate.Spec) ([]reconcile.Reconciler, error)

func (f ReconcilerSourceFunc) Reconcilers(ctx context.Context, desired estate.Spec) ([]reconcile.Reconciler, error) {
	if f == nil {
		return nil, ErrInvalidConfiguration
	}
	return f(ctx, desired)
}

// Dependencies are all side-effecting ports used by Service. No dependency
// is resolved from process globals or environment variables.
type Dependencies struct {
	Bootstrapper      OCIBootstrapper
	BootstrapGateways BootstrapGatewaySource
	Control           ControlProvider
	ControlJournals   ControlJournalFactory
	Reconcilers       ReconcilerSource
	Progress          reconcile.ProgressStore
	Audit             reconcile.AuditSink
	Drift             reconcile.DriftSink
	BootstrapProgress io.Writer
}

// Options contains bounded policy rather than provider dependencies.
type Options struct {
	ControlRetry            bootstrap.RetryPolicy
	AllowDeletes            bool
	ReconcileRate           float64
	ReconcileBurst          int
	ReconcileRetryAttempts  int
	ReconcileInitialBackoff time.Duration
	ReconcileMaxBackoff     time.Duration
}

// ProductionOptions returns the command's canonical mutation policy.
func ProductionOptions() Options {
	return Options{
		ControlRetry: bootstrap.RetryPolicy{
			MaxAttempts: 8,
			Backoff: func(ctx context.Context, _ int) error {
				timer := time.NewTimer(time.Second)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			},
		},
		AllowDeletes: true,
	}
}

// Service serializes provider mutations while allowing callers to use one
// instance throughout the bootstrap-to-R3 journey.
type Service struct {
	dependencies Dependencies
	options      Options
	operation    chan struct{}
}

// NewService builds an explicitly configured service. NewProductionService
// should be used by the binary and VM qualification.
func NewService(dependencies Dependencies, options Options) (*Service, error) {
	if dependencies.Bootstrapper == nil || dependencies.BootstrapGateways == nil ||
		dependencies.Control == nil || dependencies.ControlJournals == nil ||
		dependencies.Reconcilers == nil || dependencies.Progress == nil ||
		dependencies.Audit == nil || dependencies.Drift == nil {
		return nil, ErrInvalidConfiguration
	}
	if err := options.ControlRetry.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	if options.ReconcileRate < 0 || options.ReconcileBurst < 0 ||
		options.ReconcileRetryAttempts < 0 || options.ReconcileRetryAttempts > 16 ||
		options.ReconcileInitialBackoff < 0 || options.ReconcileMaxBackoff < 0 {
		return nil, ErrInvalidConfiguration
	}
	if dependencies.BootstrapProgress == nil {
		dependencies.BootstrapProgress = io.Discard
	}
	return &Service{dependencies: dependencies, options: options, operation: make(chan struct{}, 1)}, nil
}

// NewProductionService fixes the production OCI implementation and canonical
// retry/delete policy. Endpoints still come from the explicit typed gateways.
func NewProductionService(dependencies Dependencies) (*Service, error) {
	dependencies.Bootstrapper = provider.RunOCIBootstrap
	return NewService(dependencies, ProductionOptions())
}

type BootstrapRequest struct {
	Desired  estate.Spec
	Provider provider.BootstrapRequest
}

type AddRegionRequest struct {
	Desired  estate.Spec
	Region   string
	Provider provider.BootstrapRequest
}

type RemoteRegionRequest struct {
	Desired estate.Spec
	Region  string
}

type ControlResult struct {
	Execution   bootstrap.ControlExecutionResult
	Observation ControlObservation
}

type RemoteRegionResult struct {
	Observation                  ControlObservation
	RemoteManaged                bool
	HasGlobalReplica             bool
	RegionalR3BelowFloorRejected bool
}

type ReconcileResult struct {
	Applied   reconcile.Plan
	Observed  reconcile.State
	Remaining reconcile.Plan
	Status    reconcile.Status
	Converged bool
}

// Bootstrap converges the home Region with the production OCI reconcilers,
// then executes the fenced empty-to-R1 control transition.
func (s *Service) Bootstrap(ctx context.Context, request BootstrapRequest) (ControlResult, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return ControlResult{}, err
	}
	defer release()

	region, err := homeRegion(request.Desired)
	if err != nil {
		return ControlResult{}, err
	}
	providerRequest := request.Provider
	providerRequest.Region = region
	if err := s.bootstrapRegion(ctx, region, providerRequest); err != nil {
		return ControlResult{}, err
	}
	before, err := s.observeControl(ctx, request.Desired)
	if err != nil {
		return ControlResult{}, err
	}
	if before.State.AlreadyBootstrapped() {
		return ControlResult{Observation: before}, nil
	}
	execution, err := s.executeControl(ctx, before.State, bootstrap.ControlTransitionRequest{
		Operation:   bootstrap.ControlOperationBootstrap,
		Region:      region.Code,
		MemberHosts: int(region.Members.Count),
	})
	if err != nil {
		return ControlResult{}, err
	}
	after, err := s.observeControl(ctx, request.Desired)
	if err != nil {
		return ControlResult{Execution: execution}, err
	}
	if after.State.Topology != bootstrap.ControlTopologyTemporaryR1 ||
		after.State.Phase != bootstrap.ControlPhaseR1 || after.State.Epoch != execution.State.Epoch ||
		!after.BootstrapAuthorized {
		return ControlResult{Execution: execution, Observation: after}, ErrInvalidObservation
	}
	return ControlResult{Execution: execution, Observation: after}, nil
}

// AddRegion converges one declared OCI Region and applies its typed control
// transition. Candidate evidence is observed by the ControlPlaneProvider.
func (s *Service) AddRegion(ctx context.Context, request AddRegionRequest) (ControlResult, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return ControlResult{}, err
	}
	defer release()

	region, err := declaredRegion(request.Desired, request.Region)
	if err != nil {
		return ControlResult{}, err
	}
	if err := admitRegion(request.Desired, region); err != nil {
		return ControlResult{}, err
	}
	providerRequest := request.Provider
	providerRequest.Region = region
	if err := s.bootstrapRegion(ctx, region, providerRequest); err != nil {
		return ControlResult{}, err
	}
	before, err := s.observeControl(ctx, request.Desired)
	if err != nil {
		return ControlResult{}, err
	}
	transition := bootstrap.ControlTransitionRequest{
		Operation:       bootstrap.ControlOperationAddRegion,
		Region:          region.Code,
		MemberHosts:     int(region.Members.Count),
		EligibleHosts:   int(region.Members.Count),
		RegionalControl: region.Members.ControlReplicas > 0 && !globalControlRegion(request.Desired, region.Code),
	}
	execution, err := s.executeControl(ctx, before.State, transition)
	if err != nil {
		return ControlResult{}, err
	}
	after, err := s.observeControl(ctx, request.Desired)
	if err != nil {
		return ControlResult{Execution: execution}, err
	}
	if globalControlRegion(request.Desired, region.Code) {
		if after.State.Epoch < before.State.Epoch || after.State.Epoch != execution.State.Epoch {
			return ControlResult{Execution: execution, Observation: after}, ErrInvalidObservation
		}
	} else if after.State.Topology != bootstrap.ControlTopologyGlobalR3 || after.State.Epoch != before.State.Epoch {
		return ControlResult{Execution: execution, Observation: after}, ErrInvalidObservation
	}
	return ControlResult{Execution: execution, Observation: after}, nil
}

// ValidateRemoteRegion observes a fourth-or-later two-host Region through the
// production control endpoint. It does not mutate provider state.
func (s *Service) ValidateRemoteRegion(ctx context.Context, request RemoteRegionRequest) (RemoteRegionResult, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return RemoteRegionResult{}, err
	}
	defer release()

	region, err := declaredRegion(request.Desired, request.Region)
	if err != nil {
		return RemoteRegionResult{}, err
	}
	if err := admitRegion(request.Desired, region); err != nil {
		return RemoteRegionResult{}, err
	}
	if globalControlRegion(request.Desired, region.Code) || region.Members.ControlReplicas != 0 {
		return RemoteRegionResult{}, ErrInvalidRequest
	}
	observation, err := s.observeControl(ctx, request.Desired)
	if err != nil {
		return RemoteRegionResult{}, err
	}
	if observation.State.Topology != bootstrap.ControlTopologyGlobalR3 || observation.State.Phase != bootstrap.ControlPhaseR3 {
		return RemoteRegionResult{Observation: observation}, ErrInvalidObservation
	}
	remoteManaged := contains(observation.RemoteRegions, region.Code)
	hasReplica := false
	for _, replica := range observation.Replicas {
		if replica.Region == region.Code {
			hasReplica = true
			break
		}
	}
	_, floorErr := bootstrap.PlanControlTransition(observation.State, bootstrap.ControlTransitionRequest{
		Operation:       bootstrap.ControlOperationAddRegion,
		Region:          region.Code,
		MemberHosts:     int(region.Members.Count),
		EligibleHosts:   int(region.Members.Count),
		RegionalControl: true,
	})
	floorRejected := errors.Is(floorErr, bootstrap.ErrControlRegionalMembersFloor)
	result := RemoteRegionResult{
		Observation: observation, RemoteManaged: remoteManaged, HasGlobalReplica: hasReplica,
		RegionalR3BelowFloorRejected: floorRejected,
	}
	if !remoteManaged || hasReplica || region.Members.Count < provider.PlacementMinimumMemberHosts ||
		(region.Members.Count < 3 && !floorRejected) {
		return result, ErrInvalidObservation
	}
	return result, nil
}

// Reconcile runs one production observe-plan-apply pass, then returns a fresh
// provider observation and any remaining drift.
func (s *Service) Reconcile(ctx context.Context, desired estate.Spec) (ReconcileResult, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	defer release()
	if err := desired.Validate(); err != nil {
		return ReconcileResult{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	controllers, err := s.dependencies.Reconcilers.Reconcilers(ctx, desired)
	if err != nil {
		return ReconcileResult{}, err
	}
	if len(controllers) == 0 {
		return ReconcileResult{}, ErrInvalidConfiguration
	}
	loop, err := reconcile.NewLoop(reconcile.LoopConfig{
		Spec:                desired,
		Providers:           append([]reconcile.Reconciler(nil), controllers...),
		Interval:            time.Minute,
		AllowDeletes:        s.options.AllowDeletes,
		Rate:                s.options.ReconcileRate,
		Burst:               s.options.ReconcileBurst,
		RetryMaxAttempts:    s.options.ReconcileRetryAttempts,
		RetryInitialBackoff: s.options.ReconcileInitialBackoff,
		RetryMaxBackoff:     s.options.ReconcileMaxBackoff,
		Progress:            s.dependencies.Progress,
		Audit:               s.dependencies.Audit,
		Drift:               s.dependencies.Drift,
	})
	if err != nil {
		return ReconcileResult{}, err
	}
	applied, passErr := loop.Pass(ctx)
	observed, kinds, observeErr := observeReconcilers(ctx, controllers)
	declared, declaredErr := reconcile.Declared(desired)
	remaining, diffErr := reconcile.Diff(declared, observed, kinds...)
	result := ReconcileResult{
		Applied: applied, Observed: observed, Remaining: remaining,
		Status: loop.Status(), Converged: remaining.Empty() && passErr == nil && observeErr == nil && diffErr == nil,
	}
	return result, errors.Join(passErr, observeErr, declaredErr, diffErr)
}

// ObserveControl returns a detached, validated control observation.
func (s *Service) ObserveControl(ctx context.Context, desired estate.Spec) (ControlObservation, error) {
	release, err := s.acquire(ctx)
	if err != nil {
		return ControlObservation{}, err
	}
	defer release()
	return s.observeControl(ctx, desired)
}

func (s *Service) bootstrapRegion(ctx context.Context, region estate.Region, request provider.BootstrapRequest) error {
	gateways, err := s.dependencies.BootstrapGateways.BootstrapGateways(ctx, region)
	if err != nil {
		return err
	}
	return s.dependencies.Bootstrapper(ctx, request, gateways, s.dependencies.BootstrapProgress)
}

func (s *Service) executeControl(ctx context.Context, state bootstrap.ControlPlaneState, request bootstrap.ControlTransitionRequest) (bootstrap.ControlExecutionResult, error) {
	journal, err := s.dependencies.ControlJournals.ControlJournal(ctx, ControlJournalRequest{
		Operation: request.Operation, Region: request.Region, FromEpoch: state.Epoch,
	})
	if err != nil {
		return bootstrap.ControlExecutionResult{}, err
	}
	machine, err := bootstrap.NewControlStateMachine(s.dependencies.Control, journal, s.options.ControlRetry)
	if err != nil {
		return bootstrap.ControlExecutionResult{}, err
	}
	return machine.Execute(ctx, state, request)
}

func (s *Service) observeControl(ctx context.Context, desired estate.Spec) (ControlObservation, error) {
	if err := desired.Validate(); err != nil {
		return ControlObservation{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	observation, err := s.dependencies.Control.ObserveControl(ctx)
	if err != nil {
		return ControlObservation{}, err
	}
	if err := validateControlObservation(desired, observation); err != nil {
		return observation, err
	}
	observation.Replicas = append([]ControlReplica(nil), observation.Replicas...)
	observation.Candidates = append([]bootstrap.ControlCandidateObservation(nil), observation.Candidates...)
	observation.RemoteRegions = append([]string(nil), observation.RemoteRegions...)
	observation.State.ControlRegions = append([]string(nil), observation.State.ControlRegions...)
	observation.State.Candidates = append([]bootstrap.CandidateEvidence(nil), observation.State.Candidates...)
	return observation, nil
}

func validateControlObservation(desired estate.Spec, observation ControlObservation) error {
	if err := observation.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidObservation, err)
	}
	seenReplica := make(map[string]bool, len(observation.Replicas))
	live := 0
	for _, replica := range observation.Replicas {
		if strings.TrimSpace(replica.MemberID) == "" || seenReplica[replica.MemberID] || !declaresRegion(desired, replica.Region) {
			return ErrInvalidObservation
		}
		seenReplica[replica.MemberID] = true
		if replica.Active {
			live++
			if replica.Epoch != observation.State.Epoch {
				return ErrInvalidObservation
			}
		}
	}
	if observation.State.Topology == bootstrap.ControlTopologyGlobalR3 {
		if observation.QuorumAvailable != (live >= 2) {
			return ErrInvalidObservation
		}
	}
	seenRemote := make(map[string]bool, len(observation.RemoteRegions))
	for _, region := range observation.RemoteRegions {
		if seenRemote[region] || !declaresRegion(desired, region) || globalControlRegion(desired, region) {
			return ErrInvalidObservation
		}
		seenRemote[region] = true
	}
	seenCandidate := make(map[string]bool, len(observation.Candidates))
	for _, candidate := range observation.Candidates {
		if seenCandidate[candidate.Evidence.Region] || !declaresRegion(desired, candidate.Evidence.Region) {
			return ErrInvalidObservation
		}
		seenCandidate[candidate.Evidence.Region] = true
	}
	return nil
}

func observeReconcilers(ctx context.Context, controllers []reconcile.Reconciler) (reconcile.State, []estate.ResourceKind, error) {
	var observed reconcile.State
	var kinds []estate.ResourceKind
	for _, controller := range controllers {
		if controller == nil {
			return reconcile.State{}, nil, ErrInvalidConfiguration
		}
		state, err := controller.Observe(ctx)
		if err != nil {
			return observed, kinds, err
		}
		observed.Resources = append(observed.Resources, state.Resources...)
		kinds = append(kinds, controller.Kinds()...)
	}
	return observed, kinds, nil
}

func (s *Service) acquire(ctx context.Context) (func(), error) {
	if s == nil || ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.operation <- struct{}{}:
		return func() { <-s.operation }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func homeRegion(desired estate.Spec) (estate.Region, error) {
	if err := desired.Validate(); err != nil {
		return estate.Region{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return declaredRegion(desired, desired.HomeRegion)
}

func declaredRegion(desired estate.Spec, code string) (estate.Region, error) {
	if err := desired.Validate(); err != nil {
		return estate.Region{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	code = strings.ToLower(strings.TrimSpace(code))
	for _, region := range desired.Regions {
		if region.Code == code {
			return region, nil
		}
	}
	return estate.Region{}, ErrInvalidRequest
}

func admitRegion(desired estate.Spec, region estate.Region) error {
	if region.Members.Count < provider.PlacementMinimumMemberHosts {
		return ErrInvalidRequest
	}
	lock, err := provider.NewPlacementLock([]string{region.Code})
	if err != nil {
		return err
	}
	if err := provider.CheckPlacement(lock, []string{region.Code}, map[string]int{region.Code: int(region.Members.Count)}); err != nil {
		return err
	}
	if globalControlRegion(desired, region.Code) && region.Members.ControlReplicas != 1 {
		return ErrInvalidRequest
	}
	if !globalControlRegion(desired, region.Code) && region.Members.ControlReplicas != 0 {
		return ErrInvalidRequest
	}
	return nil
}

func globalControlRegion(desired estate.Spec, code string) bool {
	return contains(desired.ControlPlane.Regions, code)
}

func declaresRegion(desired estate.Spec, code string) bool {
	for _, region := range desired.Regions {
		if region.Code == code {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	if index < len(values) && values[index] == value {
		return true
	}
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
