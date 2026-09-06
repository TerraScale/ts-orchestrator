package main

// This file is the command composition root for the production control
// services.  The domain packages deliberately expose ports rather than
// consulting globals; the command therefore admits one complete adapter
// bundle, starts every service under the process context, and shuts them down
// in reverse dependency order.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"terrascale.tech/orchestrator/src/orchestrator/globalclient"
	"terrascale.tech/orchestrator/src/orchestrator/lifecycle"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/estatepublisher"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentityrotation"
)

const (
	productionRotationInterval = time.Minute
	productionRotationLead     = 15 * time.Minute
	productionReaperInterval   = 24 * time.Hour
)

var (
	ErrProductionCompositionMissing = errors.New("orchestrator: production runtime requires configured estate publisher, key rotation, free-tier reaper, restore drill, and delivery mirror adapters")

	// Admission validates all configuration and credential references without
	// opening clients or listeners. The returned plan opens live stores only
	// after the selected embedded broker is ready. Missing root configuration
	// fails here, before any listener can start.
	admitProductionRuntime = func(context.Context, *control.OrchestratorOptions) (*admittedProductionRuntime, error) {
		return nil, ErrProductionCompositionMissing
	}
)

// admittedProductionRuntime binds validated static input to its live
// constructor. The root resolver must return both together, so run cannot
// accidentally compose live stores before static admission or broker startup.
type admittedProductionRuntime struct {
	construct func(context.Context) (*productionRuntime, error)
}

func (a *admittedProductionRuntime) Construct(ctx context.Context) (*productionRuntime, error) {
	if a == nil || a.construct == nil {
		return nil, errors.New("production runtime admission is incomplete")
	}
	return a.construct(ctx)
}

// productionRuntimeConfig contains all side-effecting production ports. The
// delivery store is composed here, from the same durable provider journal and
// exact per-Region scopes used by the rollout path; callers cannot provide a
// put-only or unscoped mirror.
type productionRuntimeConfig struct {
	Global     *productionGlobalWorkerPlan
	EstateSpec estate.Spec

	DeliveryStore provider.DeliveryRegionStoreConfig
	Delivery      productionDeliveryConfig
	BindDelivery  func(*delivery.ArtifactMirror) (productionDeliveryConfig, error)
	Close         func() error
}

// The production root owns the mirror and estate. Provider composition
// supplies explicit global delegation trust and regional rollout adapters.
// Only the optional GRU master inputs include a registry fetcher.
type productionDeliveryConfig struct {
	Delegation *control.MasterDeliveryAdmissionConfig
	Trust      func() *delivery.TrustSet
	Rollout    delivery.RolloutConfig
	Master     *productionMasterDeliveryConfig
}

// productionMasterDeliveryConfig contains the additional GRU-only inputs. The
// root supplies the same estate mirror, release trust and original-intent trust
// used by regional admission; callers cannot substitute a second artifact path.
type productionMasterDeliveryConfig struct {
	Fetcher        delivery.ArtifactFetcher
	Signer         *security.CommandSignatureSigner
	Regions        map[string]control.RegionalDeliveryRoute
	RequestTimeout time.Duration
}

// The admitted plan validates provider references before listeners, but builds
// clients and lease-specific adapters only inside a proven global session.
type productionGlobalWorkerPlan struct {
	CandidateID string
	Construct   func(context.Context, globalWorkerSession) (productionGlobalWorkerConfig, error)
}
type productionGlobalWorkerConfig struct {
	Edge control.GlobalEdgeDelivery
	// Close releases every client allocated by Construct, including partial
	// results returned with an error. It is required even for an empty bundle.
	Close               func() error
	EstateClient        any
	EstateSnapshot      estatepublisher.SnapshotSource
	Rotation            keyrotation.Config
	Reaper              reaper.ProductionConfig
	Restore             productionRestoreConfig
	Placement           productionPlacementConfig
	PlacementTransition productionPlacementTransitionConfig
	KV                  *cloudflare.KVWriter
	ServiceIdentity     *serviceidentityrotation.Coordinator
	Database            productionDatabaseConfig
	AuthBootstrap       productionAuthBootstrapConfig
}
type productionRuntime struct {
	connection     *globalclient.Plan
	plan           *productionGlobalWorkerPlan
	mirror         *delivery.ArtifactMirror
	supervisor     *leaseOwnedGlobalWorkers
	mu             sync.Mutex
	active         *productionGlobalWorkers
	delivery       *control.SignedDeliveryRuntimeConfig
	masterDelivery *control.MasterDeliveryRuntimeConfig
	release        func() error
	closeOnce      sync.Once
	closeError     error
}

type productionGlobalWorkers struct {
	edge            control.GlobalEdgeDelivery
	check           func(context.Context) error
	release         func() error
	closeOnce       sync.Once
	closeError      error
	finished        sync.Once
	lifetime        context.Context
	publisher       *estatepublisher.Publisher
	rotation        *security.Coordinator
	reaper          *reaper.Reconciler
	restore         *restoredrill.ProductionComposition
	placement       *productionPlacement
	transition      *productionPlacementTransition
	database        *productionDatabase
	authBootstrap   *productionAuthBootstrap
	kv              *cloudflare.KVWriter
	serviceIdentity *serviceidentityrotation.Coordinator
	workers         []*lifecycle.Service
	completion      chan struct{}
}

func newProductionRuntime(config productionRuntimeConfig) (*productionRuntime, error) {
	if config.DeliveryStore.OwnershipCheck == nil {
		return nil, errors.New("runtime delivery mirror: ownership reread callback is required")
	}
	store, err := provider.NewDeliveryRegionStore(config.DeliveryStore)
	if err != nil {
		return nil, fmt.Errorf("runtime delivery mirror: %w", err)
	}
	spec := config.EstateSpec
	if spec.Version == 0 {
		spec = estate.Default()
	}
	mirror, err := delivery.NewArtifactMirror(spec, store)
	if err != nil {
		return nil, fmt.Errorf("runtime artifact mirror: %w", err)
	}

	if config.BindDelivery != nil {
		if config.Delivery.Delegation != nil || config.Delivery.Master != nil || config.Delivery.Trust != nil {
			return nil, errors.New("runtime delivery must have one composition source")
		}
		config.Delivery, err = config.BindDelivery(mirror)
		if err != nil {
			return nil, fmt.Errorf("runtime delivery provider binding: %w", err)
		}
	}
	signedDelivery, masterDelivery, err := composeProductionDelivery(config.Delivery, spec, mirror)
	if err != nil {
		return nil, err
	}

	if config.Delivery.Master != nil && config.Global == nil {
		return nil, errors.New("runtime global worker plan is missing")
	}
	if config.Global != nil && config.Delivery.Master == nil {
		return nil, errors.New("runtime global workers require GRU master configuration")
	}
	if config.Global != nil && (config.Global.Construct == nil || config.Global.CandidateID == "") {
		return nil, errors.New("runtime global worker plan is incomplete")
	}
	runtime := &productionRuntime{delivery: signedDelivery, masterDelivery: masterDelivery, plan: config.Global, mirror: mirror, release: config.Close}
	if masterDelivery != nil {
		masterDelivery.GlobalEdge = productionGlobalEdge{runtime: runtime}
	}
	return runtime, nil
}

func ownedGlobalWorkers(config productionGlobalWorkerConfig) *productionGlobalWorkers {
	return &productionGlobalWorkers{release: config.Close, completion: make(chan struct{})}
}

func newProductionGlobalWorkers(config productionGlobalWorkerConfig, session globalWorkerSession, mirror *delivery.ArtifactMirror) (*productionGlobalWorkers, error) {
	group := ownedGlobalWorkers(config)
	group.edge, group.check = config.Edge, session.CheckEffectAuthority
	if config.Close == nil {
		return group, errors.New("runtime global client cleanup is required")
	}
	if config.Edge == nil {
		return group, errors.New("runtime global edge provider is required")
	}

	epoch := uint64(session.Lease.Epoch)
	check := func(ctx context.Context) (uint64, error) {
		if err := session.CheckEffectAuthority(ctx); err != nil {
			return 0, err
		}
		return epoch, nil
	}
	publisher, err := newEstatePublisher(config.EstateClient, config.EstateSnapshot, estatepublisher.AuthorityFunc{
		GenerationFunc: check,
		FenceFunc: func(ctx context.Context, generation uint64) error {
			if generation != epoch {
				return estatepublisher.ErrFenced
			}
			return session.CheckEffectAuthority(ctx)
		},
	})
	if err != nil {
		return group, fmt.Errorf("runtime estate publisher: %w", err)
	}
	group.publisher = publisher
	config.Rotation.State = &keyrotation.NATSStateStoreConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: epoch, LeaseID: session.Lease.LeaseId}
	rotation, err := keyrotation.NewProduction(config.Rotation)
	if err != nil {
		return group, fmt.Errorf("runtime key rotation: %w", err)
	}
	config.Reaper.Store = &reaper.NATSStateStoreConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: epoch, LeaseID: session.Lease.LeaseId}
	config.Reaper.CheckEffectAuthority = session.CheckEffectAuthority
	reaperRuntime, err := reaper.NewProduction(config.Reaper)
	if err != nil {
		return group, fmt.Errorf("runtime free-tier reaper: %w", err)
	}
	journal, err := restoredrill.NewNATSJournal(restoredrill.NATSJournalConfig{Connection: session.Connection, CandidateID: session.Lease.CandidateId, AuthorityEpoch: epoch, LeaseID: session.Lease.LeaseId})
	if err != nil {
		return group, fmt.Errorf("runtime restore journal: %w", err)
	}
	config.Restore.Journal = journal
	restore, err := restoredrill.NewProductionComposition(config.Restore.resolve(mirror))
	if err != nil {
		return group, fmt.Errorf("runtime restore drill: %w", err)
	}
	placement, err := newProductionPlacement(config.Placement, session)
	if err != nil {
		return group, fmt.Errorf("runtime placement: %w", err)
	}
	group.placement = placement
	config.PlacementTransition.Targets = config.Placement.Targets
	transition, err := newProductionPlacementTransition(config.PlacementTransition, session)
	if err != nil {
		return group, fmt.Errorf("runtime placement transition: %w", err)
	}
	config.Database.ActivatePlacement = transition.Activate
	group.transition = transition
	database, err := newProductionDatabase(config.Database, session, placement)
	if err != nil {
		return group, fmt.Errorf("runtime database: %w", err)
	}
	group.database = database
	if config.KV == nil {
		return group, errors.New("runtime global KV publisher is required")
	}
	group.kv = config.KV
	if config.ServiceIdentity == nil {
		return group, errors.New("runtime service identity rotation is required")
	}
	group.serviceIdentity = config.ServiceIdentity
	authBootstrap, err := newProductionAuthBootstrap(config.AuthBootstrap, session)
	if err != nil {
		return group, fmt.Errorf("runtime auth bootstrap: %w", err)
	}
	group.authBootstrap = authBootstrap
	group.rotation, group.reaper, group.restore = rotation, reaperRuntime, restore
	return group, nil
}

func composeProductionDelivery(config productionDeliveryConfig, spec estate.Spec, mirror *delivery.ArtifactMirror) (*control.SignedDeliveryRuntimeConfig, *control.MasterDeliveryRuntimeConfig, error) {
	if err := config.Delegation.Validate(); err != nil {
		return nil, nil, fmt.Errorf("runtime signed delivery: %w", err)
	}
	delegation := *config.Delegation
	rollout := config.Rollout
	rollout.Spec = spec
	regional := &control.SignedDeliveryRuntimeConfig{Delegation: &delegation, Trust: config.Trust, Mirror: mirror, Rollout: rollout}
	if err := regional.Validate(); err != nil {
		return nil, nil, fmt.Errorf("runtime signed delivery: %w", err)
	}
	if config.Master == nil {
		return regional, nil, nil
	}
	routes := make(map[string]control.RegionalDeliveryRoute, len(config.Master.Regions))
	for cell, route := range config.Master.Regions {
		routes[cell] = route
	}
	master := &control.MasterDeliveryRuntimeConfig{
		Fetcher: config.Master.Fetcher, Trust: config.Trust, Mirror: mirror,
		Signer: config.Master.Signer, IntentVerifier: delegation.IntentVerifier,
		Regions: routes, RequestTimeout: config.Master.RequestTimeout,
	}
	if err := master.Validate(); err != nil {
		return nil, nil, fmt.Errorf("runtime master delivery: %w", err)
	}
	return regional, master, nil
}

// BindGlobalDelivery installs the admitted master adapters into the runtime that
// owns the GRU global connection and authority. Passing nil verifies that a
// regional-only process has no unstarted master configuration.
func (r *productionRuntime) BindGlobalDelivery(config *control.GlobalNatsRuntimeConfiguration) error {
	if r == nil {
		return errors.New("runtime master delivery: production composition is missing")
	}
	if config == nil {
		if r.masterDelivery != nil {
			return errors.New("runtime master delivery: GRU global runtime is required")
		}
		return nil
	}
	if config.Cell != "gru" || config.Authority == nil || config.Authority.Cell != "gru" {
		return errors.New("runtime master delivery: global runtime must belong to GRU")
	}
	if r.plan != nil && !r.connection.Matches(config.Authority) {
		return errors.New("runtime global worker connection differs from static admission")
	}
	if r.plan != nil && r.plan.CandidateID != "global-controller-"+config.Cell+"-"+config.Instance {
		return errors.New("runtime global worker candidate differs from GRU election")
	}
	if r.masterDelivery == nil {
		return errors.New("runtime master delivery: explicit master adapters are required for GRU")
	}
	if config.Delivery != nil || config.DeliveryEnabled {
		return errors.New("runtime master delivery: global delivery was already configured")
	}
	if err := r.masterDelivery.Validate(); err != nil {
		return err
	}
	config.Delivery = r.masterDelivery
	config.DeliveryEnabled = true
	return nil
}

func (r *productionGlobalWorkers) Start(ctx context.Context) error {
	if r == nil || r.publisher == nil || r.rotation == nil || r.reaper == nil || r.restore == nil || r.placement == nil || r.database == nil || r.authBootstrap == nil || r.kv == nil || r.serviceIdentity == nil {
		return errors.New("orchestrator: production runtime is incomplete")
	}
	if ctx == nil {
		return errors.New("orchestrator: production runtime context is required")
	}
	r.lifetime = ctx
	if err := r.publisher.Start(ctx); err != nil {
		return err
	}
	r.workers = []*lifecycle.Service{
		lifecycle.NewScheduledService("key rotation", productionRotationInterval, func(runCtx context.Context, _ time.Time) error {
			_, err := r.rotation.Reconcile(runCtx, productionRotationLead)
			return err
		}),
		lifecycle.NewScheduledService("free-tier reaper", productionReaperInterval, func(runCtx context.Context, _ time.Time) error {
			_, err := r.reaper.Run(runCtx)
			return err
		}),
		lifecycle.NewScheduledService("placement proposals", 5*time.Second, func(runCtx context.Context, _ time.Time) error {
			return r.placement.Reconcile(runCtx)
		}),
		lifecycle.NewScheduledService("auth bootstrap", 5*time.Second, func(runCtx context.Context, _ time.Time) error { return r.authBootstrap.Reconcile(runCtx) }),
		lifecycle.NewScheduledService("database admission", 5*time.Second, func(runCtx context.Context, _ time.Time) error { return r.database.Reconcile(runCtx) }),
		lifecycle.NewScheduledService("restore drill", 0, func(runCtx context.Context, _ time.Time) error {
			return r.restore.Drill.Start(runCtx)
		}),
		lifecycle.NewScheduledService("global edge maps", cloudflare.DefaultKVWriterHealthInterval, func(runCtx context.Context, _ time.Time) error {
			_, err := r.kv.Step(runCtx)
			return err
		}),
		lifecycle.NewScheduledService("service identity rotation", time.Minute, func(runCtx context.Context, _ time.Time) error {
			return r.serviceIdentity.Run(runCtx)
		}),
	}
	if r.completion == nil {
		r.completion = make(chan struct{})
	}
	for _, worker := range r.workers {
		if err := worker.Start(ctx); err != nil {
			return fmt.Errorf("orchestrator: start %s: %w", worker.Name(), err)
		}
	}
	go func() {
		select {
		case <-r.publisher.Completion():
		case <-r.workers[0].Completion():
		case <-r.workers[1].Completion():
		case <-r.workers[2].Completion():
		case <-r.workers[3].Completion():
		case <-r.workers[4].Completion():
		case <-r.workers[5].Completion():
		case <-r.workers[6].Completion():
		case <-r.workers[7].Completion():
		case <-r.database.service.Completion():
		case <-r.database.inventory.Completion():
		}
		r.finished.Do(func() { close(r.completion) })
	}()
	return nil
}

func (r *productionGlobalWorkers) Completion() <-chan struct{} {
	if r == nil || r.completion == nil {
		return nil
	}
	return r.completion
}

// NotifyChange is the immediate publication path used by reconciler apply
// callbacks. Publisher change notifications are coalesced, so bursts of
// provider repair still produce one bounded estate write pass.
func (r *productionGlobalWorkers) NotifyChange() {
	if r != nil && r.publisher != nil {
		r.publisher.NotifyChange()
	}
}

func (r *productionGlobalWorkers) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		var result error
		result = combineErrors(result, r.database.Close())
		for i := len(r.workers) - 1; i >= 0; i-- {
			worker := r.workers[i]
			var err error
			if r.lifetime != nil && r.lifetime.Err() != nil {
				err = worker.Shutdown()
			} else {
				err = worker.Close()
			}
			result = combineErrors(result, err)
		}
		if r.publisher != nil {
			result = combineErrors(result, r.publisher.Close())
		}
		if r.release != nil {
			result = combineErrors(result, r.release())
		}
		if r.completion != nil {
			r.finished.Do(func() { close(r.completion) })
		}
		r.closeError = result
	})
	return r.closeError
}

// Start attaches only the operational workers to the GRU election. Regional
// runtimes have no global plan and continue independently on followers.
// Standalone reconcile cannot assume global authority from process admission.
func (r *productionRuntime) Start(context.Context) error {
	return errors.New("production global workers require the live GRU election")
}
func (r *productionRuntime) StartGlobal(ctx context.Context, global component) error {
	if r == nil {
		return errors.New("production runtime is missing")
	}
	if r.plan == nil {
		if r.masterDelivery != nil {
			return errors.New("global worker plan is missing")
		}
		return nil
	}
	if r.connection == nil {
		return errors.New("global worker connection was not statically admitted")
	}
	source, ok := global.(interface {
		AuthoritySnapshot() control.RegionalAuthoritySnapshot
	})
	if !ok {
		return errors.New("global workers require the live GRU election")
	}
	supervisor, err := startLeaseOwnedGlobalWorkers(ctx, globalWorkerSessionConfig{
		CandidateID: r.plan.CandidateID, Snapshot: source.AuthoritySnapshot, OpenConnection: r.connection.Connect,
		Start: r.constructGlobalWorkers,
	})
	if err != nil {
		return err
	}
	r.supervisor = supervisor
	return nil
}
func (r *productionRuntime) constructGlobalWorkers(ctx context.Context, session globalWorkerSession) (component, error) {
	config, err := r.plan.Construct(ctx, session)
	if err != nil {
		return ownedGlobalWorkers(config), err
	}
	if err := session.CheckEffectAuthority(ctx); err != nil {
		return ownedGlobalWorkers(config), err
	}
	group, err := newProductionGlobalWorkers(config, session, r.mirror)
	if err != nil {
		return group, err
	}
	if err := group.transition.RunBootstrap(ctx); err != nil {
		return group, err
	}
	if err := group.database.Start(ctx, session); err != nil {
		return group, err
	}
	if err := group.Start(ctx); err != nil {
		return group, err
	}
	r.mu.Lock()
	r.active = group
	r.mu.Unlock()
	return group, nil
}
func (r *productionRuntime) Completion() <-chan struct{} {
	if r == nil || r.supervisor == nil {
		return nil
	}
	return r.supervisor.Completion()
}
func (r *productionRuntime) NotifyChange() {
	if r == nil {
		return
	}
	r.mu.Lock()
	group := r.active
	r.mu.Unlock()
	if group != nil {
		group.NotifyChange()
	}
}
func (r *productionRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.supervisor != nil {
			r.closeError = r.supervisor.Close()
		} else if r.active != nil {
			r.closeError = r.active.Close()
		}
		if r.release != nil {
			r.closeError = errors.Join(r.closeError, r.release())
		}
	})
	return r.closeError
}

func isNilProductionValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
