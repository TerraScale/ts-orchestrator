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
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/estatepublisher"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reaper"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
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
	EstateClient    any
	EstateSnapshot  estatepublisher.SnapshotSource
	EstateAuthority estatepublisher.Authority
	EstateSpec      estate.Spec

	Rotation keyrotation.Config
	Reaper   reaper.ProductionConfig
	Restore  productionRestoreConfig

	DeliveryStore provider.DeliveryRegionStoreConfig
	Delivery      productionDeliveryConfig
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

type productionRuntime struct {
	delivery       *control.SignedDeliveryRuntimeConfig
	masterDelivery *control.MasterDeliveryRuntimeConfig
	publisher      *estatepublisher.Publisher
	rotation       *security.Coordinator
	reaper         *reaper.Reconciler
	restore        *restoredrill.ProductionComposition
	workers        []*scheduledService
	completion     chan struct{}
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

	signedDelivery, masterDelivery, err := composeProductionDelivery(config.Delivery, spec, mirror)
	if err != nil {
		return nil, err
	}

	publisher, err := newEstatePublisher(config.EstateClient, config.EstateSnapshot, config.EstateAuthority)
	if err != nil {
		return nil, fmt.Errorf("runtime estate publisher: %w", err)
	}
	rotation, err := keyrotation.NewProduction(config.Rotation)
	if err != nil {
		return nil, fmt.Errorf("runtime key rotation: %w", err)
	}
	reaperRuntime, err := reaper.NewProduction(config.Reaper)
	if err != nil {
		return nil, fmt.Errorf("runtime free-tier reaper: %w", err)
	}
	restore, err := restoredrill.NewProductionComposition(config.Restore.resolve(mirror))
	if err != nil {
		return nil, fmt.Errorf("runtime restore drill: %w", err)
	}
	return &productionRuntime{
		delivery:       signedDelivery,
		masterDelivery: masterDelivery,
		publisher:      publisher,
		rotation:       rotation,
		reaper:         reaperRuntime,
		restore:        restore,
	}, nil
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

func (r *productionRuntime) Start(ctx context.Context) error {
	if r == nil || r.publisher == nil || r.rotation == nil || r.reaper == nil || r.restore == nil {
		return errors.New("orchestrator: production runtime is incomplete")
	}
	if ctx == nil {
		return errors.New("orchestrator: production runtime context is required")
	}
	if err := r.publisher.Start(ctx); err != nil {
		return err
	}
	r.workers = []*scheduledService{
		newScheduledService("key rotation", productionRotationInterval, func(runCtx context.Context, _ time.Time) error {
			_, err := r.rotation.Reconcile(runCtx, productionRotationLead)
			return err
		}),
		newScheduledService("free-tier reaper", productionReaperInterval, func(runCtx context.Context, _ time.Time) error {
			_, err := r.reaper.Run(runCtx)
			return err
		}),
		newScheduledService("restore drill", 0, func(runCtx context.Context, _ time.Time) error {
			return r.restore.Drill.Start(runCtx)
		}),
	}
	r.completion = make(chan struct{})
	for _, worker := range r.workers {
		if err := worker.Start(ctx); err != nil {
			_ = r.Close()
			return fmt.Errorf("orchestrator: start %s: %w", worker.name, err)
		}
	}
	go func() {
		select {
		case <-r.publisher.Completion():
		case <-r.workers[0].Completion():
		case <-r.workers[1].Completion():
		case <-r.workers[2].Completion():
		}
		close(r.completion)
	}()
	return nil
}

func (r *productionRuntime) Completion() <-chan struct{} {
	if r == nil || r.completion == nil {
		return nil
	}
	return r.completion
}

// NotifyChange is the immediate publication path used by reconciler apply
// callbacks. Publisher change notifications are coalesced, so bursts of
// provider repair still produce one bounded estate write pass.
func (r *productionRuntime) NotifyChange() {
	if r != nil && r.publisher != nil {
		r.publisher.NotifyChange()
	}
}

func (r *productionRuntime) Close() error {
	if r == nil {
		return nil
	}
	var result error
	for i := len(r.workers) - 1; i >= 0; i-- {
		result = combineErrors(result, r.workers[i].Close())
	}
	if r.publisher != nil {
		result = combineErrors(result, r.publisher.Close())
	}
	return result
}

// scheduledService adapts a periodic operation to the command lifecycle.
// A zero interval means the operation owns its own cadence (the restore
// drill's daily SchedulerPort); all services still share cancellation.
type scheduledService struct {
	name       string
	interval   time.Duration
	run        func(context.Context, time.Time) error
	completion chan struct{}
	cancel     context.CancelFunc
	mu         sync.Mutex
	started    bool
	closed     bool
	runError   error
}

func newScheduledService(name string, interval time.Duration, run func(context.Context, time.Time) error) *scheduledService {
	return &scheduledService{name: name, interval: interval, run: run, completion: make(chan struct{})}
}

func (s *scheduledService) Start(ctx context.Context) error {
	if s == nil || s.run == nil || ctx == nil {
		return errors.New("orchestrator: scheduled service is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.closed {
		return fmt.Errorf("orchestrator: %s cannot be started again", s.name)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.started = true
	go func() {
		defer close(s.completion)
		if s.interval <= 0 {
			err := s.run(loopCtx, time.Time{})
			if err == nil && loopCtx.Err() == nil {
				err = errors.New("service stopped unexpectedly")
			}
			s.recordError(loopCtx, err)
			return
		}
		// Reconcile persisted work on every start. Waiting for the first daily
		// tick leaves interrupted rotations and reaping asleep after a restart.
		if err := loopCtx.Err(); err != nil {
			return
		}
		if err := s.run(loopCtx, time.Now().UTC()); err != nil {
			s.recordError(loopCtx, err)
			return
		}
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case at := <-ticker.C:
				if err := s.run(loopCtx, at); err != nil {
					s.recordError(loopCtx, err)
					return
				}
			}
		}
	}()
	return nil
}

func (s *scheduledService) recordError(ctx context.Context, err error) {
	if err == nil || (ctx.Err() != nil && errors.Is(err, ctx.Err())) {
		return
	}
	s.mu.Lock()
	s.runError = fmt.Errorf("orchestrator: %s failed: %w", s.name, err)
	s.mu.Unlock()
}

func (s *scheduledService) Completion() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.completion
}

func (s *scheduledService) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	started := s.started
	s.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-s.completion:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.runError
	case <-time.After(10 * time.Second):
		return fmt.Errorf("orchestrator: %s shutdown timed out", s.name)
	}
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
