package workload

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/autoscale"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

const DefaultInterval = 10 * time.Second

// HostView is the regional host state the reconciler observes.
type HostView interface {
	ListHosts(context.Context) ([]host.HostStatus, error)
	ListDesired(context.Context, string) ([]host.Desired, error)
}

// DesiredWriter commits one fenced host allocation.
type DesiredWriter interface {
	ApplyDesired(context.Context, host.Desired) (host.Receipt, error)
}

// CapacityRequester is told when a service cannot be placed on current hosts,
// and when it can again. Implementations must not block; they record demand
// for a host-pool scaler.
type CapacityRequester interface {
	RequestCapacity(spec ServiceSpec, request placement.WorkloadRequest)
	CapacitySatisfied(spec ServiceSpec)
}

type Config struct {
	Cell     string
	Specs    []ServiceSpec
	Profiles map[string]placement.Resources
	Hosts    HostView
	Writer   DesiredWriter
	Fencer   authority.Fencer
	// Signals feeds autoscaling; nil disables signal-driven scaling while
	// keeping self-healing and bound enforcement.
	Signals  autoscale.Source
	Capacity CapacityRequester
	Interval time.Duration
	Now      func() time.Time
	Logf     func(string, ...any)
}

// Result is the outcome of one service reconciliation.
type Result struct {
	Role     string
	Replicas int
	Target   int
	Decision *autoscale.Decision
	// Readings are the signal readings the decision used; empty when the
	// service has no scaling policy or was not converged.
	Readings []autoscale.Reading
	Step     Step
	Reason   string
}

// Reconciler is a level-triggered desired-state loop for stateless services.
// It acts only while this controller holds the regional authority lease and
// fences every write with that lease's epoch. Autoscaling history lives in
// memory and is reset conservatively on every authority epoch change.
type Reconciler struct {
	config Config
	specs  []ServiceSpec

	mu      sync.Mutex
	epoch   uint64
	history map[string]autoscale.History
	// goal is the replica count each service converges toward. It is kept
	// while a rollout or scaling step is in flight, so that surge replicas
	// and partly applied releases neither shrink nor inflate the target.
	goal map[string]int
	last map[string]Result
}

// New validates the specs and returns a reconciler for stateless services.
func New(config Config) (*Reconciler, error) {
	if config.Hosts == nil || config.Writer == nil || config.Fencer == nil || !nameRE.MatchString(config.Cell) {
		return nil, errors.New("workload reconciler requires cell, host view, writer and fencer")
	}
	if err := ValidateSpecs(config.Specs); err != nil {
		return nil, err
	}
	specs := slices.Clone(config.Specs)
	slices.SortFunc(specs, func(a, b ServiceSpec) int {
		if a.Role < b.Role {
			return -1
		}
		if a.Role > b.Role {
			return 1
		}
		return 0
	})
	for _, spec := range specs {
		// Only stateless services are reconciled here; stateful specs
		// (TerraBase) are sized by placement and need no generic profile.
		if spec.Kind != KindStateless {
			continue
		}
		if _, err := resourcesFor(spec, config.Profiles); err != nil {
			return nil, err
		}
	}
	if config.Interval <= 0 {
		config.Interval = DefaultInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logf == nil {
		config.Logf = func(string, ...any) {}
	}
	return &Reconciler{config: config, specs: specs, history: make(map[string]autoscale.History),
		goal: make(map[string]int), last: make(map[string]Result)}, nil
}

// Signals returns the configured signal source, nil when none.
func (r *Reconciler) Signals() autoscale.Source {
	if r == nil {
		return nil
	}
	return r.config.Signals
}

// Leading reports whether this member's authority may mutate right now, so
// its reconciliation results and signal source are current.
func (r *Reconciler) Leading() bool {
	return r != nil && r.config.Fencer.Current().CanMutate()
}

// Owns reports whether the role is reconciled here, which changes how the
// delivery planner shapes its releases.
func (r *Reconciler) Owns(role string) (ServiceSpec, bool) {
	if r == nil {
		return ServiceSpec{}, false
	}
	for _, spec := range r.specs {
		if spec.Role == role && spec.Kind == KindStateless {
			return spec, true
		}
	}
	return ServiceSpec{}, false
}

// Last returns the latest result per role for diagnostics.
func (r *Reconciler) Last() map[string]Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.last)
}

// Run reconciles every interval until ctx ends.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.config.Interval)
	defer ticker.Stop()
	for {
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			r.config.Logf("workload reconciliation: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Tick reconciles every stateless service once. Followers do nothing.
func (r *Reconciler) Tick(ctx context.Context) error {
	snapshot := r.config.Fencer.Current()
	if !snapshot.CanMutate() {
		// A former leader's results are no longer current; Last must not
		// keep presenting them to history, insights or the dashboard.
		r.mu.Lock()
		clear(r.last)
		r.mu.Unlock()
		return nil
	}
	now := r.config.Now()
	r.mu.Lock()
	newTerm := r.epoch != snapshot.Epoch
	if newTerm {
		r.epoch = snapshot.Epoch
		// A new term re-derives goals from the observed replica count.
		clear(r.goal)
		for _, spec := range r.specs {
			r.history[spec.Role] = autoscale.Reset(now)
		}
	}
	r.mu.Unlock()
	if source, resettable := r.config.Signals.(interface{ Reset() }); newTerm && resettable {
		// Signals kept from an earlier term (for example by a leader that
		// returns after a short failover) are not this term's observation:
		// the new term must see a fresh window before it scales.
		source.Reset()
	}
	hosts, err := r.config.Hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	desired, err := r.config.Hosts.ListDesired(ctx, "")
	if err != nil {
		return err
	}
	var errs []error
	for _, spec := range r.specs {
		if spec.Kind != KindStateless {
			continue
		}
		// Every service plans against the allocations earlier services
		// committed in this tick, so two services can never both claim
		// the same free capacity on one host.
		result, committed, err := r.reconcile(ctx, spec, snapshot.Epoch, hosts, desired, now)
		desired = withCommitted(desired, committed)
		r.mu.Lock()
		r.last[spec.Role] = result
		r.mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("service %q: %w", spec.Role, err))
		}
	}
	return errors.Join(errs...)
}

// withCommitted returns desired with every committed write replacing the
// record of the same node and role.
func withCommitted(desired, committed []host.Desired) []host.Desired {
	if len(committed) == 0 {
		return desired
	}
	result := slices.Clone(desired)
	for _, write := range committed {
		index := slices.IndexFunc(result, func(existing host.Desired) bool {
			return existing.Node == write.Node && existing.Role == write.Role
		})
		if index < 0 {
			result = append(result, write)
		} else {
			result[index] = write
		}
	}
	return result
}

// reconcile plans and applies one step for spec. It returns the writes that
// committed, even when a later write failed. The remembered goal and the
// autoscaling history advance only after the whole step committed, so a
// failed step is decided and applied again instead of being taken as done.
func (r *Reconciler) reconcile(ctx context.Context, spec ServiceSpec, epoch uint64, hosts []host.HostStatus,
	desired []host.Desired, now time.Time,
) (Result, []host.Desired, error) {
	result := Result{Role: spec.Role}
	resources, err := resourcesFor(spec, r.config.Profiles)
	if err != nil {
		return result, nil, err
	}
	observation, err := Observe(Snapshot{Cell: r.config.Cell, Environment: spec.Environment, Role: spec.Role,
		Hosts: hosts, Desired: desired, Profiles: r.config.Profiles, Now: now})
	if err != nil {
		return result, nil, err
	}
	release, err := CurrentRelease(observation)
	if errors.Is(err, ErrNoRelease) {
		// Nothing to template new replicas from until delivery admits a release;
		// that first release starts from its own replica count.
		r.mu.Lock()
		delete(r.goal, spec.Role)
		r.mu.Unlock()
		result.Reason = "awaiting-release"
		return result, nil, nil
	}
	if err != nil {
		return result, nil, err
	}
	// Replicas counts every active replica, stale ones included. Without a
	// remembered goal, for example on a new authority term, the goal starts
	// from that count so a partly applied release never shrinks the service.
	result.Replicas = len(observation.Active)
	bounds := spec.Replicas.bounds()
	r.mu.Lock()
	goal, known := r.goal[spec.Role]
	history := r.history[spec.Role]
	r.mu.Unlock()
	if !known {
		goal = result.Replicas
	}
	target := min(max(goal, bounds.Min), bounds.Max)
	result.Reason = "self-heal"
	var readings []autoscale.Reading
	if spec.Scaling != nil && release.Converged() {
		readings = autoscale.Collect(ctx, r.config.Signals,
			autoscale.Target{Cell: r.config.Cell, Environment: spec.Environment, Role: spec.Role}, *spec.Scaling, now)
		decision := autoscale.Decide(*spec.Scaling, autoscale.Input{Current: goal, Bounds: bounds,
			Readings: readings, Now: now}, history)
		history = decision.History
		result.Decision = &decision
		result.Readings = readings
		target, result.Reason = decision.To, decision.Reason
	}
	result.Target = target
	step, err := PlanStep(StepInput{Cell: r.config.Cell, Spec: spec, Resources: resources,
		Observation: observation, Release: release, Replicas: target, Epoch: epoch})
	if errors.Is(err, placement.ErrInsufficientCapacity) && r.config.Capacity != nil {
		r.config.Capacity.RequestCapacity(spec, placement.WorkloadRequest{Cell: r.config.Cell, Role: spec.Role,
			Replicas: target, Request: resources, Hosts: observation.Candidates, Previous: release.Current,
			MaxPerFailureDomain: spec.Placement.MaxPerFailureDomain})
	}
	if err == nil && r.config.Capacity != nil {
		r.config.Capacity.CapacitySatisfied(spec)
	}
	if err != nil {
		return result, nil, err
	}
	result.Step = step
	var committed []host.Desired
	for _, write := range step.Writes {
		if err := r.config.Fencer.Guard(ctx, epoch); err != nil {
			return result, committed, err
		}
		if _, err := r.config.Writer.ApplyDesired(ctx, write); err != nil {
			// A concurrent release or authority change wins; the next tick
			// observes it and plans again.
			return result, committed, fmt.Errorf("apply desired %s/%s: %w", write.Node, write.Role, err)
		}
		committed = append(committed, write)
	}
	r.mu.Lock()
	r.goal[spec.Role] = target
	if result.Decision != nil {
		r.history[spec.Role] = history
	}
	r.mu.Unlock()
	if len(step.Writes) > 0 {
		r.config.Logf("workload %s: %d -> %d replicas (%s), generation %d, +%d -%d", spec.Role,
			result.Replicas, target, result.Reason, step.Generation, step.Added, step.Withdrawn)
		if result.Decision != nil {
			recordScale(ctx, r.config.Cell, spec, epoch, *result.Decision, readings, step.Generation)
		}
	}
	return result, committed, nil
}

func resourcesFor(spec ServiceSpec, profiles map[string]placement.Resources) (placement.Resources, error) {
	profile, exists := profiles[spec.Role]
	if !exists {
		return placement.Resources{}, fmt.Errorf("%w: role %q has no workload profile", ErrInvalidSpec, spec.Role)
	}
	if spec.Resources == (placement.Resources{}) {
		return profile, nil
	}
	if spec.Resources != profile {
		return placement.Resources{}, fmt.Errorf("%w: role %q resources differ from its workload profile", ErrInvalidSpec, spec.Role)
	}
	return spec.Resources, nil
}

// ReleaseShape is the generation and replica count a signed release of a
// reconciled role is planned with. The first release starts at the intent's
// replica count; later releases keep the current scale. Both are clamped to
// the spec bounds.
func ReleaseShape(spec ServiceSpec, intentGeneration uint64, intentReplicas int, observation Observation) (uint64, int, error) {
	generation, err := ReleaseGeneration(intentGeneration)
	if err != nil {
		return 0, 0, err
	}
	replicas := intentReplicas
	if len(observation.Active) > 0 {
		replicas = len(observation.Active)
	}
	return generation, min(max(replicas, spec.Replicas.Min), spec.Replicas.Max), nil
}
