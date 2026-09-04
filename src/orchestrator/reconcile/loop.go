package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// Status is the /healthz-style view of the reconciler: the last pass, the
// current drift count, and the applies in flight. Counters follow the D-72
// cardinality rules: bounded by subsystem, never per resource or database.
type Status struct {
	LastPassAt       string `json:"lastPassAt,omitempty"`
	LastPassDuration string `json:"lastPassDuration,omitempty"`
	LastPassError    string `json:"lastPassError,omitempty"`
	Converged        bool   `json:"converged"`
	Passes           uint64 `json:"passes"`
	DriftCount       int    `json:"driftCount"`
	InFlightApplies  int    `json:"inFlightApplies"`
	TotalApplies     uint64 `json:"totalApplies"`
	TotalDriftEvents uint64 `json:"totalDriftEvents"`
}

// LoopConfig configures one reconcile loop instance.
type LoopConfig struct {
	// Spec is the declared estate. Required.
	Spec estate.Spec
	// Providers own disjoint resource kinds. Required for the running loop;
	// an empty set is only valid for one-shot planning (dry runs).
	Providers []Reconciler
	// Interval between passes. Required for Run.
	Interval time.Duration
	// AllowDeletes gates the delete half of the plan: undeclared resources
	// are always drift, but are only removed when this is true.
	AllowDeletes bool
	// Rate is the sustained apply-call limit across providers; zero means
	// unlimited. Burst defaults to 1.
	Rate  float64
	Burst int
	// Audit receives every transition. Defaults to a discard sink.
	Audit AuditSink
	// Drift receives the drift event stream. Defaults to a discard sink.
	Drift DriftSink
	// Now overrides the clock for tests.
	Now func() time.Time
}

// Loop continuously drives the observed estate to the declared estate:
// observe all providers, diff against the declaration, plan, apply with rate
// limiting, re-observe, and audit every transition.
type Loop struct {
	config   LoopConfig
	declared State
	kinds    []estate.ResourceKind
	limiter  *rate.Limiter

	mu     sync.Mutex
	status Status
}

// NewLoop validates the configuration and prepares the loop. Kind ownership
// must be disjoint: one resource kind has exactly one provider.
func NewLoop(config LoopConfig) (*Loop, error) {
	if err := config.Spec.Validate(); err != nil {
		return nil, fmt.Errorf("reconcile: declared estate is invalid: %w", err)
	}
	declared, err := Declared(config.Spec)
	if err != nil {
		return nil, err
	}
	owner := make(map[estate.ResourceKind]string)
	var kinds []estate.ResourceKind
	for _, provider := range config.Providers {
		name := fmt.Sprintf("%T", provider)
		for _, kind := range provider.Kinds() {
			if previous, exists := owner[kind]; exists {
				return nil, fmt.Errorf("reconcile: resource kind %s is owned by both %s and %s", kind, previous, name)
			}
			owner[kind] = name
			kinds = append(kinds, kind)
		}
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	loop := &Loop{
		config:   config,
		declared: declared,
		kinds:    kinds,
	}
	if config.Rate > 0 {
		burst := config.Burst
		if burst <= 0 {
			burst = 1
		}
		loop.limiter = rate.NewLimiter(rate.Limit(config.Rate), burst)
	}
	if config.Audit == nil {
		config.Audit = discardAuditSink{}
	}
	if config.Drift == nil {
		config.Drift = discardDriftSink{}
	}
	loop.config = config
	return loop, nil
}

// Run passes until the context is cancelled.
func (l *Loop) Run(ctx context.Context) error {
	if l.config.Interval <= 0 {
		return errors.New("reconcile: loop interval must be positive")
	}
	if len(l.config.Providers) == 0 {
		return errors.New("reconcile: the running loop requires at least one provider")
	}
	ticker := time.NewTicker(l.config.Interval)
	defer ticker.Stop()
	for {
		if _, err := l.Pass(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			l.recordPassError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Pass executes one observe → diff → plan → drift → apply pass and returns
// the plan it derived; convergence is confirmed by the next pass's
// observation. A provider whose observation fails is excluded for the pass
// but does not stop the healthy providers from repairing. Apply failures are
// recorded and returned after the pass completes.
func (l *Loop) Pass(ctx context.Context) (Plan, error) {
	start := l.now()
	plan, planErr := l.observeAndPlan(ctx)
	if plan.Empty() {
		// Nothing to apply: either converged, or no usable observation to
		// repair from. Partial observation failures still surface.
		l.finishPass(start, plan, planErr)
		return plan, planErr
	}
	driftErr := l.config.Drift.PublishDrift(ctx, driftEvents(l.now().UTC().Format(time.RFC3339Nano), plan))
	applyErr := l.apply(ctx, plan)
	joined := errors.Join(planErr, driftErr, applyErr)
	l.finishPass(start, plan, joined)
	return plan, joined
}

// observeAndPlan collects every provider observation and derives the plan.
// A provider whose observation fails is excluded from the pass: its kinds are
// neither planned nor applied, so a missing observation never reads as drift
// to create, and one cloud's outage never stops the other's self-healing
// (D-67). The pass fails outright only when nothing could be observed.
func (l *Loop) observeAndPlan(ctx context.Context) (Plan, error) {
	observed := State{}
	var healthy []estate.ResourceKind
	var failures []error
	for _, provider := range l.config.Providers {
		state, err := provider.Observe(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("observe %T: %w", provider, err))
			continue
		}
		observed.Resources = append(observed.Resources, state.Resources...)
		healthy = append(healthy, provider.Kinds()...)
	}
	if len(healthy) == 0 {
		return Plan{}, errors.Join(failures...)
	}
	plan, err := Diff(l.declared, observed, healthy...)
	if err != nil {
		failures = append(failures, err)
	}
	return plan, errors.Join(failures...)
}

// apply submits the plan to its owners, rate-limited, auditing every
// transition. Deletes are submitted only when configured.
func (l *Loop) apply(ctx context.Context, plan Plan) error {
	applicable := plan
	if !l.config.AllowDeletes {
		applicable = Plan{}
		for _, action := range plan.Actions {
			if action.Kind != ActionDelete {
				applicable.Actions = append(applicable.Actions, action)
			}
		}
	}
	at := l.now().UTC().Format(time.RFC3339Nano)
	if !applicable.Empty() {
		for _, action := range applicable.Actions {
			_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: action.Kind, Result: "planned"})
		}
	}
	l.mu.Lock()
	l.status.InFlightApplies++
	l.mu.Unlock()
	var failures []error
	for _, provider := range l.config.Providers {
		owned := applicable.For(provider.Kinds()...)
		if owned.Empty() {
			continue
		}
		if l.limiter != nil {
			if err := l.limiter.Wait(ctx); err != nil {
				failures = append(failures, fmt.Errorf("rate limit: %w", err))
				break
			}
		}
		err := provider.Apply(ctx, owned)
		l.auditApplyResult(ctx, at, owned, err)
		if err != nil {
			failures = append(failures, fmt.Errorf("apply %T: %w", provider, err))
		}
		l.mu.Lock()
		l.status.TotalApplies += uint64(len(owned.Actions))
		l.mu.Unlock()
	}
	if !l.config.AllowDeletes {
		for _, action := range plan.Actions {
			if action.Kind == ActionDelete {
				_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: ActionDelete, Result: "skipped", Detail: "deletes disabled"})
			}
		}
	}
	l.mu.Lock()
	l.status.InFlightApplies--
	l.mu.Unlock()
	return errors.Join(failures...)
}

func (l *Loop) auditApplyResult(ctx context.Context, at string, owned Plan, err error) {
	result := "applied"
	detail := ""
	if err != nil {
		result = "failed"
		detail = err.Error()
	}
	for _, action := range owned.Actions {
		_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: action.Kind, Result: result, Detail: detail})
	}
}

func (l *Loop) recordPassError(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.status.LastPassError = err.Error()
}

func (l *Loop) finishPass(start time.Time, plan Plan, err error) {
	end := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.status.Passes++
	l.status.LastPassAt = end.UTC().Format(time.RFC3339)
	l.status.LastPassDuration = end.Sub(start).String()
	l.status.DriftCount = len(plan.Actions)
	l.status.TotalDriftEvents += uint64(len(plan.Actions))
	l.status.Converged = err == nil && plan.Empty()
	if err != nil {
		l.status.LastPassError = err.Error()
	} else {
		l.status.LastPassError = ""
	}
}

func (l *Loop) now() time.Time {
	if l.config.Now != nil {
		return l.config.Now()
	}
	return time.Now()
}

// Status returns the current reconciler status snapshot.
func (l *Loop) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status
}

// StatusHandler serves the reconciler status as JSON, /healthz-style.
func (l *Loop) StatusHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(writer).Encode(l.Status())
	})
}

type discardAuditSink struct{}

func (discardAuditSink) Append(context.Context, AuditEntry) error { return nil }

type discardDriftSink struct{}

func (discardDriftSink) PublishDrift(context.Context, []DriftEvent) error { return nil }
