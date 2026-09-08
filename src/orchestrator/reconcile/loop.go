package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// Desired optionally refreshes the authoritative declaration before each
	// pass. It is used by GRU-owned projections such as autoscale targets.
	Desired func(context.Context) (estate.Spec, error)
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
	// RetryMaxAttempts bounds provider retries. Zero means one attempt. The
	// backoff is exponential and always interruptible by ctx.
	RetryMaxAttempts    int
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
	// MaxAttempts and backoff aliases are retained for callers that configure
	// a generic retry policy.
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	// Progress durably records provider mutation outcomes. Nil uses an
	// in-memory store, while production wiring should provide a durable store.
	Progress ProgressStore
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
		if provider == nil {
			return nil, errors.New("reconcile: nil provider")
		}
		name := fmt.Sprintf("%T", provider)
		seen := make(map[estate.ResourceKind]struct{})
		for _, kind := range provider.Kinds() {
			if kind == "" {
				return nil, fmt.Errorf("reconcile: provider %s owns an empty resource kind", name)
			}
			if _, exists := seen[kind]; exists {
				return nil, fmt.Errorf("reconcile: provider %s lists resource kind %s more than once", name, kind)
			}
			seen[kind] = struct{}{}
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
	if config.Progress == nil {
		config.Progress = NewMemoryProgressStore()
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
	if l.config.Desired != nil {
		spec, err := l.config.Desired(ctx)
		if err != nil {
			l.finishPass(start, Plan{}, err)
			return Plan{}, err
		}
		declared, err := Declared(spec)
		if err != nil {
			l.finishPass(start, Plan{}, err)
			return Plan{}, err
		}
		l.declared = declared
	}
	plan, planErr := l.observeAndPlan(ctx)
	if plan.Empty() {
		// Nothing to apply: either converged, or no usable observation to
		// repair from. Partial observation failures still surface.
		l.finishPass(start, plan, planErr)
		return plan, planErr
	}
	driftErr := l.config.Drift.PublishDrift(ctx, driftEvents(l.now().UTC().Format(time.RFC3339Nano), plan))
	var applyErr error
	var unsafe *IndeterminateError
	if errors.As(planErr, &unsafe) {
		applyErr = errors.New("reconcile: apply withheld because provider state is indeterminate")
	} else {
		applyErr = l.apply(ctx, plan)
	}
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
		// Destructive actions require a proof from the observation and a
		// provider-side authorization check immediately before mutation.
		var safe Plan
		for _, action := range owned.Actions {
			if action.Kind != ActionDelete {
				safe.Actions = append(safe.Actions, action)
				continue
			}
			if !action.Ownership.validForDelete() {
				_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: action.Kind, Result: "skipped", Detail: "ownership or deletion authority is unproven"})
				continue
			}
			if authorizer, ok := provider.(DeleteAuthorizer); ok {
				if err := authorizer.AuthorizeDelete(ctx, action); err != nil {
					_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: action.Kind, Result: "skipped", Detail: "delete authorization failed: " + err.Error()})
					failures = append(failures, fmt.Errorf("authorize delete %s: %w", RefKey(action.Ref), err))
					continue
				}
			} else {
				_ = l.config.Audit.Append(ctx, AuditEntry{At: at, Ref: action.Ref, Action: action.Kind, Result: "skipped", Detail: "provider has no delete authorization"})
				continue
			}
			safe.Actions = append(safe.Actions, action)
		}
		owned = safe
		if owned.Empty() {
			continue
		}
		if l.limiter != nil {
			if err := l.limiter.Wait(ctx); err != nil {
				failures = append(failures, fmt.Errorf("rate limit: %w", err))
				break
			}
		}
		err := l.applyWithRetry(ctx, provider, owned)
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

func (l *Loop) applyWithRetry(ctx context.Context, provider Reconciler, plan Plan) error {
	attempts := l.config.RetryMaxAttempts
	if attempts == 0 {
		attempts = l.config.MaxAttempts
	}
	if attempts <= 0 {
		attempts = 1
	}
	initial := l.config.RetryInitialBackoff
	if initial == 0 {
		initial = l.config.InitialBackoff
	}
	if initial <= 0 {
		initial = 100 * time.Millisecond
	}
	maxDelay := l.config.RetryMaxBackoff
	if maxDelay == 0 {
		maxDelay = l.config.MaxBackoff
	}
	if maxDelay <= 0 {
		maxDelay = 5 * time.Second
	}
	key := planOperationKey(plan)
	for _, action := range plan.Actions {
		progressKey := OperationKey(action)
		if previous, ok, err := l.config.Progress.Load(ctx, progressKey); err != nil {
			return err
		} else if ok && (previous.Outcome == "unknown" || previous.Outcome == "pending") {
			return &UnknownOutcomeError{Err: fmt.Errorf("operation %s is unresolved with outcome %q", progressKey, previous.Outcome)}
		}
		if err := l.config.Progress.Save(ctx, Progress{Key: progressKey, Action: action.Kind, Ref: RefKey(action.Ref), Attempt: 1, Outcome: "pending", UpdatedAt: l.now().UTC()}); err != nil {
			return err
		}
	}
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			// The admission record was written before this check. A cancellation
			// before dispatch therefore has to release that admission so a later
			// pass can retry the operation; leaving it pending would permanently
			// treat a mutation that never ran as unresolved.
			if persistErr := l.recordProgressOutcome(ctx, plan, attempt, "failed", err); persistErr != nil {
				return persistErr
			}
			return err
		}
		if keyed, ok := provider.(ApplyWithKey); ok {
			last = keyed.ApplyWithKey(ctx, key, plan)
		} else {
			last = provider.Apply(ctx, plan)
		}
		if last == nil {
			for _, action := range plan.Actions {
				if err := l.saveProgress(ctx, Progress{Key: OperationKey(action), Action: action.Kind, Ref: RefKey(action.Ref), Attempt: attempt, Outcome: "applied", UpdatedAt: l.now().UTC()}); err != nil {
					// The provider returned success, but the durable outcome could
					// not be recorded. Treat it as unknown: a later process must
					// not replay a potentially destructive mutation.
					return &UnknownOutcomeError{Err: fmt.Errorf("persist applied outcome for %s: %w", OperationKey(action), err)}
				}
			}
			return nil
		}
		// A cancellation returned by an in-flight provider call has the same
		// ambiguity as a lost response: the request may already have committed.
		// Preserve that fact durably instead of allowing a destructive replay.
		unknown := IsUnknownOutcome(last) || errors.Is(last, context.Canceled) || errors.Is(last, context.DeadlineExceeded)
		outcome := "failed"
		if unknown {
			outcome = "unknown"
		}
		if err := l.recordProgressOutcome(ctx, plan, attempt, outcome, last); err != nil {
			return err
		}
		if unknown || errors.Is(last, context.Canceled) || errors.Is(last, context.DeadlineExceeded) {
			return last
		}
		if classified, ok := last.(RetryableError); ok && !classified.Retryable() {
			return last
		}
		if attempt == attempts {
			return last
		}
		delay := initial
		for n := 1; n < attempt; n++ {
			if delay >= maxDelay/2 {
				delay = maxDelay
				break
			}
			delay *= 2
		}
		if delay > maxDelay {
			delay = maxDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

// saveProgress persists terminal state even after caller cancellation. The
// provider call may have completed after the caller detached, and losing its
// durable outcome would leave a permanent pending admission token.
func (l *Loop) saveProgress(ctx context.Context, progress Progress) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		ctx = context.WithoutCancel(ctx)
	}
	return l.config.Progress.Save(ctx, progress)
}

func (l *Loop) recordProgressOutcome(ctx context.Context, plan Plan, attempt int, outcome string, cause error) error {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	for _, action := range plan.Actions {
		if err := l.saveProgress(ctx, Progress{Key: OperationKey(action), Action: action.Kind, Ref: RefKey(action.Ref), Attempt: attempt, Outcome: outcome, Detail: detail, UpdatedAt: l.now().UTC()}); err != nil {
			// Even a provider error may follow a partial mutation. Losing
			// its durable progress record therefore has the same safety
			// posture as an indeterminate provider response.
			return &UnknownOutcomeError{Err: fmt.Errorf("persist %s outcome for %s: %w", outcome, OperationKey(action), err)}
		}
	}
	return nil
}

func planOperationKey(plan Plan) string {
	var key string
	for _, action := range plan.Actions {
		key += OperationKey(action) + ";"
	}
	hash := sha256.Sum256([]byte(key))
	return "reconcile-plan-" + hex.EncodeToString(hash[:16])
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
