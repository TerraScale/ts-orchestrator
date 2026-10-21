package membership

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

// Leadership is the authority view the reconciler is fenced by.
type Leadership interface {
	Current() authority.Snapshot
	Guard(context.Context, uint64) error
}

// PeerSource reads the local embedded server's JetStream metadata view.
type PeerSource interface {
	Meta(context.Context) (Meta, error)
}

// LedgerSource reads every slot's historically verified current HEAD.
type LedgerSource interface {
	Slots(context.Context, []string) (map[string]LedgerSlot, error)
}

// InstanceSource reads the lifecycle state of exact ledger-pinned instances.
// It never discovers an instance by tag or display name.
type InstanceSource interface {
	Lifecycle(context.Context, string) (string, error)
}

// EvidenceSource returns operator-supplied retirement envelopes by slot.
type EvidenceSource interface {
	Evidence(context.Context) (map[string]Evidence, error)
}

// RetirementRequest describes a lost slot whose exact prior instance needs
// offline root-signed retirement evidence before it can be replaced.
type RetirementRequest struct {
	Slot         string
	Attempt      uint64
	InstanceOCID string
	Lifecycle    string
	MetaLeader   string
	OfflineSince time.Time
	ObservedAt   time.Time
	Epoch        uint64
}

// RetirementRequester renders the unsigned retirement candidate an operator
// reviews and signs. It must never sign anything itself.
type RetirementRequester interface {
	RequestRetirement(context.Context, RetirementRequest) error
}

// Replacer executes one replacement. It must be idempotent for a replayed
// action with the same evidence.
type Replacer interface {
	Replace(context.Context, Action) error
}

// ErrReplacerUnavailable is returned by a Replacer on a controller that does
// not hold the founder signer, so the action is held rather than retried hot.
var ErrReplacerUnavailable = errors.New("controller slot replacer is unavailable on this controller")

// Dependencies wires a Reconciler. Replacer may be nil on controllers that
// cannot replace; their decisions are then reported and held.
type Dependencies struct {
	Leadership Leadership
	Peers      PeerSource
	Ledger     LedgerSource
	Instances  InstanceSource
	Evidence   EvidenceSource
	Replacer   Replacer
	Requests   RetirementRequester
	Now        func() time.Time
	Logger     *slog.Logger
}

// Reconciler runs Decide on the authority leader every interval.
type Reconciler struct {
	topology Topology
	deps     Dependencies
	mu       sync.Mutex
	state    State
	epoch    uint64
	statuses []SlotStatus
	// requested remembers, per term, the slot attempts already requested.
	requested map[string]retirementRequestMark
}

func New(topology Topology, deps Dependencies) (*Reconciler, error) {
	if err := topology.Validate(); err != nil {
		return nil, err
	}
	if deps.Leadership == nil || deps.Peers == nil || deps.Ledger == nil || deps.Instances == nil ||
		deps.Evidence == nil {
		return nil, errors.New("membership reconciler dependencies are incomplete")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Reconciler{topology: topology, deps: deps,
		state: State{Slots: make(map[string]SlotStatus)}, requested: make(map[string]retirementRequestMark)}, nil
}

// Run evaluates membership until ctx ends. Errors in one pass are logged and
// retried on the next tick; they never stop the controller.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(DefaultInterval)
	defer ticker.Stop()
	for {
		if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
			r.deps.Logger.Warn("controller membership pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Statuses returns the last evaluated slot statuses, sorted by slot.
func (r *Reconciler) Statuses() []SlotStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.statuses)
}

// Tick is one complete observe, decide and act pass.
func (r *Reconciler) Tick(ctx context.Context) error {
	snapshot := r.deps.Leadership.Current()
	if !snapshot.CanMutate() {
		r.reset(0)
		return nil
	}
	r.mu.Lock()
	if r.epoch != snapshot.Epoch {
		// A new term starts every grace period from its own observations.
		r.state, r.epoch = State{Slots: make(map[string]SlotStatus)}, snapshot.Epoch
		r.requested = make(map[string]retirementRequestMark)
	}
	previous := r.state.clone()
	r.mu.Unlock()
	observation, err := r.observe(ctx)
	if err != nil {
		return err
	}
	next, actions := Decide(r.topology, previous, observation)
	for _, action := range actions {
		next.Slots[action.Slot] = r.execute(ctx, snapshot.Epoch, action, next.Slots[action.Slot], observation.At)
	}
	r.requestRetirements(ctx, snapshot.Epoch, next, observation)
	r.commit(snapshot.Epoch, previous, next)
	return nil
}

// RetirementRequestRefresh re-renders a still-unanswered retirement request.
// The signer refuses a request whose observation is older than its 24-hour
// bound, so an operator who waits must find a fresh request in place.
const RetirementRequestRefresh = 12 * time.Hour

// retirementRequestMark is the slot attempt a request was rendered for and
// the observation time it bound.
type retirementRequestMark struct {
	attempt uint64
	at      time.Time
}

// requestRetirements asks for evidence once per lost slot attempt and term,
// and again whenever the previous request is RetirementRequestRefresh old.
// Decide only waits for evidence after OCI reported the instance TERMINATED.
func (r *Reconciler) requestRetirements(ctx context.Context, epoch uint64, next State, observation Observation) {
	if r.deps.Requests == nil {
		return
	}
	for _, slot := range r.topology.Slots {
		status := next.Slots[slot]
		if status.Phase != PhaseHeld || status.Lifecycle != LifecycleTerminated ||
			!strings.HasPrefix(status.Reason, ReasonAwaitingEvidence) {
			continue
		}
		r.mu.Lock()
		mark := r.requested[slot]
		done := mark.attempt == status.Attempt && observation.At.Sub(mark.at) < RetirementRequestRefresh
		r.mu.Unlock()
		if done {
			continue
		}
		err := r.deps.Requests.RequestRetirement(ctx, RetirementRequest{Slot: slot, Attempt: status.Attempt,
			InstanceOCID: status.InstanceOCID, Lifecycle: status.Lifecycle, MetaLeader: observation.Meta.Leader,
			OfflineSince: status.OfflineSince, ObservedAt: observation.At, Epoch: epoch})
		if err != nil {
			r.deps.Logger.Warn("controller slot retirement request failed", "slot", slot, "error", err)
			continue
		}
		r.deps.Logger.Info("controller slot retirement evidence requested", "slot", slot,
			"attempt", status.Attempt, "instance", status.InstanceOCID)
		r.mu.Lock()
		r.requested[slot] = retirementRequestMark{attempt: status.Attempt, at: observation.At}
		r.mu.Unlock()
	}
}

func (r *Reconciler) observe(ctx context.Context) (Observation, error) {
	meta, err := r.deps.Peers.Meta(ctx)
	if err != nil {
		return Observation{}, fmt.Errorf("read JetStream metadata peers: %w", err)
	}
	ledger, err := r.deps.Ledger.Slots(ctx, r.topology.Slots)
	if err != nil {
		return Observation{}, fmt.Errorf("read controller slot ledger: %w", err)
	}
	lifecycle := make(map[string]string, len(ledger))
	for _, slot := range r.topology.Slots {
		pinned := ledger[slot]
		if slot == r.topology.SelfSlot || pinned.InstanceOCID == "" {
			continue
		}
		state, err := r.deps.Instances.Lifecycle(ctx, pinned.InstanceOCID)
		if err != nil {
			if ctx.Err() != nil {
				return Observation{}, ctx.Err()
			}
			// An unobservable instance is held, never assumed terminated.
			r.deps.Logger.Debug("controller slot instance unobservable", "slot", slot, "error", err)
			continue
		}
		lifecycle[slot] = state
	}
	evidence, err := r.deps.Evidence.Evidence(ctx)
	if err != nil {
		return Observation{}, fmt.Errorf("read retirement evidence: %w", err)
	}
	return Observation{At: r.deps.Now().UTC(), Meta: meta, Ledger: ledger, Lifecycle: lifecycle,
		Evidence: evidence}, nil
}

func (r *Reconciler) execute(ctx context.Context, epoch uint64, action Action, status SlotStatus,
	at time.Time,
) SlotStatus {
	fail := func(err error) SlotStatus {
		status.LastFailure, status.LastError = at, err.Error()
		r.deps.Logger.Warn("controller slot replacement failed", "slot", action.Slot,
			"previous_attempt", action.PreviousAttempt, "error", err)
		return status
	}
	unavailable := func() SlotStatus {
		// Report the decision, but do not hold the single replacement slot.
		status = fail(ErrReplacerUnavailable)
		status.Phase, status.Reason, status.PendingAttempt = PhaseHeld, ErrReplacerUnavailable.Error(), 0
		return status
	}
	if r.deps.Replacer == nil {
		return unavailable()
	}
	if err := r.deps.Leadership.Guard(ctx, epoch); err != nil {
		return fail(fmt.Errorf("authority fence: %w", err))
	}
	r.deps.Logger.Info("replacing controller slot", "slot", action.Slot, "previous_attempt", action.PreviousAttempt,
		"prior_instance", action.PriorInstanceOCID, "reason", action.Reason, "epoch", epoch)
	// The term's fence extends through the whole replacement: the context
	// ends as soon as this controller stops holding the epoch, and the
	// replacer rechecks the guard right before each mutation.
	fencedCtx, stopFence := r.termContext(ctx, epoch)
	defer stopFence()
	action.Epoch = epoch
	action.Fence = func(fenceCtx context.Context) error { return r.deps.Leadership.Guard(fenceCtx, epoch) }
	if err := r.deps.Replacer.Replace(fencedCtx, action); err != nil {
		if errors.Is(err, ErrReplacerUnavailable) {
			return unavailable()
		}
		return fail(err)
	}
	status.LastFailure, status.LastError = timeZero, ""
	r.recordReplacement(ctx, epoch, action)
	return status
}

// termFencePoll is how often a running replacement rechecks that this
// controller still holds the term that decided it.
var termFencePoll = time.Second

// termContext ends when ctx ends or when this controller no longer holds
// epoch with mutation rights.
func (r *Reconciler) termContext(ctx context.Context, epoch uint64) (context.Context, context.CancelFunc) {
	termCtx, cancel := context.WithCancelCause(ctx)
	go func() {
		ticker := time.NewTicker(termFencePoll)
		defer ticker.Stop()
		for {
			select {
			case <-termCtx.Done():
				return
			case <-ticker.C:
				if snapshot := r.deps.Leadership.Current(); !snapshot.CanMutate() || snapshot.Epoch != epoch {
					cancel(errors.New("controller authority term ended during slot replacement"))
					return
				}
			}
		}
	}()
	return termCtx, func() { cancel(context.Canceled) }
}

// recordReplacement journals a replacement the founder accepted. Replace is
// idempotent for a replayed action, so the decision is keyed on the slot and
// prior attempt and recorded once per process; the journal never changes
// the replacement path.
func (r *Reconciler) recordReplacement(ctx context.Context, epoch uint64, action Action) {
	key := fmt.Sprintf("membership:%s:%d", action.Slot, action.PreviousAttempt)
	if decisionlog.Correlated(key) != "" {
		return
	}
	id := decisionlog.Record(ctx, decisionlog.Decision{
		Region:  r.topology.Cell,
		Actor:   decisionlog.Actor{Slice: "membership"},
		Kind:    decisionlog.KindControllerReplaced,
		Subject: decisionlog.Subject{Kind: "member", ID: r.topology.ServerName(action.Slot), Name: action.Slot},
		Summary: fmt.Sprintf("Replacing controller slot %s as attempt %d", action.Slot, action.PreviousAttempt+1),
		Reason:  "The slot was lost and root-signed retirement evidence names its exact prior instance.",
		Rule:    "membership." + action.Reason,
		Signals: []decisionlog.Signal{{Name: "prior_attempt", Value: float64(action.PreviousAttempt)}},
		Status:  decisionlog.StatusInProgress,
		Epoch:   epoch,
		Attrs:   map[string]string{"prior_instance": action.PriorInstanceOCID, "retirement": action.Retirement.Digest},
	})
	decisionlog.Correlate(key, id)
}

func (r *Reconciler) commit(epoch uint64, previous, next State) {
	statuses := make([]SlotStatus, 0, len(next.Slots))
	for _, slot := range r.topology.Slots {
		status := next.Slots[slot]
		statuses = append(statuses, status)
		before, existed := previous.Slots[slot]
		if !existed || before.Phase != status.Phase || before.Reason != status.Reason {
			r.deps.Logger.Info("controller slot membership", "slot", slot, "phase", status.Phase,
				"reason", status.Reason, "attempt", status.Attempt, "online", status.Online,
				"lifecycle", status.Lifecycle)
		}
	}
	slices.SortFunc(statuses, func(a, b SlotStatus) int {
		switch {
		case a.Slot < b.Slot:
			return -1
		case a.Slot > b.Slot:
			return 1
		}
		return 0
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch == epoch {
		r.state, r.statuses = next, statuses
	}
}

func (r *Reconciler) reset(epoch uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state, r.epoch, r.statuses = State{Slots: make(map[string]SlotStatus)}, epoch, nil
	r.requested = make(map[string]retirementRequestMark)
}
