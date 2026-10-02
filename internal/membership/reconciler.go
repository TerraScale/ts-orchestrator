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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
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
	config   Config
	topology Topology
	deps     Dependencies
	mu       sync.Mutex
	state    State
	epoch    uint64
	statuses []SlotStatus
	// requested remembers, per term, the slot attempts already requested.
	requested map[string]uint64
}

func New(config Config, topology Topology, deps Dependencies) (*Reconciler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
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
	return &Reconciler{config: config, topology: topology, deps: deps,
		state: State{Slots: make(map[string]SlotStatus)}, requested: make(map[string]uint64)}, nil
}

// Run evaluates membership until ctx ends. Errors in one pass are logged and
// retried on the next tick; they never stop the controller.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.config.Interval())
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
		r.requested = make(map[string]uint64)
	}
	previous := r.state.clone()
	r.mu.Unlock()
	observation, err := r.observe(ctx)
	if err != nil {
		return err
	}
	next, actions := Decide(r.config, r.topology, previous, observation)
	for _, action := range actions {
		next.Slots[action.Slot] = r.execute(ctx, snapshot.Epoch, action, next.Slots[action.Slot], observation.At)
	}
	r.requestRetirements(ctx, snapshot.Epoch, next, observation)
	r.commit(snapshot.Epoch, previous, next)
	return nil
}

// requestRetirements asks for evidence once per lost slot attempt and term.
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
		done := r.requested[slot] == status.Attempt
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
		r.requested[slot] = status.Attempt
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
	if err := r.deps.Replacer.Replace(ctx, action); err != nil {
		if errors.Is(err, ErrReplacerUnavailable) {
			return unavailable()
		}
		return fail(err)
	}
	status.LastFailure, status.LastError = timeZero, ""
	return status
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
				"lifecycle", status.Lifecycle, "replace_enabled", r.config.Replace)
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
	r.requested = make(map[string]uint64)
}
