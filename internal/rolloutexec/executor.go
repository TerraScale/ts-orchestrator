package rolloutexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

const (
	// DefaultInterval is how often the leader drives the active rollout.
	DefaultInterval = 5 * time.Second
	// DefaultProofFreshness is how recent a unit's proof must be for the
	// unit to count as serving in preflight and peer checks.
	DefaultProofFreshness = 4 * DefaultProofInterval
	// maxRounds bounds how many derive-act-commit rounds one tick runs, so a
	// tick can move a rollout through several immediate transitions.
	maxRounds = 4
)

// ProofSource returns a unit's newest verified health proof. Collector is
// the production source.
type ProofSource interface {
	Latest(unit string) (HealthProof, bool)
}

// issue is the leader-local memory of one step it sent. It is lost on a
// leader change; the successor re-sends the step (agents are idempotent per
// operation) and falls back to the durable phase start for freshness.
type issue struct {
	at       time.Time
	before   HealthProof
	known    bool
	accepted bool
}

// Executor drives the cell's active rollout on the authority leader.
type Executor struct {
	Cell   string
	Store  *rollout.Store
	Fencer authority.Fencer
	Driver Driver
	Proofs ProofSource
	// Gate is checked before preflight and every unit step; nil means none.
	Gate Gate
	// Status receives the derived status after every tick; nil means none.
	Status StatusSink
	// Program lists the rollouts to start, in order, when the cell slot is
	// free; nil starts nothing.
	Program        func(ctx context.Context) (Program, error)
	Interval       time.Duration
	ProofFreshness time.Duration
	Now            func() time.Time

	// The leader-local memory below belongs to one rollout (rolloutID)
	// and is reset when the active rollout changes or ends.
	rolloutID string
	issued    map[string]*issue
	holds     map[string]string
	paged     map[string]bool
	halted    string
}

// forget resets the leader-local memory and binds it to rolloutID.
func (e *Executor) forget(rolloutID string) {
	e.rolloutID = rolloutID
	e.issued, e.holds, e.paged = map[string]*issue{}, map[string]string{}, map[string]bool{}
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Executor) freshness() time.Duration {
	if e.ProofFreshness > 0 {
		return e.ProofFreshness
	}
	return DefaultProofFreshness
}

// Run drives the active rollout until ctx ends. Tick errors are logged and
// retried on the next tick: a rollout only ever waits, its deadlines decide.
func (e *Executor) Run(ctx context.Context) error {
	if e.Store == nil || e.Fencer == nil || e.Driver == nil || e.Proofs == nil {
		return fmt.Errorf("%w: rollout executor needs a store, fencer, driver and proof source", ErrInvalid)
	}
	interval := e.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := e.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("rollout executor tick failed", "component", "rollout", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Tick runs one leader-only pass: adopt the active rollout under the
// current epoch, derive its next actions, perform them, and commit the
// events they produced. A follower forgets its leader-local memory.
func (e *Executor) Tick(ctx context.Context) error {
	snapshot := e.Fencer.Current()
	if !snapshot.CanMutate() {
		e.forget("")
		return nil
	}
	if e.issued == nil {
		e.forget("")
	}
	record, revision, ok, err := e.Store.Active(ctx)
	if err != nil {
		return err
	}
	if !ok {
		e.forget("")
		if err := e.startNext(ctx, snapshot.Epoch); err != nil {
			e.publish(snapshot.Epoch, nil)
			return err
		}
		if record, revision, ok, err = e.Store.Active(ctx); err != nil || !ok {
			e.publish(snapshot.Epoch, nil)
			return err
		}
	}
	if record.RolloutID != e.rolloutID {
		e.forget(record.RolloutID)
	}
	if record.AuthorityEpoch != snapshot.Epoch && !record.Phase.Terminal() {
		id := record.RolloutID
		if record, revision, err = e.Store.Adopt(ctx, id, snapshot.Epoch); err != nil {
			return fmt.Errorf("adopt rollout %s: %w", id, err)
		}
	}
	if record.Phase.Terminal() {
		e.forget(record.RolloutID)
		e.publish(snapshot.Epoch, &record)
		return e.Store.Settle(ctx, record, snapshot.Epoch)
	}
	defer func() { e.publish(snapshot.Epoch, &record) }()
	for range maxRounds {
		before := revision
		if record.Phase == rollout.PhasePending {
			if err := e.apply(ctx, &record, &revision, rollout.Event{Kind: rollout.EventStart, At: e.now()}); err != nil {
				return err
			}
		}
		// Deadlines are committed before any effect is derived: a tick
		// that resumes after a deadline rolls back (or freezes) instead of
		// still sending the expired step.
		if err := e.apply(ctx, &record, &revision, rollout.Event{Kind: rollout.EventTick, At: e.now()}); err != nil {
			return err
		}
		if record.Phase.Terminal() {
			break
		}
		events, err := e.act(ctx, record)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := e.apply(ctx, &record, &revision, event); err != nil {
				return err
			}
		}
		if err := e.apply(ctx, &record, &revision, rollout.Event{Kind: rollout.EventTick, At: e.now()}); err != nil {
			return err
		}
		if revision == before || record.Phase.Terminal() {
			break
		}
	}
	return nil
}

// apply feeds one event to the transition core and commits a changed
// record. An event the core rejects (stale for the current phase, a
// replayed report) is dropped: it was derived from an older record.
func (e *Executor) apply(ctx context.Context, record *rollout.Record, revision *uint64, event rollout.Event) error {
	next, err := rollout.Apply(*record, event)
	if errors.Is(err, rollout.ErrInvalidTransition) || errors.Is(err, rollout.ErrInvalid) || errors.Is(err, rollout.ErrTerminal) {
		slog.Debug("rollout event dropped", "component", "rollout", "rollout", record.RolloutID,
			"event", event.Kind, "unit", event.Unit, "error", err)
		return nil
	}
	if err != nil {
		return err
	}
	if same, err := sameRecord(*record, next); err != nil || same {
		return err
	}
	committed, err := e.Store.Commit(ctx, *revision, next)
	if committed == 0 {
		return fmt.Errorf("commit rollout %s: %w", record.RolloutID, err)
	}
	if err != nil {
		// The record is committed; the cell slot catches up on a later
		// commit or Settle.
		slog.Warn("rollout cell slot update is pending", "component", "rollout", "rollout", record.RolloutID, "error", err)
	}
	*record, *revision = next, committed
	return nil
}

func sameRecord(a, b rollout.Record) (bool, error) {
	left, err := protocol.EncodeJSON(a)
	if err != nil {
		return false, err
	}
	right, err := protocol.EncodeJSON(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(left, right), nil
}

// act performs the effects of a stored record's next actions and returns
// the events they observed.
func (e *Executor) act(ctx context.Context, record rollout.Record) ([]rollout.Event, error) {
	var events []rollout.Event
	// A wave is promoted from stored reports when its last unit reports;
	// while a unit that already reported has lost its fresh proof, no
	// healthy report may complete the wave around it.
	lost := e.waveLostProof(record)
	// A unit that restarted during its soak is reported before any other
	// unit can complete the wave from the restarted unit's stored reports.
	if restart := e.waveRestart(record); restart != nil {
		return []rollout.Event{*restart}, nil
	}
	for _, action := range rollout.NextActions(record) {
		var event *rollout.Event
		var err error
		switch action.Kind {
		case rollout.ActionPreflight:
			event = e.preflight(ctx, record)
		case rollout.ActionPrepare:
			event, err = e.prepare(ctx, record, action)
		case rollout.ActionAwaitHealth:
			event = e.awaitHealth(record, action)
			if event != nil && event.Kind == rollout.EventHealthy && lost != "" {
				e.hold(record, "soak", "unit "+lost+" stopped proving it serves the target")
				event = nil
			} else if event != nil && event.Kind == rollout.EventHealthy {
				e.release(record, "soak")
			}
		case rollout.ActionRollback:
			event, err = e.rollback(ctx, record, action)
		case rollout.ActionPage:
			e.page(record)
		}
		if err != nil {
			// Events observed before the fence failed are dropped with
			// it: the successor derives them again.
			return nil, err
		}
		if event != nil {
			events = append(events, *event)
		}
	}
	return events, nil
}

func (e *Executor) preflight(ctx context.Context, record rollout.Record) *rollout.Event {
	if reason := e.checkGate(ctx, record, ""); reason != "" {
		e.hold(record, "", reason)
		return nil
	}
	now := e.now()
	for _, unit := range sortedUnits(record) {
		proof, ok := e.Proofs.Latest(unit)
		if !ok || now.Sub(proof.ObservedAt) > e.freshness() {
			e.hold(record, "", "unit "+unit+" has no fresh health proof")
			return nil
		}
		if proof.BinarySHA256 != record.FromDigest {
			e.release(record, "")
			return &rollout.Event{Kind: rollout.EventPreflightFailed, At: now,
				Reason: fmt.Sprintf("unit %s serves %s, not the rollout's from digest", unit, short(proof.BinarySHA256))}
		}
	}
	e.release(record, "")
	return &rollout.Event{Kind: rollout.EventPreflightPassed, At: now}
}

func (e *Executor) prepare(ctx context.Context, record rollout.Record, action rollout.Action) (*rollout.Event, error) {
	if reason := e.peersServing(record, action.Peers); reason != "" {
		e.hold(record, action.Unit, reason)
		return nil, nil
	}
	if reason := e.checkGate(ctx, record, action.Unit); reason != "" {
		e.hold(record, action.Unit, reason)
		return nil, nil
	}
	if e.expired(action) {
		return nil, nil
	}
	if err := e.fence(ctx, record); err != nil {
		return nil, err
	}
	step := e.track(stepKey(record.RolloutID, action.Unit, StepPrepare), action.Unit)
	reply, err := e.Driver.Step(ctx, Step{RolloutID: record.RolloutID, Kind: record.Kind, Unit: action.Unit,
		OperationID: action.OperationID, Action: StepPrepare, Digest: action.Digest, Epoch: record.AuthorityEpoch,
		ProofWindow: time.Duration(record.Policy.ProofDeadlineSeconds) * time.Second,
		Fence:       func(ctx context.Context) error { return e.fence(ctx, record) }})
	switch {
	case errors.Is(err, ErrLeaseLost):
		return nil, err
	case err != nil:
		slog.Warn("rollout step was not delivered", "component", "rollout", "rollout", record.RolloutID,
			"unit", action.Unit, "error", err)
		e.hold(record, action.Unit, "the unit's step agent did not answer")
		return nil, nil
	case reply.Outcome.Accepted():
		e.release(record, action.Unit)
		if !step.accepted {
			step.accepted = true
			recordStep(record, action.Unit, StepPrepare, reply.Outcome)
		}
		return &rollout.Event{Kind: rollout.EventPrepared, Unit: action.Unit, At: e.now()}, nil
	case reply.Outcome == OutcomeRefused:
		e.release(record, action.Unit)
		return &rollout.Event{Kind: rollout.EventHeld, Unit: action.Unit, At: e.now(),
			Reason: "unit " + action.Unit + " refused the step: " + reply.Reason}, nil
	default:
		e.hold(record, action.Unit, "the unit asked to retry: "+reply.Reason)
		return nil, nil
	}
}

func (e *Executor) awaitHealth(record rollout.Record, action rollout.Action) *rollout.Event {
	proof, ok := e.Proofs.Latest(action.Unit)
	// Only a fresh proof completes anything: a cached one cannot supply a
	// soak report for a unit that has since stopped serving.
	if !ok || proof.ObservedAt.Before(record.PhaseStartedAt) || !e.fresh(proof) {
		return nil
	}
	if proof.BinarySHA256 == record.ToDigest {
		progress := record.Units[action.Unit]
		if progress.HealthyReports > 0 && !proof.ObservedAt.After(progress.LastHealthyAt) {
			return nil
		}
		return &rollout.Event{Kind: rollout.EventHealthy, Unit: action.Unit, Health: proof.Health(), At: e.now()}
	}
	// A new incarnation that serves another release after the step means
	// the unit came back on the wrong binary (for example the watchdog
	// rolled it back). The old process's proofs, sent before it restarted,
	// are ignored by the incarnation check.
	step, known := e.issued[stepKey(record.RolloutID, action.Unit, StepPrepare)]
	if known && step.known && !proof.sameIncarnation(step.before) && proof.ObservedAt.After(step.at) {
		return &rollout.Event{Kind: rollout.EventUnhealthy, Unit: action.Unit, At: e.now(),
			Reason: fmt.Sprintf("unit %s restarted serving %s instead of the target", action.Unit, short(proof.BinarySHA256))}
	}
	return nil
}

func (e *Executor) rollback(ctx context.Context, record rollout.Record, action rollout.Action) (*rollout.Event, error) {
	key := stepKey(record.RolloutID, action.Unit, StepRollback) + "/" + action.OperationID
	step, sent := e.issued[key]
	if !sent || !step.accepted {
		if reason := e.peersServing(record, action.Peers); reason != "" {
			e.hold(record, action.Unit, reason)
			return nil, nil
		}
		if reason := e.checkGate(ctx, record, action.Unit); reason != "" {
			e.hold(record, action.Unit, reason)
			return nil, nil
		}
		if e.expired(action) {
			return nil, nil
		}
		if err := e.fence(ctx, record); err != nil {
			return nil, err
		}
		step = e.track(key, action.Unit)
		reply, err := e.Driver.Step(ctx, Step{RolloutID: record.RolloutID, Kind: record.Kind, Unit: action.Unit,
			OperationID: action.OperationID, Action: StepRollback, Digest: action.Digest, Replaces: record.ToDigest,
			Epoch: record.AuthorityEpoch, ProofWindow: time.Duration(record.Policy.RollbackDeadlineSeconds) * time.Second,
			Fence: func(ctx context.Context) error { return e.fence(ctx, record) }})
		switch {
		case errors.Is(err, ErrLeaseLost):
			return nil, err
		case err != nil:
			slog.Warn("rollout rollback step was not delivered", "component", "rollout", "rollout", record.RolloutID,
				"unit", action.Unit, "error", err)
			e.hold(record, action.Unit, "the unit's step agent did not answer")
			return nil, nil
		case reply.Outcome == OutcomeRefused:
			e.release(record, action.Unit)
			return &rollout.Event{Kind: rollout.EventRollbackHeld, Unit: action.Unit, At: e.now(),
				Reason: "unit " + action.Unit + " refused its rollback: " + reply.Reason}, nil
		case !reply.Outcome.Accepted():
			e.hold(record, action.Unit, "the unit asked to retry its rollback: "+reply.Reason)
			return nil, nil
		}
		e.release(record, action.Unit)
		step.accepted = true
		// Only a proof observed after the accepted attempt returned speaks
		// for the process it left running; a proof cached from an earlier,
		// failed attempt does not.
		step.at = e.now()
		recordStep(record, action.Unit, StepRollback, reply.Outcome)
	}
	proof, ok := e.Proofs.Latest(action.Unit)
	if ok && proof.BinarySHA256 == record.FromDigest && proof.ObservedAt.After(step.at) && e.fresh(proof) {
		return &rollout.Event{Kind: rollout.EventRollbackServing, Unit: action.Unit, At: e.now()}, nil
	}
	return nil, nil
}

// fence re-checks the authority lease immediately before a step leaves the
// leader: a lease lost while earlier steps, gates or reads ran must not
// still move a unit. Store.Commit fences the record, not this effect.
func (e *Executor) fence(ctx context.Context, record rollout.Record) error {
	if err := e.Fencer.Guard(ctx, record.AuthorityEpoch); err != nil {
		return fmt.Errorf("%w: %w", ErrLeaseLost, err)
	}
	return nil
}

// ErrLeaseLost stops a tick whose authority lease was lost before a step
// left the leader.
var ErrLeaseLost = errors.New("authority lease lost before a rollout step")

// waveLostProof names a soaking unit of the current wave that already
// reported healthy but has no fresh proof on the target now.
func (e *Executor) waveLostProof(record rollout.Record) string {
	if record.WaveIndex < 0 || record.WaveIndex >= len(record.Waves) {
		return ""
	}
	for _, id := range record.Waves[record.WaveIndex] {
		progress := record.Units[id]
		if progress.State != rollout.UnitSoaking || progress.HealthyReports == 0 {
			continue
		}
		if proof, ok := e.Proofs.Latest(id); !ok || !e.fresh(proof) || proof.BinarySHA256 != record.ToDigest {
			return id
		}
	}
	return ""
}

// waveRestart returns the healthy report of a soaking unit of the current
// wave whose fresh proof comes from a new incarnation; the transition core
// rolls the rollout back on it.
func (e *Executor) waveRestart(record rollout.Record) *rollout.Event {
	if !(record.Phase == rollout.PhaseCanary || record.Phase == rollout.PhaseCanarySoak ||
		record.Phase == rollout.PhaseBatch || record.Phase == rollout.PhaseBatchSoak) {
		return nil
	}
	for _, id := range record.Waves[record.WaveIndex] {
		progress := record.Units[id]
		if progress.State != rollout.UnitSoaking || progress.HealthyReports == 0 {
			continue
		}
		proof, ok := e.Proofs.Latest(id)
		if ok && e.fresh(proof) && !proof.ObservedAt.Before(record.PhaseStartedAt) &&
			(proof.ProcessID != progress.ProcessID || proof.StartNonce != progress.StartNonce) {
			return &rollout.Event{Kind: rollout.EventHealthy, Unit: id, Health: proof.Health(), At: e.now()}
		}
	}
	return nil
}

// expired reports a step whose phase deadline passed while its gates ran;
// the next tick commits the deadline instead of sending it.
func (e *Executor) expired(action rollout.Action) bool {
	return !action.Deadline.IsZero() && !e.now().Before(action.Deadline)
}

func (e *Executor) fresh(proof HealthProof) bool {
	return e.now().Sub(proof.ObservedAt) <= e.freshness()
}

func (e *Executor) page(record rollout.Record) {
	if e.paged[record.RolloutID] {
		return
	}
	e.paged[record.RolloutID] = true
	slog.Error("rollout is frozen and needs an operator", "component", "rollout", "rollout", record.RolloutID,
		"kind", record.Kind, "reason", record.Reason)
}

// track returns the leader-local memory of a step, creating it with the
// unit's proof from before the step.
func (e *Executor) track(key, unit string) *issue {
	if step, exists := e.issued[key]; exists {
		return step
	}
	before, known := e.Proofs.Latest(unit)
	step := &issue{at: e.now(), before: before, known: known}
	e.issued[key] = step
	return step
}

func stepKey(rolloutID, unit string, action StepAction) string {
	return rolloutID + "/" + unit + "/" + string(action)
}

// peersServing requires a fresh proof from every group peer, on either
// side of the rollout, so a step never takes a second replica down.
func (e *Executor) peersServing(record rollout.Record, peers []string) string {
	now := e.now()
	for _, peer := range peers {
		proof, ok := e.Proofs.Latest(peer)
		if !ok || now.Sub(proof.ObservedAt) > e.freshness() ||
			proof.BinarySHA256 != record.FromDigest && proof.BinarySHA256 != record.ToDigest {
			return "group peer " + peer + " is not serving"
		}
	}
	return ""
}

func (e *Executor) checkGate(ctx context.Context, record rollout.Record, unit string) string {
	if e.Gate == nil {
		return ""
	}
	if err := e.Gate.Check(ctx, record, unit); err != nil {
		return err.Error()
	}
	return ""
}

// startNext begins the first program rollout that has not completed. A
// program stops at a rollout that ended any other way.
func (e *Executor) startNext(ctx context.Context, epoch uint64) error {
	if e.Program == nil {
		return nil
	}
	program, err := e.Program(ctx)
	if err != nil {
		return fmt.Errorf("read rollout program: %w", err)
	}
	for _, spec := range program {
		existing, _, err := e.Store.Load(ctx, spec.RolloutID)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			spec.AuthorityEpoch = epoch
			if _, _, err := e.Store.Begin(ctx, spec, e.now()); err != nil {
				return fmt.Errorf("begin rollout %s: %w", spec.RolloutID, err)
			}
			return nil
		}
		if err != nil {
			return e.halt(spec.RolloutID, err.Error())
		}
		// A completed record only satisfies the program step it was
		// planned from: the same ID with another target, kind, waves or
		// policy stops the program instead of skipping ahead.
		if err := existing.Matches(spec); err != nil {
			return e.halt(spec.RolloutID, err.Error())
		}
		if existing.Phase != rollout.PhaseComplete {
			return e.halt(spec.RolloutID, "rollout ended "+string(existing.Phase))
		}
	}
	return nil
}

func (e *Executor) halt(rolloutID, reason string) error {
	if e.halted != rolloutID {
		e.halted = rolloutID
		slog.Warn("rollout program stopped", "component", "rollout", "rollout", rolloutID, "reason", reason)
	}
	return nil
}

func (e *Executor) publish(epoch uint64, record *rollout.Record) {
	if e.Status == nil {
		return
	}
	e.Status.PublishStatus(statusOf(e.Cell, epoch, record, e.Proofs, e.holds, e.now()))
}

func sortedUnits(record rollout.Record) []string {
	var units []string
	for _, wave := range record.Waves {
		units = append(units, wave...)
	}
	return units
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
