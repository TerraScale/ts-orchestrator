package rollout

import (
	"cmp"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// Spec is the caller-supplied rollout definition. KnownBad is the cell's
// durable known-bad list; a target in it can never start.
type Spec struct {
	RolloutID      string
	Kind           Kind
	Cell           string
	FromDigest     string
	ToDigest       string
	Units          []Unit
	Policy         Policy
	KnownBad       []string
	AuthorityEpoch uint64
}

// New plans the waves and returns a pending record. It performs no effect.
func New(spec Spec, now time.Time) (Record, error) {
	if now.IsZero() {
		return Record{}, fmt.Errorf("%w: start time", ErrInvalid)
	}
	if slices.Contains(spec.KnownBad, spec.ToDigest) {
		return Record{}, ErrKnownBad
	}
	waves, err := PlanWaves(spec.Units, spec.Policy)
	if err != nil {
		return Record{}, err
	}
	policyDigest, err := spec.Policy.Digest()
	if err != nil {
		return Record{}, err
	}
	units := make(map[string]UnitProgress, len(spec.Units))
	for _, unit := range spec.Units {
		units[unit.ID] = UnitProgress{State: UnitPending, Group: unit.Group, Seed: unit.Seed}
	}
	for wave, ids := range waves {
		for _, id := range ids {
			progress := units[id]
			progress.Wave = wave
			units[id] = progress
		}
	}
	knownBad := slices.Clone(spec.KnownBad)
	slices.Sort(knownBad)
	record := Record{
		SchemaVersion: SchemaVersion, RolloutID: spec.RolloutID, Kind: spec.Kind, Cell: spec.Cell,
		FromDigest: spec.FromDigest, ToDigest: spec.ToDigest, Policy: spec.Policy, PolicyDigest: policyDigest,
		Phase: PhasePending, Waves: waves, Units: units, KnownBad: slices.Compact(knownBad),
		StartedAt: now.UTC(), PhaseStartedAt: now.UTC(), AuthorityEpoch: spec.AuthorityEpoch,
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// EventKind names an observation fed into the transition core.
type EventKind string

const (
	// EventStart moves a pending rollout into preflight.
	EventStart EventKind = "start"
	// EventPreflightPassed reports that the authority lease, JetStream
	// quorum, every unit serving FromDigest and the compatibility evidence
	// were all checked.
	EventPreflightPassed EventKind = "preflight-passed"
	EventPreflightFailed EventKind = "preflight-failed"
	// EventPrepared reports that the executor accepted one unit's forward step.
	EventPrepared EventKind = "prepared"
	// EventHealthy is one fresh serving report from a unit.
	EventHealthy EventKind = "healthy"
	// EventUnhealthy is a failed-canary, not-serving or wrong-digest report.
	EventUnhealthy EventKind = "unhealthy"
	// EventHeld reports that the executor or controller held the unit.
	EventHeld EventKind = "held"
	// EventRollbackServing reports that a unit serves FromDigest again.
	EventRollbackServing EventKind = "rollback-serving"
	// EventRollbackHeld reports that a unit's rollback step was itself held.
	EventRollbackHeld EventKind = "rollback-held"
	// EventTick evaluates deadlines and soak completion at Event.At.
	EventTick EventKind = "tick"
	// EventAbort is an explicit operator stop.
	EventAbort EventKind = "abort"
	// EventFreeze stops all progress, for example after host session loss.
	EventFreeze EventKind = "freeze"
	// EventResume is an explicit signed operator resume of a frozen rollout.
	// It only ever continues a rollback; it never retargets ToDigest.
	EventResume EventKind = "resume"
)

// Event is one observation. At is the observation time used for deadlines.
type Event struct {
	Kind   EventKind
	Unit   string
	Health Health
	Reason string
	At     time.Time
	// Left, for EventResume, lists the units that already prove a third
	// release, neither FromDigest nor ToDigest nor known bad: an operator
	// moved them off the target.
	Left []string
}

// Apply returns the record that results from event. The input is never
// modified. An error leaves the caller's durable record unchanged.
func Apply(record Record, event Event) (Record, error) {
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	if event.At.IsZero() || len(event.Reason) > maxReason {
		return Record{}, fmt.Errorf("%w: event time or reason", ErrInvalid)
	}
	if record.Phase.Terminal() {
		return Record{}, ErrTerminal
	}
	next := record.Clone()
	at := event.At.UTC()
	if completionEvent(event.Kind) {
		// A completion that arrives after its phase deadline must not erase
		// that deadline: enforce it first, exactly as a tick at the same
		// instant would, and drop the late completion if it fired.
		phase, wave := next.Phase, next.WaveIndex
		next.tick(at)
		if next.Phase != phase || next.WaveIndex != wave {
			if err := next.Validate(); err != nil {
				return Record{}, err
			}
			return next, nil
		}
	}
	var err error
	switch event.Kind {
	case EventStart:
		err = next.start(at)
	case EventPreflightPassed:
		err = next.preflightPassed(at)
	case EventPreflightFailed:
		err = next.requirePhase(PhasePreflight)
		if err == nil {
			next.finish(PhaseAborted, at, reasonOr(event.Reason, "preflight failed"))
		}
	case EventPrepared:
		err = next.prepared(event.Unit, at)
	case EventHealthy:
		err = next.healthy(event.Unit, event.Health, at)
	case EventUnhealthy, EventHeld:
		// A held forward step rolls back like an unhealthy one; rollback
		// itself, not the forward unit, is what freezes for a human.
		err = next.failed(event.Unit, at, reasonOr(event.Reason, string(event.Kind)))
	case EventRollbackServing:
		err = next.rollbackServing(event.Unit, at)
	case EventRollbackHeld:
		err = next.rollbackHeld(event.Unit, at, reasonOr(event.Reason, "rollback held"))
	case EventTick:
		next.tick(at)
	case EventAbort:
		err = next.abort(at, reasonOr(event.Reason, "operator abort"))
	case EventFreeze:
		if next.Phase == PhaseFrozen {
			return Record{}, ErrInvalidTransition
		}
		next.enter(PhaseFrozen, at, time.Time{}, reasonOr(event.Reason, "frozen"))
	case EventResume:
		err = next.resume(at, event.Left)
	default:
		err = fmt.Errorf("%w: event kind", ErrInvalid)
	}
	if err != nil {
		return Record{}, err
	}
	if err := next.Validate(); err != nil {
		return Record{}, err
	}
	return next, nil
}

// completionEvent reports events that complete a phase with a deadline.
func completionEvent(kind EventKind) bool {
	return kind == EventPreflightPassed || kind == EventPrepared || kind == EventHealthy
}

// boundReason keeps a stored reason within maxReason bytes without splitting
// a UTF-8 rune, so a prefixed failure reason can never fail validation and
// discard the rollback it describes.
func boundReason(reason string) string {
	if len(reason) <= maxReason {
		return reason
	}
	const ellipsis = "..."
	cut := maxReason - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + ellipsis
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}

func (record *Record) requirePhase(phases ...Phase) error {
	if !slices.Contains(phases, record.Phase) {
		return fmt.Errorf("%w: %s", ErrInvalidTransition, record.Phase)
	}
	return nil
}

func (record *Record) enter(phase Phase, at, deadline time.Time, reason string) {
	record.Phase = phase
	record.PhaseStartedAt = at
	record.PhaseDeadline = deadline
	record.Reason = boundReason(reason)
}

func (record *Record) finish(phase Phase, at time.Time, reason string) {
	record.enter(phase, at, time.Time{}, reason)
}

func (record *Record) start(at time.Time) error {
	if err := record.requirePhase(PhasePending); err != nil {
		return err
	}
	if slices.Contains(record.KnownBad, record.ToDigest) {
		record.finish(PhaseAborted, at, "target digest is known bad")
		return nil
	}
	record.enter(PhasePreflight, at, at.Add(seconds(record.Policy.PreflightSeconds)), "")
	return nil
}

func (record *Record) preflightPassed(at time.Time) error {
	if err := record.requirePhase(PhasePreflight); err != nil {
		return err
	}
	if slices.Contains(record.KnownBad, record.ToDigest) {
		record.finish(PhaseAborted, at, "target digest is known bad")
		return nil
	}
	record.beginWave(0, at)
	return nil
}

// beginWave marks the wave's units as preparing. The executor must only
// issue each prepare after the unit's group peers are serving (see Action).
func (record *Record) beginWave(wave int, at time.Time) {
	record.WaveIndex = wave
	phase := PhaseBatch
	if wave == 0 {
		phase = PhaseCanary
	}
	for _, id := range record.Waves[wave] {
		progress := record.Units[id]
		progress.State = UnitPreparing
		progress.HealthyReports, progress.FirstHealthyAt, progress.ProcessID, progress.StartNonce = 0, time.Time{}, 0, ""
		progress.LastHealthyAt = time.Time{}
		record.Units[id] = progress
	}
	record.enter(phase, at, at.Add(seconds(record.Policy.ProofDeadlineSeconds)), "")
}

func (record *Record) currentWaveUnit(unit string) (UnitProgress, error) {
	progress, exists := record.Units[unit]
	if !exists || progress.Wave != record.WaveIndex {
		return UnitProgress{}, fmt.Errorf("%w: unit %q is not in the current wave", ErrInvalidTransition, unit)
	}
	return progress, nil
}

func (record *Record) prepared(unit string, at time.Time) error {
	if !record.Phase.preparing() && !record.Phase.soaking() {
		return fmt.Errorf("%w: %s", ErrInvalidTransition, record.Phase)
	}
	progress, err := record.currentWaveUnit(unit)
	if err != nil {
		return err
	}
	switch progress.State {
	case UnitSoaking:
		return nil
	case UnitPreparing:
	default:
		return fmt.Errorf("%w: unit %q is %s", ErrInvalidTransition, unit, progress.State)
	}
	progress.State = UnitSoaking
	record.Units[unit] = progress
	if record.Phase.preparing() && record.waveState(UnitSoaking) {
		phase := PhaseBatchSoak
		if record.Phase == PhaseCanary {
			phase = PhaseCanarySoak
		}
		record.enter(phase, at, at.Add(seconds(record.Policy.ProofDeadlineSeconds)), "")
	}
	return nil
}

func (record *Record) waveState(state UnitState) bool {
	for _, id := range record.Waves[record.WaveIndex] {
		if record.Units[id].State != state {
			return false
		}
	}
	return true
}

func (record *Record) healthy(unit string, health Health, at time.Time) error {
	if !record.Phase.preparing() && !record.Phase.soaking() {
		return fmt.Errorf("%w: %s", ErrInvalidTransition, record.Phase)
	}
	progress, err := record.currentWaveUnit(unit)
	if err != nil {
		return err
	}
	if progress.State != UnitSoaking {
		return fmt.Errorf("%w: unit %q is %s", ErrInvalidTransition, unit, progress.State)
	}
	if health.ProcessID <= 0 || !nonceRE.MatchString(health.StartNonce) || health.ObservedAt.IsZero() {
		return fmt.Errorf("%w: health report identity", ErrInvalid)
	}
	if health.ObservedAt.Before(record.PhaseStartedAt) || health.ObservedAt.After(at.Add(time.Minute)) {
		// A report older than the current phase cannot prove the new
		// process, in the preparing phase as little as in the soak: a
		// replayed report would start the soak clock in the past.
		return fmt.Errorf("%w: stale or future health report", ErrInvalid)
	}
	if health.Digest != record.ToDigest {
		record.startRollback(at, fmt.Sprintf("unit %s serves an unexpected digest", unit))
		return nil
	}
	if progress.HealthyReports > 0 && (progress.ProcessID != health.ProcessID || progress.StartNonce != health.StartNonce) {
		record.startRollback(at, fmt.Sprintf("unit %s restarted during soak", unit))
		return nil
	}
	observed := health.ObservedAt.UTC()
	if progress.HealthyReports > 0 && !observed.After(progress.LastHealthyAt) {
		// A replayed or reordered report proves nothing new.
		return nil
	}
	if progress.HealthyReports == 0 {
		progress.FirstHealthyAt = observed
		progress.ProcessID, progress.StartNonce = health.ProcessID, health.StartNonce
	}
	progress.LastHealthyAt = observed
	progress.HealthyReports++
	record.Units[unit] = progress
	record.advanceIfSoaked(at)
	return nil
}

func (record *Record) failed(unit string, at time.Time, reason string) error {
	if !record.Phase.preparing() && !record.Phase.soaking() {
		return fmt.Errorf("%w: %s", ErrInvalidTransition, record.Phase)
	}
	progress, exists := record.Units[unit]
	if !exists || !progress.State.touched() {
		return fmt.Errorf("%w: unit %q has not moved", ErrInvalidTransition, unit)
	}
	record.startRollback(at, fmt.Sprintf("unit %s: %s", unit, reason))
	return nil
}

func (record *Record) soakDuration() time.Duration {
	if record.Phase == PhaseCanarySoak {
		return seconds(record.Policy.CanarySoakSeconds)
	}
	return seconds(record.Policy.BatchSoakSeconds)
}

// advanceIfSoaked promotes the wave once every unit has produced the
// required consecutive reports from one incarnation over the soak window.
func (record *Record) advanceIfSoaked(at time.Time) {
	if !record.Phase.soaking() {
		return
	}
	for _, id := range record.Waves[record.WaveIndex] {
		progress := record.Units[id]
		// The observations, not elapsed tick time, must span the window: a
		// unit that stopped reporting early never completes its soak.
		if progress.State != UnitSoaking || progress.HealthyReports < record.Policy.MinHealthyReports ||
			progress.LastHealthyAt.Before(progress.FirstHealthyAt.Add(record.soakDuration())) {
			return
		}
	}
	for _, id := range record.Waves[record.WaveIndex] {
		progress := record.Units[id]
		progress.State = UnitPromoted
		record.Units[id] = progress
	}
	if record.WaveIndex+1 < len(record.Waves) {
		record.beginWave(record.WaveIndex+1, at)
		return
	}
	record.finish(PhaseComplete, at, "")
}

func (record *Record) tick(at time.Time) {
	switch {
	case record.Phase == PhasePreflight && !at.Before(record.PhaseDeadline):
		record.finish(PhaseAborted, at, "preflight deadline exceeded")
	case record.Phase.preparing() && !at.Before(record.PhaseDeadline):
		record.startRollback(at, "prepare deadline exceeded")
	case record.Phase.soaking():
		if !at.Before(record.PhaseDeadline) {
			for _, id := range record.Waves[record.WaveIndex] {
				if record.Units[id].HealthyReports == 0 {
					record.startRollback(at, fmt.Sprintf("unit %s missed its serving-proof deadline", id))
					return
				}
			}
		}
		wave := record.WaveIndex
		record.advanceIfSoaked(at)
		// Every unit that proved itself before the serving-proof deadline
		// has finished its soak window by deadline+soak, and has reported
		// again within minSoakGap after it. A wave still soaking then has a
		// unit that stopped reporting (for example a hung process after one
		// healthy report); it must not hold the cell's rollout slot forever.
		if record.Phase.soaking() && record.WaveIndex == wave &&
			!at.Before(record.PhaseDeadline.Add(record.soakDuration()).Add(minSoakGap)) {
			record.startRollback(at, "soak did not complete before its deadline")
		}
	case record.Phase == PhaseRollingBack && !at.Before(record.PhaseDeadline):
		head := record.rollbackHead()
		if head != "" {
			progress := record.Units[head]
			progress.State = UnitHeld
			record.Units[head] = progress
		}
		record.enter(PhaseFrozen, at, time.Time{}, "rollback deadline exceeded")
	}
}

// startRollback durably marks ToDigest known bad in the same record write
// that first orders any rollback action, then rolls back every touched unit
// newest first.
func (record *Record) startRollback(at time.Time, reason string) {
	if !slices.Contains(record.KnownBad, record.ToDigest) {
		record.KnownBad = append(record.KnownBad, record.ToDigest)
		slices.Sort(record.KnownBad)
		if len(record.KnownBad) > MaxKnownBad {
			// Keep the current target; the cell list retains the dropped entry.
			drop := 0
			if record.KnownBad[0] == record.ToDigest {
				drop = 1
			}
			record.KnownBad = slices.Delete(record.KnownBad, drop, drop+1)
		}
	}
	var touched []string
	for id, progress := range record.Units {
		if progress.State.touched() {
			touched = append(touched, id)
		}
	}
	slices.SortFunc(touched, func(a, b string) int {
		if order := cmp.Compare(record.Units[b].Wave, record.Units[a].Wave); order != 0 {
			return order
		}
		return cmp.Compare(b, a)
	})
	for _, id := range touched {
		progress := record.Units[id]
		progress.State = UnitRollingBack
		record.Units[id] = progress
	}
	record.RollbackOrder = touched
	if len(touched) == 0 {
		record.finish(PhaseRolledBack, at, reason)
		return
	}
	record.enter(PhaseRollingBack, at, at.Add(seconds(record.Policy.RollbackDeadlineSeconds)), reason)
}

// rollbackHead returns the next unit to return to FromDigest. Rollback moves
// one unit at a time so the group peer of each step keeps serving.
func (record *Record) rollbackHead() string {
	for _, id := range record.RollbackOrder {
		if record.Units[id].State == UnitRollingBack {
			return id
		}
	}
	return ""
}

func (record *Record) rollbackServing(unit string, at time.Time) error {
	if err := record.requirePhase(PhaseRollingBack); err != nil {
		return err
	}
	if head := record.rollbackHead(); head != unit {
		if progress, exists := record.Units[unit]; exists && progress.State == UnitRolledBack {
			return nil
		}
		return fmt.Errorf("%w: unit %q is not the rollback head", ErrInvalidTransition, unit)
	}
	progress := record.Units[unit]
	progress.State = UnitRolledBack
	record.Units[unit] = progress
	if record.rollbackHead() == "" {
		record.finish(PhaseRolledBack, at, record.Reason)
		return nil
	}
	record.enter(PhaseRollingBack, at, at.Add(seconds(record.Policy.RollbackDeadlineSeconds)), record.Reason)
	return nil
}

func (record *Record) rollbackHeld(unit string, at time.Time, reason string) error {
	if err := record.requirePhase(PhaseRollingBack); err != nil {
		return err
	}
	if head := record.rollbackHead(); head != unit {
		return fmt.Errorf("%w: unit %q is not the rollback head", ErrInvalidTransition, unit)
	}
	progress := record.Units[unit]
	progress.State = UnitHeld
	record.Units[unit] = progress
	// Never retarget ToDigest: a held rollback stops for a human.
	record.enter(PhaseFrozen, at, time.Time{}, reason)
	return nil
}

func (record *Record) abort(at time.Time, reason string) error {
	switch {
	case record.Phase == PhasePending || record.Phase == PhasePreflight:
		record.finish(PhaseAborted, at, reason)
	case record.Phase.preparing() || record.Phase.soaking():
		record.startRollback(at, reason)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidTransition, record.Phase)
	}
	return nil
}

// resume continues a frozen rollout by retrying its rollback. Units still on
// the forward path are rolled back too; nothing moves towards ToDigest. A
// unit in left, which an operator already moved off the target by hand, is
// done: stepping it back to FromDigest could undo the fix (ts-gru-2,
// 2026-10-08).
func (record *Record) resume(at time.Time, left []string) error {
	if err := record.requirePhase(PhaseFrozen); err != nil {
		return err
	}
	for _, id := range left {
		if progress, in := record.Units[id]; in && progress.State.touched() {
			progress.State = UnitRolledBack
			record.Units[id] = progress
		}
	}
	for id, progress := range record.Units {
		if progress.State == UnitHeld {
			if progress.Attempts >= record.Policy.MaxRollbackRetries {
				return fmt.Errorf("%w: unit %q exhausted its rollback retries", ErrAttemptsExhausted, id)
			}
			progress.Attempts++
			progress.State = UnitRollingBack
			record.Units[id] = progress
		}
	}
	reason := record.Reason
	pending := record.rollbackHead() != ""
	for _, progress := range record.Units {
		if progress.State == UnitPreparing || progress.State == UnitSoaking || progress.State == UnitPromoted {
			pending = true
		}
	}
	if !pending {
		record.finish(PhaseAborted, at, reason)
		return nil
	}
	// Re-derive the order so units that were frozen mid-forward join it.
	record.startRollback(at, reason)
	return nil
}
