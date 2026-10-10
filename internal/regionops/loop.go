// Package regionops is the global home leader's region operations loop. On
// every tick, and only while this controller holds the global lease, it runs
// the region planner, admits approved regions and refreshes stale cost
// admissions, and advances each open region by at most one lifecycle step
// through regionlifecycle.Driver.
//
// Each capability is optional and off unless its caller wires it:
//   - without Plan nothing is proposed;
//   - without Admissions nothing is admitted or readmitted;
//   - without an effector for a step, a region waiting on that step stays
//     where it is and the wait is journaled once.
//
// The loop never approves anything; the region planner approves its own
// proposals inside the guardrails in docs/capacity.md (TS-804).
package regionops

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
)

// ErrEffectPending is wrapped by an effector whose effect exists but has not
// finished, so it is neither absent (to retry) nor found (to complete). The
// loop waits for a later observation instead of reporting a failure.
var ErrEffectPending = errors.New("region lifecycle step effect is still in progress")

// ErrNoEffector is returned for a step no effector is registered for.
var ErrNoEffector = errors.New("no effector is registered for this region lifecycle step")

// Effectors dispatches a step's effect to the effector registered for it.
type Effectors map[regionlifecycle.Step]regionlifecycle.Effector

// Has reports whether step has an effector.
func (effectors Effectors) Has(step regionlifecycle.Step) bool { return effectors[step] != nil }

func (effectors Effectors) Execute(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.StepResult, error) {
	effector := effectors[intent.Step]
	if effector == nil {
		return regionlifecycle.StepResult{}, ErrNoEffector
	}
	return effector.Execute(ctx, record, intent)
}

func (effectors Effectors) Observe(ctx context.Context, record regionlifecycle.Record,
	intent regionlifecycle.StepIntent,
) (regionlifecycle.Observation, error) {
	effector := effectors[intent.Step]
	if effector == nil {
		return regionlifecycle.Observation{}, ErrNoEffector
	}
	return effector.Observe(ctx, record, intent)
}

// Admissions produces a fresh cost estimate for a region.
type Admissions interface {
	Estimate(ctx context.Context, record regionlifecycle.Record, now time.Time) (regionlifecycle.CostAdmission, error)
}

// Loop runs the global leader's region operations.
type Loop struct {
	Store   *regionlifecycle.Store
	Machine regionlifecycle.Machine
	// Home is the global home region, counted in the admission guards.
	Home   regionlifecycle.Home
	Leader authority.Fencer
	// Plan runs the region planner under epoch; nil proposes nothing.
	Plan func(ctx context.Context, epoch uint64, now time.Time) ([]string, error)
	// Admissions admits approved regions and refreshes stale admissions of
	// in-flight ones; nil admits nothing.
	Admissions Admissions
	// Effectors drive lifecycle steps; nil drives nothing. A non-nil set,
	// even an empty one, turns driving on: a region whose next step has no
	// effector waits, and the wait is journaled once.
	Effectors Effectors
	Now       func() time.Time

	mu sync.Mutex
	// noted is the last wait or refusal journaled per cell, so a region
	// that waits for many ticks is journaled once. The key carries the
	// proposal generation, so a replaced proposal journals its own waits.
	noted map[string]string
}

// Report is what one tick did, for tests and logs.
type Report struct {
	Leader     bool
	Proposed   []string
	Admitted   []string
	Readmitted []string
	Advanced   []string
	Resumed    []string
	Waiting    []string
	Errors     []error
}

func (loop *Loop) now() time.Time {
	if loop.Now != nil {
		return loop.Now()
	}
	return time.Now()
}

// Run ticks until ctx ends.
func (loop *Loop) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report := loop.Tick(ctx)
		for _, err := range report.Errors {
			slog.Warn("region operations tick failed", observability.ComponentKey, "regionops", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick runs one round on the global leader; followers do nothing.
func (loop *Loop) Tick(ctx context.Context) Report {
	var report Report
	snapshot := loop.Leader.Current()
	if !snapshot.CanMutate() {
		return report
	}
	report.Leader = true
	epoch := snapshot.Epoch
	if loop.Plan != nil {
		proposed, err := loop.Plan(ctx, epoch, loop.now())
		report.Proposed = proposed
		if err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("plan regions: %w", err))
		}
	}
	if loop.Admissions == nil && loop.Effectors == nil {
		return report
	}
	records, err := loop.Store.List(ctx)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Errorf("list region lifecycle records: %w", err))
		return report
	}
	slices.SortFunc(records, func(a, b regionlifecycle.Record) int {
		switch {
		case a.Cell < b.Cell:
			return -1
		case a.Cell > b.Cell:
			return 1
		}
		return 0
	})
	for _, record := range records {
		if record.Phase.Terminal() || ctx.Err() != nil {
			continue
		}
		if loop.Admissions != nil {
			blocked, err := loop.admit(ctx, epoch, record.Cell, records, &report, false)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Errorf("admit region %s: %w", record.Cell, err))
			}
			if blocked {
				continue
			}
		}
		if loop.Effectors != nil {
			if err := loop.drive(ctx, epoch, record.Cell, records, &report); err != nil {
				report.Errors = append(report.Errors, fmt.Errorf("advance region %s: %w", record.Cell, err))
			}
		}
	}
	return report
}

// admit admits an Approved region, or refreshes the admission of an
// in-flight one whose next step spends and whose admission is missing or
// within the last third of its TTL, so the step never races its expiry. It
// reports blocked when an admission was due but not stored (refused or
// failed): the region must not run a step this tick.
//
// Only a step that starts new spending is readmitted up front. A journaled
// (recovered) intent is reconciled by observation first, because recording
// an effect that already exists is not subject to the budget; drive asks
// for its readmission (recovered) only when the effect is confirmed absent
// and the driver refused a stale admission.
func (loop *Loop) admit(ctx context.Context, epoch uint64, cell string, fleetRecords []regionlifecycle.Record,
	report *Report, recovered bool,
) (blocked bool, err error) {
	record, revision, err := loop.Store.Get(ctx, cell)
	if err != nil {
		return true, err
	}
	now := loop.now()
	ttl := regionlifecycle.AdmissionTTL
	readmit := false
	switch {
	case record.Phase == regionlifecycle.Approved && !recovered:
	case record.Phase != regionlifecycle.Held && record.Phase != regionlifecycle.RollingBack &&
		record.Phase != regionlifecycle.RetireProposed && record.Phase != regionlifecycle.RetireApproved:
		// Only a step this loop can run needs a fresh admission; refreshing
		// one that waits for an effector would only churn the journal.
		step, ok := regionlifecycle.NextStep(record)
		if !ok || !step.Spends() || step.Retire() || !loop.Effectors.Has(step) || (record.Pending != nil) != recovered {
			return false, nil
		}
		if record.Admission != nil && now.Before(record.Admission.AdmittedAt.Add(ttl-ttl/3)) {
			return false, nil
		}
		readmit = true
	default:
		return false, nil
	}
	admission, err := loop.Admissions.Estimate(ctx, record, now)
	if err != nil {
		return true, err
	}
	fleet := regionlifecycle.FleetOf(fleetRecords, cell, loop.Home)
	var next regionlifecycle.Record
	if readmit {
		next, err = loop.Machine.Readmit(record, admission, fleet, now)
	} else {
		next, err = loop.Machine.Admit(record, admission, fleet, now)
	}
	if errors.Is(err, regionlifecycle.ErrRegionLimit) || errors.Is(err, regionlifecycle.ErrBudgetCeiling) ||
		errors.Is(err, regionlifecycle.ErrAdmissionStale) {
		loop.note(ctx, epoch, record, "admission refused: "+err.Error(), decisionlog.KindHeld, decisionlog.StatusPending)
		report.Waiting = append(report.Waiting, cell)
		// A refused readmission blocks this tick's step even while the older
		// admission is still fresh: the driver only checks freshness, and
		// the current fleet or price no longer fits.
		return true, nil
	}
	if err != nil {
		return true, err
	}
	if _, err := loop.Store.Update(ctx, epoch, record, next, revision); err != nil {
		return true, err
	}
	// Later admissions in this tick see this one's admitted estimate.
	for index := range fleetRecords {
		if fleetRecords[index].Cell == cell {
			fleetRecords[index] = next
		}
	}
	if readmit {
		report.Readmitted = append(report.Readmitted, cell)
	} else {
		report.Admitted = append(report.Admitted, cell)
	}
	recordAdmission(ctx, epoch, next, fleet, readmit)
	loop.clearNote(cell)
	return false, nil
}

// drive advances one region by at most one step, or resumes a held one whose
// pending effect an observation now finds.
func (loop *Loop) drive(ctx context.Context, epoch uint64, cell string, fleetRecords []regionlifecycle.Record,
	report *Report,
) error {
	record, revision, err := loop.Store.Get(ctx, cell)
	if err != nil {
		return err
	}
	step, ok := regionlifecycle.NextStep(record)
	if !ok || record.Phase == regionlifecycle.RollingBack {
		return nil
	}
	if !loop.Effectors.Has(step) {
		loop.note(ctx, epoch, record, "waiting for an effector for step "+string(step), decisionlog.KindHeld,
			decisionlog.StatusPending)
		report.Waiting = append(report.Waiting, cell)
		return nil
	}
	if record.Phase == regionlifecycle.Held {
		return loop.resume(ctx, epoch, record, revision, report)
	}
	driver := regionlifecycle.Driver{Machine: loop.Machine, Store: loop.Store, Effector: loop.Effectors, Now: loop.Now}
	next, err := driver.Advance(ctx, epoch, cell)
	if errors.Is(err, regionlifecycle.ErrAdmissionStale) && record.Pending != nil && loop.Admissions != nil &&
		next.Generation == record.Generation {
		// The recovered effect is confirmed absent and its admission is
		// stale: readmit, then retry; a refusal leaves it unexecuted.
		blocked, admitErr := loop.admit(ctx, epoch, cell, fleetRecords, report, true)
		if admitErr != nil || blocked {
			return admitErr
		}
		if record, _, err = loop.Store.Get(ctx, cell); err != nil {
			return err
		}
		next, err = driver.Advance(ctx, epoch, cell)
	}
	if next.Generation != record.Generation && next.Generation != 0 {
		recordStep(ctx, epoch, record, next, step, err)
		report.Advanced = append(report.Advanced, cell)
		loop.clearNote(cell)
		if next.Phase == regionlifecycle.Held {
			return nil // the hold is the outcome; it is journaled above
		}
		return err
	}
	if errors.Is(err, regionlifecycle.ErrAdmissionStale) || errors.Is(err, ErrEffectPending) {
		loop.note(ctx, epoch, record, "step "+string(step)+" waits: "+err.Error(), decisionlog.KindHeld,
			decisionlog.StatusPending)
		report.Waiting = append(report.Waiting, cell)
		return nil
	}
	return err
}

// resume leaves Held only when an observation finds the pending step's
// effect: the step then completes with the observed result. An absent effect
// is left held for an operator, because retrying an effect that failed is a
// decision the loop does not take on its own.
func (loop *Loop) resume(ctx context.Context, epoch uint64, record regionlifecycle.Record, revision uint64,
	report *Report,
) error {
	// Only a step held in its running phase completes from an observation;
	// rollback and a failed bring-up's pending intent settle on their own
	// paths (CompleteRollback, ReconcileRetirePending).
	if record.Pending == nil || record.Hold == nil || record.Hold.Phase == regionlifecycle.RollingBack ||
		record.Hold.Phase == regionlifecycle.RetireProposed || record.Hold.Phase == regionlifecycle.RetireApproved {
		return nil
	}
	observation, err := loop.Effectors.Observe(ctx, record, *record.Pending)
	if errors.Is(err, ErrEffectPending) {
		return nil
	}
	if err != nil || !observation.Found {
		return err
	}
	next, err := loop.Machine.Resume(record, &observation, loop.now())
	if err != nil {
		return err
	}
	if _, err := loop.Store.Update(ctx, epoch, record, next, revision); err != nil {
		return err
	}
	recordStep(ctx, epoch, record, next, record.Pending.Step, nil)
	report.Resumed = append(report.Resumed, record.Cell)
	loop.clearNote(record.Cell)
	return nil
}

func (loop *Loop) note(ctx context.Context, epoch uint64, record regionlifecycle.Record, why string,
	kind decisionlog.Kind, status decisionlog.Status,
) {
	loop.mu.Lock()
	if loop.noted == nil {
		loop.noted = map[string]string{}
	}
	key := strconv.FormatUint(record.ProposalGeneration, 10) + "\x00" + string(record.Phase) + "\x00" + why
	if loop.noted[record.Cell] == key {
		loop.mu.Unlock()
		return
	}
	loop.noted[record.Cell] = key
	loop.mu.Unlock()
	decisionlog.Record(ctx, decisionlog.Decision{
		Region: record.Cell, Actor: decisionlog.Actor{Slice: "regionops"}, Kind: kind,
		Subject: regionSubject(record),
		Summary: fmt.Sprintf("Region %s waits in %s", record.Cell, record.Phase),
		Reason:  why, Rule: "regionops.loop", Status: status, Epoch: epoch,
		Attrs: map[string]string{"proposal": record.Proposal.ID, "phase": string(record.Phase)},
	})
}

func (loop *Loop) clearNote(cell string) {
	loop.mu.Lock()
	delete(loop.noted, cell)
	loop.mu.Unlock()
}

func regionSubject(record regionlifecycle.Record) decisionlog.Subject {
	return decisionlog.Subject{Kind: "region", ID: record.Cell, Name: record.Proposal.OCIRegion}
}

func recordAdmission(ctx context.Context, epoch uint64, record regionlifecycle.Record, fleet regionlifecycle.Fleet,
	readmit bool,
) {
	verb := "Admitted"
	if readmit {
		verb = "Readmitted"
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region: record.Cell, Actor: decisionlog.Actor{Slice: "regionops"}, Kind: decisionlog.KindRegionAdmitted,
		Subject: regionSubject(record),
		Summary: fmt.Sprintf("%s region %s at an estimated %d cents per month", verb, record.Cell,
			record.Admission.EstimatedMonthlyCents),
		Reason: "A fresh cost estimate fits the region maximum and the monthly budget headroom.",
		Rule:   "regionlifecycle.admit",
		Signals: []decisionlog.Signal{
			{Name: "estimated_monthly_cost", Value: float64(record.Admission.EstimatedMonthlyCents) / 100, Unit: "USD"},
			{Name: "committed_monthly_cost", Value: float64(fleet.CommittedMonthlyCents) / 100, Unit: "USD"},
			{Name: "other_regions", Value: float64(fleet.Regions)},
		},
		Status: decisionlog.StatusSucceeded, Epoch: epoch,
		Attrs: map[string]string{"proposal": record.Proposal.ID, "phase": string(record.Phase),
			"evidence": record.Admission.EvidenceDigest},
	})
}

func recordStep(ctx context.Context, epoch uint64, prior, next regionlifecycle.Record, step regionlifecycle.Step,
	cause error,
) {
	status := decisionlog.StatusInProgress
	outcome := "moved to " + string(next.Phase)
	switch {
	case next.Phase == regionlifecycle.Held:
		status, outcome = decisionlog.StatusFailed, "held"
	case next.Pending == nil:
		status = decisionlog.StatusSucceeded
	}
	reason := fmt.Sprintf("Step %s of proposal %s ran under global epoch %d.", step, prior.Proposal.ID, epoch)
	if next.Hold != nil {
		reason = "Held: " + next.Hold.Reason
	} else if cause != nil {
		reason += " " + cause.Error()
	}
	attrs := map[string]string{"proposal": prior.Proposal.ID, "step": string(step), "from": string(prior.Phase),
		"to": string(next.Phase), "generation": strconv.FormatUint(next.Generation, 10)}
	if next.Pending != nil {
		attrs["create_key"] = next.Pending.CreateKey
	}
	decisionlog.Record(ctx, decisionlog.Decision{
		Region: prior.Cell, Actor: decisionlog.Actor{Slice: "regionops"}, Kind: decisionlog.KindRegionStep,
		Subject: regionSubject(prior),
		Summary: fmt.Sprintf("Region %s step %s: %s -> %s", prior.Cell, step, prior.Phase, next.Phase),
		Reason:  reason, Rule: "regionlifecycle.driver", Status: status, Outcome: outcome, Epoch: epoch,
		Attrs: attrs,
	})
}
