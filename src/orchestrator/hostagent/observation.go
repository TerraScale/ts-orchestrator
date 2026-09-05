package hostagent

import (
	"context"
	"errors"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

var errHostObservationBusy = errors.New("host observation unavailable while lifecycle mutation is in progress")

type lifecycleObservation struct {
	state    string
	desired  []hostmanifest.ComponentSpec
	quiesced bool
}

// A provider download or systemd transition keeps the mutation lock for its
// entire operation. Read-only status must report unknown promptly while that
// lock is held, rather than queue behind an installation or claim cached health.
func (l *Lifecycle) tryObservation(ctx context.Context) (lifecycleObservation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycleObservation{}, err
	}
	if !l.mutex.TryLock() {
		return lifecycleObservation{}, l.observationBusyError()
	}
	defer l.mutex.Unlock()
	result := lifecycleObservation{state: l.state, desired: slices.Clone(l.desired), quiesced: l.quiescedObservationLocked(ctx)}
	if err := ctx.Err(); err != nil {
		return lifecycleObservation{}, err
	}
	return result, nil
}

// Progress names only fixed phases and the already validated component token.
// It does not retain error strings, provider responses, URLs, or configuration.
// Access never takes the mutation lock, so a retry cannot hide its last failure.
type reconcileProgress struct {
	component       string
	phase           string
	outcome         string
	failedComponent string
	failedPhase     string
}

type installPhaseFailure struct {
	phase string
	cause error
}

func (e *installPhaseFailure) Error() string { return e.cause.Error() }
func (e *installPhaseFailure) Unwrap() error { return e.cause }

func (l *Lifecycle) recordReconcileProgress(component, phase, outcome string) {
	next := reconcileProgress{component: component, phase: phase, outcome: outcome}
	if previous := l.reconcileProgress.Load(); previous != nil {
		next.failedComponent, next.failedPhase = previous.failedComponent, previous.failedPhase
	}
	if outcome == "failed" {
		next.failedComponent, next.failedPhase = component, phase
	}
	if outcome == "succeeded" && next.failedComponent == component {
		next.failedComponent, next.failedPhase = "", ""
	}
	l.reconcileProgress.Store(&next)
}

func (l *Lifecycle) observationBusyError() error {
	progress := l.reconcileProgress.Load()
	if progress == nil {
		return errHostObservationBusy
	}
	detail := errHostObservationBusy.Error() + "; reconcile component=" + progress.component + " phase=" + progress.phase + " outcome=" + progress.outcome
	if progress.failedPhase != "" {
		detail += " last-failed-component=" + progress.failedComponent + " last-failed-phase=" + progress.failedPhase
	}
	return errors.New(detail)
}
