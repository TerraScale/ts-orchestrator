package control

import (
	"fmt"
	"time"
)

// NatsMonitoringSupervisionAction mirrors the C# enum: the supervision
// decision for the monitoring observer itself.
type NatsMonitoringSupervisionAction int

const (
	// NatsMonitoringSupervisionActionContinue: observations are current; keep
	// serving the aggregate.
	NatsMonitoringSupervisionActionContinue NatsMonitoringSupervisionAction = 1
	// NatsMonitoringSupervisionActionMarkDegraded: observations are aging or
	// partially failing; keep the last truthful aggregate marked degraded.
	NatsMonitoringSupervisionActionMarkDegraded NatsMonitoringSupervisionAction = 2
	// NatsMonitoringSupervisionActionMarkUnavailable: no current observation at
	// all; report unavailability instead of stale numbers.
	NatsMonitoringSupervisionActionMarkUnavailable NatsMonitoringSupervisionAction = 3
)

func (a NatsMonitoringSupervisionAction) String() string {
	switch a {
	case NatsMonitoringSupervisionActionContinue:
		return "Continue"
	case NatsMonitoringSupervisionActionMarkDegraded:
		return "MarkDegraded"
	case NatsMonitoringSupervisionActionMarkUnavailable:
		return "MarkUnavailable"
	default:
		return fmt.Sprintf("%d", int(a))
	}
}

// NatsMonitoringSupervision mirrors the C# static class: supervision for the
// NATS monitoring observer. Supervision can only change how observability
// reports itself; it has no capability that could gate, delay, or fail
// regional control.
var NatsMonitoringSupervision natsMonitoringSupervision

type natsMonitoringSupervision struct{}

// NatsMonitoringSupervisionDegradedAfter mirrors the C# DegradedAfter:
// observations older than this stay truthful-but-degraded.
var NatsMonitoringSupervisionDegradedAfter = 30 * time.Second

// NatsMonitoringSupervisionUnavailableAfter mirrors the C# UnavailableAfter:
// observations older than this are reported unavailable, never stale-served.
var NatsMonitoringSupervisionUnavailableAfter = 2 * time.Minute

// NatsMonitoringSupervisionDegradedAfterConsecutiveFailures mirrors the C#
// constant: consecutive failed observation rounds tolerated before degrading.
const NatsMonitoringSupervisionDegradedAfterConsecutiveFailures = 1

// Evaluate mirrors NatsMonitoringSupervision.Evaluate.
func (natsMonitoringSupervision) Evaluate(
	lastSuccessfulObservation *time.Time,
	consecutiveFailedRounds int,
	now time.Time,
) NatsMonitoringSupervisionAction {
	if consecutiveFailedRounds < 0 {
		panic("Specified argument was out of the range of valid values. (Parameter 'consecutiveFailedRounds')")
	}

	if lastSuccessfulObservation != nil {
		age := now.Sub(*lastSuccessfulObservation)
		if age < NatsMonitoringSupervisionDegradedAfter && consecutiveFailedRounds == 0 {
			return NatsMonitoringSupervisionActionContinue
		}

		if age < NatsMonitoringSupervisionUnavailableAfter {
			return NatsMonitoringSupervisionActionMarkDegraded
		}

		return NatsMonitoringSupervisionActionMarkUnavailable
	}

	// No successful observation yet: never report healthy. Starting without
	// failures is degraded (no data yet); any failure before the first success
	// is unavailable.
	if consecutiveFailedRounds == 0 {
		return NatsMonitoringSupervisionActionMarkDegraded
	}

	return NatsMonitoringSupervisionActionMarkUnavailable
}

// Availability mirrors NatsMonitoringSupervision.Availability.
func (natsMonitoringSupervision) Availability(
	lastSuccessfulObservation *time.Time,
	consecutiveFailedRounds int,
	now time.Time,
) NatsMonitoringAvailability {
	switch NatsMonitoringSupervision.Evaluate(lastSuccessfulObservation, consecutiveFailedRounds, now) {
	case NatsMonitoringSupervisionActionContinue:
		return NatsMonitoringAvailabilityAvailable
	case NatsMonitoringSupervisionActionMarkDegraded:
		return NatsMonitoringAvailabilityDegraded
	default:
		return NatsMonitoringAvailabilityUnavailable
	}
}

// RegionalControlContinues mirrors the C# RegionalControlContinues: always
// true by construction; the pure function exists so tests can pin the
// invariant that no supervision state ever suppresses control.
func (natsMonitoringSupervision) RegionalControlContinues(action NatsMonitoringSupervisionAction) bool {
	return true
}
