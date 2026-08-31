// This file ports Scheduling/Availability/AvailabilityModels.cs.
package scheduling

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

var availabilityIdentityPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

// availabilityIdentityValidate ports the internal AvailabilityIdentity.Validate.
func availabilityIdentityValidate(value string, parameterName string) (string, error) {
	if len(value) < 1 || len(value) > 63 || !availabilityIdentityPattern.MatchString(value) {
		return "", &errs.Argument{
			Param:   parameterName,
			Message: "Identity must be a bounded canonical lowercase token.",
		}
	}
	return value, nil
}

// ServiceId identifies one service in availability policy evaluation.
type ServiceId struct {
	Value string
}

// NewServiceId validates the canonical identity token.
func NewServiceId(value string) (ServiceId, error) {
	validated, err := availabilityIdentityValidate(value, "value")
	if err != nil {
		return ServiceId{}, err
	}
	return ServiceId{Value: validated}, nil
}

func (id ServiceId) String() string { return id.Value }

// ReplicaId identifies one replica of a service.
type ReplicaId struct {
	Value string
}

// NewReplicaId validates the canonical identity token.
func NewReplicaId(value string) (ReplicaId, error) {
	validated, err := availabilityIdentityValidate(value, "value")
	if err != nil {
		return ReplicaId{}, err
	}
	return ReplicaId{Value: validated}, nil
}

func (id ReplicaId) String() string { return id.Value }

// AvailabilityNodeId identifies one node in availability observations.
type AvailabilityNodeId struct {
	Value string
}

// NewAvailabilityNodeId validates the canonical identity token.
func NewAvailabilityNodeId(value string) (AvailabilityNodeId, error) {
	validated, err := availabilityIdentityValidate(value, "value")
	if err != nil {
		return AvailabilityNodeId{}, err
	}
	return AvailabilityNodeId{Value: validated}, nil
}

func (id AvailabilityNodeId) String() string { return id.Value }

// FailureDomainId identifies one failure domain.
type FailureDomainId struct {
	Value string
}

// NewFailureDomainId validates the canonical identity token.
func NewFailureDomainId(value string) (FailureDomainId, error) {
	validated, err := availabilityIdentityValidate(value, "value")
	if err != nil {
		return FailureDomainId{}, err
	}
	return FailureDomainId{Value: validated}, nil
}

func (id FailureDomainId) String() string { return id.Value }

// AvailabilityCount is an unsigned availability quantity.
type AvailabilityCount struct {
	Value uint64
}

// NewAvailabilityCount wraps a count without validation (mirrors the C# record).
func NewAvailabilityCount(value uint64) AvailabilityCount {
	return AvailabilityCount{Value: value}
}

// AddChecked adds two counts with checked arithmetic.
func (c AvailabilityCount) AddChecked(other AvailabilityCount) (AvailabilityCount, error) {
	sum := c.Value + other.Value
	if sum < c.Value {
		return AvailabilityCount{}, &OverflowError{Message: "Arithmetic operation resulted in an overflow."}
	}
	return AvailabilityCount{Value: sum}, nil
}

// SubtractChecked subtracts other from c with checked arithmetic.
func (c AvailabilityCount) SubtractChecked(other AvailabilityCount) (AvailabilityCount, error) {
	if other.Value > c.Value {
		return AvailabilityCount{}, &OverflowError{Message: "Arithmetic operation resulted in an overflow."}
	}
	return AvailabilityCount{Value: c.Value - other.Value}, nil
}

func availabilityCountFromInt32(value int) (AvailabilityCount, error) {
	if value < 0 {
		return AvailabilityCount{}, &OverflowError{Message: "Arithmetic operation resulted in an overflow."}
	}
	return AvailabilityCount{Value: uint64(value)}, nil
}

// AvailabilityGeneration is a positive generation of a caller-accepted
// availability observation snapshot. Zero is deliberately not a sentinel
// because generation equality authorizes a change against already accepted
// evidence.
type AvailabilityGeneration struct {
	Value uint64
}

// NewAvailabilityGeneration requires a positive generation.
func NewAvailabilityGeneration(value uint64) (AvailabilityGeneration, error) {
	if value == 0 {
		return AvailabilityGeneration{}, &errs.ArgumentOutOfRangeError{
			Param:   "value",
			Message: "Availability generations must be positive.",
		}
	}
	return AvailabilityGeneration{Value: value}, nil
}

// ServiceCriticality classifies a service for availability policy.
type ServiceCriticality int

const (
	ServiceCriticalityOrdinary ServiceCriticality = 1 + iota
	ServiceCriticalityCritical
)

func (c ServiceCriticality) defined() bool {
	return c == ServiceCriticalityOrdinary || c == ServiceCriticalityCritical
}

// ReserveDisposition states whether placement may consume the reserve.
type ReserveDisposition int

const (
	ReserveDispositionPreserve ReserveDisposition = 1 + iota
	ReserveDispositionMayConsume
)

func (d ReserveDisposition) defined() bool {
	return d == ReserveDispositionPreserve || d == ReserveDispositionMayConsume
}

// ServiceAvailabilityPolicy is the explicit caller-owned availability policy.
type ServiceAvailabilityPolicy struct {
	ServiceId                      ServiceId
	Desired                        AvailabilityCount
	MinimumAvailable               AvailabilityCount
	Quorum                         AvailabilityCount
	MaximumConcurrentDisruptions   AvailabilityCount
	Criticality                    ServiceCriticality
	OnePerHost                     bool
	RequiredDistinctFailureDomains AvailabilityCount
	Reserve                        ResourceVector
	ReserveDisposition             ReserveDisposition
}

// NewServiceAvailabilityPolicy validates the closed policy relations.
func NewServiceAvailabilityPolicy(
	serviceId ServiceId,
	desired AvailabilityCount,
	minimumAvailable AvailabilityCount,
	quorum AvailabilityCount,
	maximumConcurrentDisruptions AvailabilityCount,
	criticality ServiceCriticality,
	onePerHost bool,
	requiredDistinctFailureDomains AvailabilityCount,
	reserve ResourceVector,
	reserveDisposition ReserveDisposition,
) (*ServiceAvailabilityPolicy, error) {
	if !criticality.defined() {
		return nil, &errs.ArgumentOutOfRangeError{Param: "criticality"}
	}
	if !reserveDisposition.defined() {
		return nil, &errs.ArgumentOutOfRangeError{Param: "reserveDisposition"}
	}
	if minimumAvailable.Value > desired.Value || quorum.Value > desired.Value ||
		maximumConcurrentDisruptions.Value > desired.Value ||
		requiredDistinctFailureDomains.Value > desired.Value {
		return nil, &errs.Argument{
			Param: "minimumAvailable",
			Message: "Minimum, quorum, disruption, and topology counts cannot exceed " +
				"desired count.",
		}
	}
	return &ServiceAvailabilityPolicy{
		ServiceId:                      serviceId,
		Desired:                        desired,
		MinimumAvailable:               minimumAvailable,
		Quorum:                         quorum,
		MaximumConcurrentDisruptions:   maximumConcurrentDisruptions,
		Criticality:                    criticality,
		OnePerHost:                     onePerHost,
		RequiredDistinctFailureDomains: requiredDistinctFailureDomains,
		Reserve:                        reserve,
		ReserveDisposition:             reserveDisposition,
	}, nil
}

// ReplicaAvailabilityState is the observed condition of one replica.
type ReplicaAvailabilityState int

const (
	ReplicaAvailabilityStateAvailable ReplicaAvailabilityState = 1 + iota
	ReplicaAvailabilityStateUnavailable
	ReplicaAvailabilityStateDisrupting
)

func (s ReplicaAvailabilityState) defined() bool {
	return s >= ReplicaAvailabilityStateAvailable && s <= ReplicaAvailabilityStateDisrupting
}

// ReplicaObservation is what one replica actually runs, as last observed.
type ReplicaObservation struct {
	ReplicaId       ReplicaId
	ServiceId       ServiceId
	NodeId          *AvailabilityNodeId
	FailureDomainId *FailureDomainId
	State           ReplicaAvailabilityState
}

// NewReplicaObservation validates the observation shape.
func NewReplicaObservation(
	replicaId ReplicaId,
	serviceId ServiceId,
	nodeId *AvailabilityNodeId,
	failureDomainId *FailureDomainId,
	state ReplicaAvailabilityState,
) (ReplicaObservation, error) {
	if !state.defined() {
		return ReplicaObservation{}, &errs.ArgumentOutOfRangeError{Param: "state"}
	}
	return ReplicaObservation{
		ReplicaId:       replicaId,
		ServiceId:       serviceId,
		NodeId:          nodeId,
		FailureDomainId: failureDomainId,
		State:           state,
	}, nil
}

// canonicalKey ports the internal CanonicalKey used for duplicate/conflict
// detection.
func (o ReplicaObservation) canonicalKey() string {
	node := "-"
	if o.NodeId != nil {
		node = o.NodeId.Value
	}
	domain := "-"
	if o.FailureDomainId != nil {
		domain = o.FailureDomainId.Value
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d", o.ReplicaId.Value, o.ServiceId.Value, node, domain, int(o.State))
}

// ObservationCompleteness states whether the observation set is complete.
type ObservationCompleteness int

const (
	ObservationCompletenessComplete ObservationCompleteness = 1 + iota
	ObservationCompletenessIncomplete
)

func (c ObservationCompleteness) defined() bool {
	return c == ObservationCompletenessComplete || c == ObservationCompletenessIncomplete
}

// AvailabilityChange is the closed change vocabulary.
type AvailabilityChange interface {
	isAvailabilityChange()
}

// PlaceReplicaChange places one new replica.
type PlaceReplicaChange struct {
	ReplicaId             ReplicaId
	TargetNodeId          AvailabilityNodeId
	TargetFailureDomainId FailureDomainId
	RequestedResources    ResourceVector
	AvailableResources    ResourceVector
}

func (PlaceReplicaChange) isAvailabilityChange() {}

// DrainNodeChange drains every replica on one node.
type DrainNodeChange struct {
	NodeId AvailabilityNodeId
}

func (DrainNodeChange) isAvailabilityChange() {}

// MaintainReplicaChange disrupts one replica for maintenance.
type MaintainReplicaChange struct {
	ReplicaId ReplicaId
}

func (MaintainReplicaChange) isAvailabilityChange() {}

// AvailabilityEvaluationRequest is the explicit evaluation input.
type AvailabilityEvaluationRequest struct {
	Policy                               ServiceAvailabilityPolicy
	Change                               AvailabilityChange
	ObservationCompleteness              ObservationCompleteness
	ObservationGeneration                AvailabilityGeneration
	CurrentAcceptedObservationGeneration AvailabilityGeneration
	Observations                         []ReplicaObservation
}

// NewAvailabilityEvaluationRequest defensively copies and validates the input.
func NewAvailabilityEvaluationRequest(
	policy *ServiceAvailabilityPolicy,
	change AvailabilityChange,
	observationCompleteness ObservationCompleteness,
	observationGeneration AvailabilityGeneration,
	currentAcceptedObservationGeneration AvailabilityGeneration,
	observations []ReplicaObservation,
) (*AvailabilityEvaluationRequest, error) {
	if policy == nil {
		return nil, &errs.Argument{Param: "policy"}
	}
	if change == nil {
		return nil, &errs.Argument{Param: "change"}
	}
	if !observationCompleteness.defined() {
		return nil, &errs.ArgumentOutOfRangeError{Param: "observationCompleteness"}
	}
	if observations == nil {
		return nil, &errs.Argument{Param: "observations"}
	}
	snapshot, err := schedulerInputSnapshotCopy(
		observations,
		SchedulerTechnicalInputLimits.MaximumAvailabilityObservationCount,
		"observations",
		"Availability observation input")
	if err != nil {
		return nil, err
	}
	return &AvailabilityEvaluationRequest{
		Policy:                               *policy,
		Change:                               change,
		ObservationCompleteness:              observationCompleteness,
		ObservationGeneration:                observationGeneration,
		CurrentAcceptedObservationGeneration: currentAcceptedObservationGeneration,
		Observations:                         snapshot,
	}, nil
}

// AvailabilityReasonCode enumerates every trace row, in canonical trace order.
type AvailabilityReasonCode int

const (
	AvailabilityReasonCodeObservationSetComplete AvailabilityReasonCode = 1 + iota
	AvailabilityReasonCodeReplicaObservationsUnique
	AvailabilityReasonCodeReplicaObservationsConsistent
	AvailabilityReasonCodeReplicaIdentitiesComplete
	AvailabilityReasonCodeServiceIdentityConsistent
	AvailabilityReasonCodeChangeTargetValid
	AvailabilityReasonCodeDesiredCount
	AvailabilityReasonCodeMinimumAvailable
	AvailabilityReasonCodeQuorum
	AvailabilityReasonCodeDisruptionBudget
	AvailabilityReasonCodeOnePerHost
	AvailabilityReasonCodeFailureDomainSpread
	AvailabilityReasonCodeReserveCpu
	AvailabilityReasonCodeReserveMemory
	AvailabilityReasonCodeReserveBlockIo
	AvailabilityReasonCodeReserveEphemeralDisk
	AvailabilityReasonCodeReserveBandwidth
	AvailabilityReasonCodeReservePids
	AvailabilityReasonCodeReserveFileDescriptors
	AvailabilityReasonCodeReserveHugePages
	AvailabilityReasonCodeCapacityCpu
	AvailabilityReasonCodeCapacityMemory
	AvailabilityReasonCodeCapacityBlockIo
	AvailabilityReasonCodeCapacityEphemeralDisk
	AvailabilityReasonCodeCapacityBandwidth
	AvailabilityReasonCodeCapacityPids
	AvailabilityReasonCodeCapacityFileDescriptors
	AvailabilityReasonCodeCapacityHugePages
	AvailabilityReasonCodeObservationGenerationNotRollback
	AvailabilityReasonCodeObservationGenerationNotFuture
)

func (c AvailabilityReasonCode) defined() bool {
	return c >= AvailabilityReasonCodeObservationSetComplete &&
		c <= AvailabilityReasonCodeObservationGenerationNotFuture
}

func (c AvailabilityReasonCode) String() string {
	names := [...]string{
		"ObservationSetComplete", "ReplicaObservationsUnique", "ReplicaObservationsConsistent",
		"ReplicaIdentitiesComplete", "ServiceIdentityConsistent", "ChangeTargetValid",
		"DesiredCount", "MinimumAvailable", "Quorum", "DisruptionBudget", "OnePerHost",
		"FailureDomainSpread", "ReserveCpu", "ReserveMemory", "ReserveBlockIo",
		"ReserveEphemeralDisk", "ReserveBandwidth", "ReservePids", "ReserveFileDescriptors",
		"ReserveHugePages", "CapacityCpu", "CapacityMemory", "CapacityBlockIo",
		"CapacityEphemeralDisk", "CapacityBandwidth", "CapacityPids", "CapacityFileDescriptors",
		"CapacityHugePages", "ObservationGenerationNotRollback", "ObservationGenerationNotFuture",
	}
	if c >= 1 && int(c) <= len(names) {
		return names[c-1]
	}
	return fmt.Sprintf("AvailabilityReasonCode(%d)", int(c))
}

// AllAvailabilityReasonCodes lists every code in canonical order.
var AllAvailabilityReasonCodes = func() []AvailabilityReasonCode {
	codes := make([]AvailabilityReasonCode, 0, 30)
	for code := AvailabilityReasonCodeObservationSetComplete; code <= AvailabilityReasonCodeObservationGenerationNotFuture; code++ {
		codes = append(codes, code)
	}
	return codes
}()

// AvailabilityReasonOutcome is the outcome of one trace row.
type AvailabilityReasonOutcome int

const (
	AvailabilityReasonOutcomePassed AvailabilityReasonOutcome = 1 + iota
	AvailabilityReasonOutcomeRejected
	AvailabilityReasonOutcomeHeld
	AvailabilityReasonOutcomeNotApplicable
)

func (o AvailabilityReasonOutcome) defined() bool {
	return o >= AvailabilityReasonOutcomePassed && o <= AvailabilityReasonOutcomeNotApplicable
}

func (o AvailabilityReasonOutcome) String() string {
	switch o {
	case AvailabilityReasonOutcomePassed:
		return "Passed"
	case AvailabilityReasonOutcomeRejected:
		return "Rejected"
	case AvailabilityReasonOutcomeHeld:
		return "Held"
	case AvailabilityReasonOutcomeNotApplicable:
		return "NotApplicable"
	default:
		return fmt.Sprintf("AvailabilityReasonOutcome(%d)", int(o))
	}
}

// AvailabilityReason is one numeric, closed trace row.
type AvailabilityReason struct {
	Code     AvailabilityReasonCode
	Outcome  AvailabilityReasonOutcome
	Observed uint64
	Required uint64
}

func newAvailabilityReason(
	code AvailabilityReasonCode,
	outcome AvailabilityReasonOutcome,
	observed uint64,
	required uint64,
) AvailabilityReason {
	if !code.defined() || !outcome.defined() {
		panic("Trace codes and outcomes must be known.")
	}
	return AvailabilityReason{Code: code, Outcome: outcome, Observed: observed, Required: required}
}

// AvailabilityDecision is the typed evaluation outcome.
type AvailabilityDecision struct {
	AcceptedRequest *AvailabilityEvaluationRequest
	Trace           []AvailabilityReason
}

// Admitted reports whether the request was accepted.
func (d AvailabilityDecision) Admitted() bool {
	return d.AcceptedRequest != nil
}

// sortReplicaObservations applies the canonical evaluation ordering.
func sortReplicaObservations(observations []ReplicaObservation) {
	sort.SliceStable(observations, func(left, right int) bool {
		if observations[left].ReplicaId.Value != observations[right].ReplicaId.Value {
			return strings.Compare(observations[left].ReplicaId.Value, observations[right].ReplicaId.Value) < 0
		}
		return strings.Compare(observations[left].canonicalKey(), observations[right].canonicalKey()) < 0
	})
}
