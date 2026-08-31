// Package scheduling ports TerraScale.Orchestrator.Scheduler (SchedulingModels.cs,
// DeterministicScheduler.cs, Availability/AvailabilityModels.cs and
// Availability/AvailabilityPolicyEvaluator.cs from src/TerraScale.Orchestrator).
//
// This file ports Scheduling/SchedulingModels.cs.
package scheduling

import (
	"fmt"
	"math/big"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// InvalidOperationError mirrors System.InvalidOperationException.
type InvalidOperationError struct {
	Message string
}

func (e *InvalidOperationError) Error() string { return e.Message }

// OverflowError mirrors System.OverflowException raised by checked arithmetic.
type OverflowError struct {
	Message string
}

func (e *OverflowError) Error() string { return e.Message }

// SchedulerTechnicalInputLimits holds the technical caller-input snapshot limits;
// these are not placement, replica, or allocation policy caps.
var SchedulerTechnicalInputLimits = struct {
	MaximumCandidateCount               int
	MaximumAvailabilityObservationCount int
	MaximumPortCount                    int
	MaximumFactCount                    int
	MaximumLabelCount                   int
	ScoreDimensionCount                 int
}{
	MaximumCandidateCount:               4_096,
	MaximumAvailabilityObservationCount: 4_096,
	MaximumPortCount:                    1_024,
	MaximumFactCount:                    1_024,
	MaximumLabelCount:                   1_024,
	ScoreDimensionCount:                 8,
}

// schedulerInputSnapshotCopy ports the internal SchedulerInputSnapshot.Copy bound
// check. (The .NET enumerator-failure translation has no Go equivalent: slices
// cannot fail mid-enumeration, so only the snapshot bound remains.)
func schedulerInputSnapshotCopy[T any](source []T, maximum int, parameterName, inputName string) ([]T, error) {
	if len(source) > maximum {
		return nil, &errs.Argument{
			Param:   parameterName,
			Message: fmt.Sprintf("%s exceeds the technical snapshot bound.", inputName),
		}
	}
	return slices.Clone(source), nil
}

// ResourceVector carries non-negative quantities in scheduler-defined base units.
// Callers are responsible for using the same unit for available and requested
// values in each dimension.
type ResourceVector struct {
	Cpu             int64
	Memory          int64
	BlockIo         int64
	EphemeralDisk   int64
	Bandwidth       int64
	Pids            int64
	FileDescriptors int64
	HugePages       int64
}

// ResourceVectorZero mirrors ResourceVector.Zero.
var ResourceVectorZero = ResourceVector{}

func requireNonNegative(value int64, parameterName string) (int64, error) {
	if value < 0 {
		return 0, &errs.ArgumentOutOfRangeError{
			Param:   parameterName,
			Message: "Resource quantities must be non-negative.",
		}
	}
	return value, nil
}

// NewResourceVector validates and constructs a ResourceVector, mirroring the C#
// constructor which rejects negative quantities.
func NewResourceVector(cpu, memory, blockIo, ephemeralDisk, bandwidth, pids, fileDescriptors, hugePages int64) (ResourceVector, error) {
	var err error
	if cpu, err = requireNonNegative(cpu, "cpu"); err != nil {
		return ResourceVector{}, err
	}
	if memory, err = requireNonNegative(memory, "memory"); err != nil {
		return ResourceVector{}, err
	}
	if blockIo, err = requireNonNegative(blockIo, "blockIo"); err != nil {
		return ResourceVector{}, err
	}
	if ephemeralDisk, err = requireNonNegative(ephemeralDisk, "ephemeralDisk"); err != nil {
		return ResourceVector{}, err
	}
	if bandwidth, err = requireNonNegative(bandwidth, "bandwidth"); err != nil {
		return ResourceVector{}, err
	}
	if pids, err = requireNonNegative(pids, "pids"); err != nil {
		return ResourceVector{}, err
	}
	if fileDescriptors, err = requireNonNegative(fileDescriptors, "fileDescriptors"); err != nil {
		return ResourceVector{}, err
	}
	if hugePages, err = requireNonNegative(hugePages, "hugePages"); err != nil {
		return ResourceVector{}, err
	}
	return ResourceVector{
		Cpu:             cpu,
		Memory:          memory,
		BlockIo:         blockIo,
		EphemeralDisk:   ephemeralDisk,
		Bandwidth:       bandwidth,
		Pids:            pids,
		FileDescriptors: fileDescriptors,
		HugePages:       hugePages,
	}, nil
}

// AddChecked adds two vectors with checked arithmetic.
func (v ResourceVector) AddChecked(other ResourceVector) (ResourceVector, error) {
	var dims [8]int64
	values := [...]int64{v.Cpu, v.Memory, v.BlockIo, v.EphemeralDisk, v.Bandwidth, v.Pids, v.FileDescriptors, v.HugePages}
	others := [...]int64{other.Cpu, other.Memory, other.BlockIo, other.EphemeralDisk, other.Bandwidth, other.Pids, other.FileDescriptors, other.HugePages}
	for index := range values {
		sum, err := checkedAdd(values[index], others[index])
		if err != nil {
			return ResourceVector{}, &OverflowError{Message: err.Error()}
		}
		dims[index] = sum
	}
	return NewResourceVector(dims[0], dims[1], dims[2], dims[3], dims[4], dims[5], dims[6], dims[7])
}

// SubtractChecked subtracts other from v with checked arithmetic; the result is
// re-validated as a non-negative vector exactly like the C# record constructor.
func (v ResourceVector) SubtractChecked(other ResourceVector) (ResourceVector, error) {
	var dims [8]int64
	values := [...]int64{v.Cpu, v.Memory, v.BlockIo, v.EphemeralDisk, v.Bandwidth, v.Pids, v.FileDescriptors, v.HugePages}
	others := [...]int64{other.Cpu, other.Memory, other.BlockIo, other.EphemeralDisk, other.Bandwidth, other.Pids, other.FileDescriptors, other.HugePages}
	for index := range values {
		difference, err := checkedSubtract(values[index], others[index])
		if err != nil {
			return ResourceVector{}, &OverflowError{Message: err.Error()}
		}
		dims[index] = difference
	}
	return NewResourceVector(dims[0], dims[1], dims[2], dims[3], dims[4], dims[5], dims[6], dims[7])
}

type dimensionValue struct {
	Dimension ResourceDimension
	Value     int64
}

// orderedValues ports ResourceVector.OrderedValues().
func (v ResourceVector) orderedValues() []dimensionValue {
	return []dimensionValue{
		{ResourceDimensionCpu, v.Cpu},
		{ResourceDimensionMemory, v.Memory},
		{ResourceDimensionBlockIo, v.BlockIo},
		{ResourceDimensionEphemeralDisk, v.EphemeralDisk},
		{ResourceDimensionBandwidth, v.Bandwidth},
		{ResourceDimensionPids, v.Pids},
		{ResourceDimensionFileDescriptors, v.FileDescriptors},
		{ResourceDimensionHugePages, v.HugePages},
	}
}

// ResourceDimension enumerates the scheduler resource dimensions.
type ResourceDimension int

const (
	ResourceDimensionCpu ResourceDimension = iota
	ResourceDimensionMemory
	ResourceDimensionBlockIo
	ResourceDimensionEphemeralDisk
	ResourceDimensionBandwidth
	ResourceDimensionPids
	ResourceDimensionFileDescriptors
	ResourceDimensionHugePages
)

// AllResourceDimensions lists every dimension in canonical order (Enum.GetValues).
var AllResourceDimensions = []ResourceDimension{
	ResourceDimensionCpu,
	ResourceDimensionMemory,
	ResourceDimensionBlockIo,
	ResourceDimensionEphemeralDisk,
	ResourceDimensionBandwidth,
	ResourceDimensionPids,
	ResourceDimensionFileDescriptors,
	ResourceDimensionHugePages,
}

func (d ResourceDimension) String() string {
	switch d {
	case ResourceDimensionCpu:
		return "Cpu"
	case ResourceDimensionMemory:
		return "Memory"
	case ResourceDimensionBlockIo:
		return "BlockIo"
	case ResourceDimensionEphemeralDisk:
		return "EphemeralDisk"
	case ResourceDimensionBandwidth:
		return "Bandwidth"
	case ResourceDimensionPids:
		return "Pids"
	case ResourceDimensionFileDescriptors:
		return "FileDescriptors"
	case ResourceDimensionHugePages:
		return "HugePages"
	default:
		return fmt.Sprintf("ResourceDimension(%d)", int(d))
	}
}

// CandidateVetoCode is the closed veto vocabulary.
type CandidateVetoCode int

const (
	CandidateVetoCodeStatefulSafetyHold CandidateVetoCode = iota
	CandidateVetoCodeDisruptionBudgetHold
	CandidateVetoCodeVolumeLocalityMismatch
	CandidateVetoCodeTopologySafetyHold
	CandidateVetoCodeControllerHold
)

func (c CandidateVetoCode) defined() bool {
	return c >= CandidateVetoCodeStatefulSafetyHold && c <= CandidateVetoCodeControllerHold
}

func (c CandidateVetoCode) String() string {
	switch c {
	case CandidateVetoCodeStatefulSafetyHold:
		return "StatefulSafetyHold"
	case CandidateVetoCodeDisruptionBudgetHold:
		return "DisruptionBudgetHold"
	case CandidateVetoCodeVolumeLocalityMismatch:
		return "VolumeLocalityMismatch"
	case CandidateVetoCodeTopologySafetyHold:
		return "TopologySafetyHold"
	case CandidateVetoCodeControllerHold:
		return "ControllerHold"
	default:
		return fmt.Sprintf("CandidateVetoCode(%d)", int(c))
	}
}

// AllCandidateVetoCodes lists every veto code in declared order.
var AllCandidateVetoCodes = []CandidateVetoCode{
	CandidateVetoCodeStatefulSafetyHold,
	CandidateVetoCodeDisruptionBudgetHold,
	CandidateVetoCodeVolumeLocalityMismatch,
	CandidateVetoCodeTopologySafetyHold,
	CandidateVetoCodeControllerHold,
}

// CandidateVeto is a closed, non-secret-bearing caller veto. Arbitrary caller
// text is deliberately impossible because reason traces may be exported to
// logs and evidence.
type CandidateVeto struct {
	Code CandidateVetoCode
}

// NewCandidateVeto validates the code against the closed vocabulary.
func NewCandidateVeto(code CandidateVetoCode) (CandidateVeto, error) {
	if !code.defined() {
		return CandidateVeto{}, &errs.ArgumentOutOfRangeError{Param: "code"}
	}
	return CandidateVeto{Code: code}, nil
}

// AllocationSafetyCap is a caller-supplied admission ceiling.
type AllocationSafetyCap struct {
	CurrentAllocations int64
	MaximumAllocations int64
}

// NewAllocationSafetyCap validates that both counts are non-negative.
func NewAllocationSafetyCap(currentAllocations, maximumAllocations int64) (AllocationSafetyCap, error) {
	if currentAllocations < 0 {
		return AllocationSafetyCap{}, &errs.ArgumentOutOfRangeError{Param: "currentAllocations"}
	}
	if maximumAllocations < 0 {
		return AllocationSafetyCap{}, &errs.ArgumentOutOfRangeError{Param: "maximumAllocations"}
	}
	return AllocationSafetyCap{
		CurrentAllocations: currentAllocations,
		MaximumAllocations: maximumAllocations,
	}, nil
}

// CanAdmit reports whether one more allocation fits under the cap.
func (c AllocationSafetyCap) CanAdmit() bool {
	return c.CurrentAllocations < c.MaximumAllocations
}

// ScoreDimension couples one resource dimension with its caller weight.
type ScoreDimension struct {
	Dimension ResourceDimension
	Weight    int64
}

// NewScoreDimension validates that the weight is non-negative.
func NewScoreDimension(dimension ResourceDimension, weight int64) (ScoreDimension, error) {
	if dimension < ResourceDimensionCpu || dimension > ResourceDimensionHugePages {
		return ScoreDimension{}, &errs.ArgumentOutOfRangeError{Param: "dimension"}
	}
	if weight < 0 {
		return ScoreDimension{}, &errs.ArgumentOutOfRangeError{Param: "weight"}
	}
	return ScoreDimension{Dimension: dimension, Weight: weight}, nil
}

// LeastWastePolicy is the caller-owned least-waste policy. All dimensions must
// appear exactly once; list order is the exact component tie-break order after
// weighted waste.
type LeastWastePolicy struct {
	Dimensions []ScoreDimension
}

// NewLeastWastePolicy validates the closed policy shape.
func NewLeastWastePolicy(dimensions []ScoreDimension) (*LeastWastePolicy, error) {
	copyDimensions, err := schedulerInputSnapshotCopy(
		dimensions,
		SchedulerTechnicalInputLimits.ScoreDimensionCount,
		"dimensions",
		"Score dimension input")
	if err != nil {
		return nil, err
	}
	seen := make(map[ResourceDimension]bool, len(copyDimensions))
	positive := false
	for _, item := range copyDimensions {
		if item.Dimension < ResourceDimensionCpu || item.Dimension > ResourceDimensionHugePages {
			return nil, &errs.ArgumentOutOfRangeError{Param: "dimensions"}
		}
		if item.Weight < 0 {
			return nil, &errs.ArgumentOutOfRangeError{Param: "dimensions"}
		}
		if seen[item.Dimension] {
			return nil, &errs.Argument{
				Param:   "dimensions",
				Message: "Every resource dimension must appear exactly once.",
			}
		}
		seen[item.Dimension] = true
		if item.Weight > 0 {
			positive = true
		}
	}
	if len(seen) != len(AllResourceDimensions) {
		return nil, &errs.Argument{
			Param:   "dimensions",
			Message: "Every resource dimension must appear exactly once.",
		}
	}
	for _, dimension := range AllResourceDimensions {
		if !seen[dimension] {
			return nil, &errs.Argument{
				Param:   "dimensions",
				Message: "Every resource dimension must appear exactly once.",
			}
		}
	}
	if !positive {
		return nil, &errs.Argument{
			Param:   "dimensions",
			Message: "At least one score weight must be positive.",
		}
	}
	return &LeastWastePolicy{Dimensions: copyDimensions}, nil
}

// NodeCandidate describes one schedulable node.
type NodeCandidate struct {
	Id            string
	NodeClass     string
	Architecture  string
	FailureDomain string
	Available     ResourceVector
	OccupiedPorts map[int]struct{}
	Labels        map[string]string
	TrustZones    map[string]struct{}
	NetworkZones  map[string]struct{}
	SecretZones   map[string]struct{}
	AffinityFacts map[string]struct{}
	SafetyCap     *AllocationSafetyCap
	Veto          *CandidateVeto
}

// NewNodeCandidate snapshots and validates every caller input, mirroring the C#
// constructor (optional collections are nil-able).
func NewNodeCandidate(
	id string,
	nodeClass string,
	architecture string,
	failureDomain string,
	available ResourceVector,
	occupiedPorts []int,
	labels map[string]string,
	trustZones []string,
	networkZones []string,
	secretZones []string,
	affinityFacts []string,
	safetyCap *AllocationSafetyCap,
	veto *CandidateVeto,
) (*NodeCandidate, error) {
	var err error
	if _, err := NewResourceVector(
		available.Cpu, available.Memory, available.BlockIo, available.EphemeralDisk,
		available.Bandwidth, available.Pids, available.FileDescriptors, available.HugePages); err != nil {
		return nil, err
	}
	if id, err = requireText(id, "id"); err != nil {
		return nil, err
	}
	if nodeClass, err = requireText(nodeClass, "nodeClass"); err != nil {
		return nil, err
	}
	if architecture, err = requireText(architecture, "architecture"); err != nil {
		return nil, err
	}
	if failureDomain, err = requireText(failureDomain, "failureDomain"); err != nil {
		return nil, err
	}
	ports, err := copyPorts(occupiedPorts, "occupiedPorts")
	if err != nil {
		return nil, err
	}
	labelSnapshot, err := copyLabels(labels, "labels")
	if err != nil {
		return nil, err
	}
	trust, err := copyFacts(trustZones)
	if err != nil {
		return nil, err
	}
	network, err := copyFacts(networkZones)
	if err != nil {
		return nil, err
	}
	secret, err := copyFacts(secretZones)
	if err != nil {
		return nil, err
	}
	affinity, err := copyFacts(affinityFacts)
	if err != nil {
		return nil, err
	}
	var capSnapshot *AllocationSafetyCap
	if safetyCap != nil {
		captured, capErr := NewAllocationSafetyCap(safetyCap.CurrentAllocations, safetyCap.MaximumAllocations)
		if capErr != nil {
			return nil, capErr
		}
		capSnapshot = &captured
	}
	var vetoSnapshot *CandidateVeto
	if veto != nil {
		captured, vetoErr := NewCandidateVeto(veto.Code)
		if vetoErr != nil {
			return nil, vetoErr
		}
		vetoSnapshot = &captured
	}
	return &NodeCandidate{
		Id:            id,
		NodeClass:     nodeClass,
		Architecture:  architecture,
		FailureDomain: failureDomain,
		Available:     available,
		OccupiedPorts: ports,
		Labels:        labelSnapshot,
		TrustZones:    trust,
		NetworkZones:  network,
		SecretZones:   secret,
		AffinityFacts: affinity,
		SafetyCap:     capSnapshot,
		Veto:          vetoSnapshot,
	}, nil
}

// WorkloadRequest describes the workload asking for placement.
type WorkloadRequest struct {
	Id                      string
	Architecture            string
	Resources               ResourceVector
	RequiredPorts           map[int]struct{}
	RequiredNodeClass       *string
	RequiredLabels          map[string]string
	RequiredTrustZones      map[string]struct{}
	RequiredNetworkZones    map[string]struct{}
	RequiredSecretZones     map[string]struct{}
	AllowedFailureDomains   map[string]struct{}
	RequiredAffinityFacts   map[string]struct{}
	ProhibitedAffinityFacts map[string]struct{}
}

// NewWorkloadRequest snapshots and validates every caller input.
func NewWorkloadRequest(
	id string,
	architecture string,
	resources ResourceVector,
	requiredPorts []int,
	requiredNodeClass *string,
	requiredLabels map[string]string,
	requiredTrustZones []string,
	requiredNetworkZones []string,
	requiredSecretZones []string,
	allowedFailureDomains []string,
	requiredAffinityFacts []string,
	prohibitedAffinityFacts []string,
) (*WorkloadRequest, error) {
	var err error
	if _, err := NewResourceVector(
		resources.Cpu, resources.Memory, resources.BlockIo, resources.EphemeralDisk,
		resources.Bandwidth, resources.Pids, resources.FileDescriptors, resources.HugePages); err != nil {
		return nil, err
	}
	if id, err = requireText(id, "id"); err != nil {
		return nil, err
	}
	if architecture, err = requireText(architecture, "architecture"); err != nil {
		return nil, err
	}
	ports, err := copyPorts(requiredPorts, "ports")
	if err != nil {
		return nil, err
	}
	var nodeClass *string
	if requiredNodeClass != nil {
		value, textErr := requireText(*requiredNodeClass, "requiredNodeClass")
		if textErr != nil {
			return nil, textErr
		}
		nodeClass = &value
	}
	labelSnapshot, err := copyLabels(requiredLabels, "labels")
	if err != nil {
		return nil, err
	}
	trust, err := copyFacts(requiredTrustZones)
	if err != nil {
		return nil, err
	}
	network, err := copyFacts(requiredNetworkZones)
	if err != nil {
		return nil, err
	}
	secret, err := copyFacts(requiredSecretZones)
	if err != nil {
		return nil, err
	}
	allowed, err := copyFacts(allowedFailureDomains)
	if err != nil {
		return nil, err
	}
	requiredAffinity, err := copyFacts(requiredAffinityFacts)
	if err != nil {
		return nil, err
	}
	prohibitedAffinity, err := copyFacts(prohibitedAffinityFacts)
	if err != nil {
		return nil, err
	}
	return &WorkloadRequest{
		Id:                      id,
		Architecture:            architecture,
		Resources:               resources,
		RequiredPorts:           ports,
		RequiredNodeClass:       nodeClass,
		RequiredLabels:          labelSnapshot,
		RequiredTrustZones:      trust,
		RequiredNetworkZones:    network,
		RequiredSecretZones:     secret,
		AllowedFailureDomains:   allowed,
		RequiredAffinityFacts:   requiredAffinity,
		ProhibitedAffinityFacts: prohibitedAffinity,
	}, nil
}

// PlacementCheck enumerates every emitted placement check, in trace order.
type PlacementCheck int

const (
	PlacementCheckCallerVeto PlacementCheck = iota
	PlacementCheckArchitecture
	PlacementCheckNodeClass
	PlacementCheckLabels
	PlacementCheckTrustZones
	PlacementCheckNetworkZones
	PlacementCheckSecretZones
	PlacementCheckFailureDomain
	PlacementCheckAffinity
	PlacementCheckAntiAffinity
	PlacementCheckPorts
	PlacementCheckSafetyCap
	PlacementCheckCpu
	PlacementCheckMemory
	PlacementCheckBlockIo
	PlacementCheckEphemeralDisk
	PlacementCheckBandwidth
	PlacementCheckPids
	PlacementCheckFileDescriptors
	PlacementCheckHugePages
	PlacementCheckScore
	PlacementCheckSelection
)

func (c PlacementCheck) String() string {
	names := [...]string{
		"CallerVeto", "Architecture", "NodeClass", "Labels", "TrustZones",
		"NetworkZones", "SecretZones", "FailureDomain", "Affinity", "AntiAffinity",
		"Ports", "SafetyCap", "Cpu", "Memory", "BlockIo", "EphemeralDisk",
		"Bandwidth", "Pids", "FileDescriptors", "HugePages", "Score", "Selection",
	}
	if c >= 0 && int(c) < len(names) {
		return names[c]
	}
	return fmt.Sprintf("PlacementCheck(%d)", int(c))
}

// CheckOutcome is the outcome of one placement check.
type CheckOutcome int

const (
	CheckOutcomePassed CheckOutcome = iota
	CheckOutcomeRejected
	CheckOutcomeNotApplicable
)

func (o CheckOutcome) String() string {
	switch o {
	case CheckOutcomePassed:
		return "Passed"
	case CheckOutcomeRejected:
		return "Rejected"
	case CheckOutcomeNotApplicable:
		return "NotApplicable"
	default:
		return fmt.Sprintf("CheckOutcome(%d)", int(o))
	}
}

// PlacementReason is one typed trace row.
type PlacementReason struct {
	Check   PlacementCheck
	Outcome CheckOutcome
	Detail  string
}

// WasteComponent is one weighted waste term. WeightedWaste mirrors the C#
// System.Numerics.BigInteger product Remaining*Weight.
type WasteComponent struct {
	Dimension     ResourceDimension
	Remaining     int64
	Weight        int64
	WeightedWaste *big.Int
}

// WasteScore is the exact least-waste score of one candidate.
type WasteScore struct {
	WeightedWaste *big.Int
	Remaining     ResourceVector
	Components    []WasteComponent
}

// CandidateTrace is the complete per-candidate trace of one scheduling pass.
type CandidateTrace struct {
	CandidateId string
	Eligible    bool
	Score       *WasteScore
	Reasons     []PlacementReason
}

// ScheduleResult is the closed result vocabulary of the scheduler.
type ScheduleResult interface {
	isScheduleResult()
}

// PlacementSelected is the schedulable outcome.
type PlacementSelected struct {
	WorkloadId          string
	SelectedCandidateId string
	Candidates          []CandidateTrace
}

func (PlacementSelected) isScheduleResult() {}

// Unschedulable is the fail-closed outcome.
type Unschedulable struct {
	WorkloadId string
	Candidates []CandidateTrace
}

func (Unschedulable) isScheduleResult() {}

func copyPorts(ports []int, parameterName string) (map[int]struct{}, error) {
	values, err := schedulerInputSnapshotCopy(ports, SchedulerTechnicalInputLimits.MaximumPortCount, parameterName, "Port input")
	if err != nil {
		return nil, err
	}
	seen := make(map[int]struct{}, len(values))
	for _, port := range values {
		if _, duplicate := seen[port]; duplicate {
			return nil, &errs.Argument{
				Param:   parameterName,
				Message: "Port collections cannot contain duplicates.",
			}
		}
		seen[port] = struct{}{}
	}
	for _, port := range values {
		if port < 1 || port > 65535 {
			return nil, &errs.ArgumentOutOfRangeError{
				Param:   parameterName,
				Message: "Ports must be between 1 and 65535.",
			}
		}
	}
	return seen, nil
}

func copyFacts(facts []string) (map[string]struct{}, error) {
	values, err := schedulerInputSnapshotCopy(facts, SchedulerTechnicalInputLimits.MaximumFactCount, "facts", "Fact input")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(values))
	for _, fact := range values {
		if strings.TrimSpace(fact) == "" {
			return nil, &errs.Argument{
				Param:   "facts",
				Message: "Facts and zone names must be nonempty.",
			}
		}
		if _, duplicate := seen[fact]; duplicate {
			return nil, &errs.Argument{
				Param:   "facts",
				Message: "Facts and zone names cannot contain duplicates.",
			}
		}
		seen[fact] = struct{}{}
	}
	return seen, nil
}

func copyLabels(labels map[string]string, parameterName string) (map[string]string, error) {
	if len(labels) > SchedulerTechnicalInputLimits.MaximumLabelCount {
		return nil, &errs.Argument{
			Param:   parameterName,
			Message: "Label input exceeds the technical snapshot bound.",
		}
	}
	snapshot := make(map[string]string, len(labels))
	for key, value := range labels {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return nil, &errs.Argument{
				Param:   parameterName,
				Message: "Label keys and values must be nonempty.",
			}
		}
		snapshot[key] = value
	}
	return snapshot, nil
}

func requireText(value string, parameterName string) (string, error) {
	if strings.TrimSpace(value) != "" {
		return value, nil
	}
	return "", &errs.Argument{
		Param:   parameterName,
		Message: "A nonempty value is required.",
	}
}

// checkedAdd mirrors C# checked integer addition.
func checkedAdd(left, right int64) (int64, error) {
	sum := left + right
	if (sum > left) == (right > 0) {
		return sum, nil
	}
	return 0, &OverflowError{Message: "Arithmetic operation resulted in an overflow."}
}

// checkedSubtract mirrors C# checked integer subtraction.
func checkedSubtract(left, right int64) (int64, error) {
	difference := left - right
	if (difference < left) == (right > 0) {
		return difference, nil
	}
	return 0, &OverflowError{Message: "Arithmetic operation resulted in an overflow."}
}
