// This file ports tests/TerraScale.Orchestrator.Scheduler.Tests/Properties/
// DeterministicPropertyData.cs (the shared property-test generators, oracle and
// serialization helpers). .NET-only concerns (CultureInfo, throwing iterators)
// have no Go equivalent and are not ported.
package scheduling

import (
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

const propertyFeatureCases = 1_000

type deterministicSequence struct {
	state uint64
}

func newDeterministicSequence(seed uint64) *deterministicSequence {
	return &deterministicSequence{state: seed}
}

func (s *deterministicSequence) Next() uint64 {
	s.state += 0x9E3779B97F4A7C15
	value := s.state
	value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9
	value = (value ^ (value >> 27)) * 0x94D049BB133111EB
	return value ^ (value >> 31)
}

func (s *deterministicSequence) Int(minimumInclusive, maximumExclusive int) int {
	return minimumInclusive + int(s.Next()%uint64(maximumExclusive-minimumInclusive))
}

func (s *deterministicSequence) Long(minimumInclusive, maximumExclusive int64) int64 {
	return minimumInclusive + int64(s.Next()%uint64(maximumExclusive-minimumInclusive))
}

type schedulerViolation int

const (
	violationArchitecture schedulerViolation = iota
	violationNodeClass
	violationLabels
	violationTrustZone
	violationNetworkZone
	violationSecretZone
	violationFailureDomain
	violationAffinity
	violationAntiAffinity
	violationPort
	violationSafetyCap
	violationVeto
	violationCapacity
)

var allSchedulerViolations = []schedulerViolation{
	violationArchitecture, violationNodeClass, violationLabels, violationTrustZone,
	violationNetworkZone, violationSecretZone, violationFailureDomain, violationAffinity,
	violationAntiAffinity, violationPort, violationSafetyCap, violationVeto, violationCapacity,
}

type schedulerValidatorFamily int

const (
	familyNegativeResource schedulerValidatorFamily = iota
	familyAdditionOverflow
	familySubtractionUnderflow
	familyUnknownVeto
	familyNegativeSafetyCap
	familyNegativeScoreWeight
	familyDuplicateScoreDimension
	familyZeroScorePolicy
	familyNodeIdentity
	familyNodePorts
	familyNodeFacts
	familyNodeLabels
	familyWorkloadIdentity
	familyWorkloadPorts
	familyWorkloadFacts
	familyDuplicateCandidate
	familyNullCandidate
	familyUnknownScoreDimension
	familyWorkloadLabels
	familyNullScheduleInput
)

var allSchedulerValidatorFamilies = []schedulerValidatorFamily{
	familyNegativeResource, familyAdditionOverflow, familySubtractionUnderflow,
	familyUnknownVeto, familyNegativeSafetyCap, familyNegativeScoreWeight,
	familyDuplicateScoreDimension, familyZeroScorePolicy, familyNodeIdentity,
	familyNodePorts, familyNodeFacts, familyNodeLabels, familyWorkloadIdentity,
	familyWorkloadPorts, familyWorkloadFacts, familyDuplicateCandidate,
	familyNullCandidate, familyUnknownScoreDimension, familyWorkloadLabels,
	familyNullScheduleInput,
}

type availabilityValidatorFamily int

const (
	familyCountOverflow availabilityValidatorFamily = iota
	familyCountUnderflow
	familyIdentity
	familyPolicyRelation
	familyPolicyEnum
	familyObservationEnum
	familyRequestPolicyNull
	familyRequestChangeNull
	familyRequestEnum
	familyRequestObservationNull
	familyEvaluatorNull
)

var allAvailabilityValidatorFamilies = []availabilityValidatorFamily{
	familyCountOverflow, familyCountUnderflow, familyIdentity, familyPolicyRelation,
	familyPolicyEnum, familyObservationEnum, familyRequestPolicyNull,
	familyRequestChangeNull, familyRequestEnum, familyRequestObservationNull,
	familyEvaluatorNull,
}

type schedulerPropertyCase struct {
	Seed       uint64
	Workload   *WorkloadRequest
	Candidates []*NodeCandidate
	Policy     *LeastWastePolicy
}

func ptr(value string) *string { return &value }

func schedulerPropertyValid(seed uint64) (*schedulerPropertyCase, error) {
	sequence := newDeterministicSequence(seed)
	requested, err := propertyVector(sequence, 1, 40)
	if err != nil {
		return nil, err
	}
	policy, err := propertyPolicy(sequence)
	if err != nil {
		return nil, err
	}
	count := sequence.Int(2, 6)
	candidates := make([]*NodeCandidate, 0, count)
	for index := 0; index < count; index++ {
		candidate, candidateErr := propertyCandidate(fmt.Sprintf("node-%02d", index), index, requested, sequence, nil)
		if candidateErr != nil {
			return nil, candidateErr
		}
		candidates = append(candidates, candidate)
	}
	workload, err := NewWorkloadRequest(
		fmt.Sprintf("workload-%d", seed), "linux-amd64", requested,
		[]int{8080}, ptr("compute"), map[string]string{"region": "gru"},
		[]string{"trusted"}, []string{"product"}, []string{"runtime"},
		[]string{"fd-a", "fd-b", "fd-c"}, []string{"service"}, []string{"noisy"})
	if err != nil {
		return nil, err
	}
	return &schedulerPropertyCase{Seed: seed, Workload: workload, Candidates: candidates, Policy: policy}, nil
}

type schedulerInvalidProperty struct {
	Case      *schedulerPropertyCase
	Violation schedulerViolation
	Check     PlacementCheck
}

func schedulerPropertyInvalid(seed uint64) (*schedulerInvalidProperty, error) {
	valid, err := schedulerPropertyValid(seed)
	if err != nil {
		return nil, err
	}
	sequence := newDeterministicSequence(seed ^ 0xD1B54A32D192ED03)
	violation := allSchedulerViolations[sequence.Int(0, len(allSchedulerViolations))]
	candidate, err := invalidCandidate("invalid", valid.Workload.Resources, violation, int(seed%8))
	if err != nil {
		return nil, err
	}
	return &schedulerInvalidProperty{
		Case:      &schedulerPropertyCase{Seed: seed, Workload: valid.Workload, Candidates: []*NodeCandidate{candidate}, Policy: valid.Policy},
		Violation: violation,
		Check:     violationToCheck(violation, seed),
	}, nil
}

func schedulerPropertyCapacityInvalid(seed uint64) (*schedulerInvalidProperty, error) {
	valid, err := schedulerPropertyValid(seed)
	if err != nil {
		return nil, err
	}
	dimension := int(seed % 8)
	candidate, err := invalidCandidate("invalid", valid.Workload.Resources, violationCapacity, dimension)
	if err != nil {
		return nil, err
	}
	return &schedulerInvalidProperty{
		Case:      &schedulerPropertyCase{Seed: seed, Workload: valid.Workload, Candidates: []*NodeCandidate{candidate}, Policy: valid.Policy},
		Violation: violationCapacity,
		Check:     PlacementCheck(int(PlacementCheckCpu) + dimension),
	}, nil
}

func schedulerPropertyVetoed(workload *WorkloadRequest, code CandidateVetoCode) (*NodeCandidate, error) {
	available, err := propertyAdd(workload.Resources, 20)
	if err != nil {
		return nil, err
	}
	cap := AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 100}
	veto := CandidateVeto{Code: code}
	return NewNodeCandidate("vetoed", "compute", "linux-amd64", "fd-a", available, []int{},
		map[string]string{"region": "gru"}, []string{"trusted"}, []string{"product"},
		[]string{"runtime"}, []string{"service"}, &cap, &veto)
}

func schedulerPropertyTiedCandidates(workload *WorkloadRequest) ([]*NodeCandidate, error) {
	available, err := propertyAdd(workload.Resources, 10)
	if err != nil {
		return nil, err
	}
	first, err := candidateWithAvailable("node-z", available)
	if err != nil {
		return nil, err
	}
	second, err := candidateWithAvailable("node-a", available)
	if err != nil {
		return nil, err
	}
	return []*NodeCandidate{first, second}, nil
}

func throwsArgument(action func()) bool {
	result := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = true
			}
		}()
		action()
	}()
	return result
}

// invalidValidator ports SchedulerPropertyGenerator.InvalidValidator. The
// null-candidate/null-input families are represented with nil pointers and nil
// slice elements, which Go can express.
func schedulerPropertyInvalidValidator(seed uint64) (schedulerValidatorFamily, bool, error) {
	family := allSchedulerValidatorFamilies[seed%uint64(len(allSchedulerValidatorFamilies))]
	variant := seed / uint64(len(allSchedulerValidatorFamilies))
	property, err := schedulerPropertyValid(seed)
	if err != nil {
		return family, false, err
	}
	scheduler := DeterministicScheduler{}
	threw := false
	rejected := false
	switch family {
	case familyNegativeResource:
		_, threw = propertyWithOneDimensionErr(ResourceVectorZero, int(variant%8), -1)
		rejected = threw
	case familyAdditionOverflow:
		maximum := ResourceVector{Cpu: int64(^uint64(0) >> 1)}
		_, err := maximum.AddChecked(ResourceVector{Cpu: 1})
		rejected = err != nil
	case familySubtractionUnderflow:
		_, err := ResourceVectorZero.SubtractChecked(ResourceVector{Cpu: 1})
		rejected = err != nil
	case familyUnknownVeto:
		_, err := NewCandidateVeto(CandidateVetoCode(99))
		rejected = err != nil
	case familyNegativeSafetyCap:
		if variant%2 == 0 {
			_, err := NewAllocationSafetyCap(-1, 1)
			rejected = err != nil
		} else {
			_, err := NewAllocationSafetyCap(0, -1)
			rejected = err != nil
		}
	case familyNegativeScoreWeight:
		_, err := NewScoreDimension(ResourceDimensionCpu, -1)
		rejected = err != nil
	case familyDuplicateScoreDimension:
		dimensions := make([]ScoreDimension, len(AllResourceDimensions))
		for index := range dimensions {
			dimensions[index] = ScoreDimension{Dimension: ResourceDimensionCpu, Weight: 1}
		}
		_, err := NewLeastWastePolicy(dimensions)
		rejected = err != nil
	case familyZeroScorePolicy:
		dimensions := make([]ScoreDimension, len(AllResourceDimensions))
		for index, dimension := range AllResourceDimensions {
			dimensions[index] = ScoreDimension{Dimension: dimension, Weight: 0}
		}
		_, err := NewLeastWastePolicy(dimensions)
		rejected = err != nil
	case familyNodeIdentity:
		blank := " "
		switch variant % 4 {
		case 0:
			_, err := NewNodeCandidate(blank, "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		case 1:
			_, err := NewNodeCandidate("node", blank, "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		case 2:
			_, err := NewNodeCandidate("node", "compute", blank, "fd-a", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		default:
			_, err := NewNodeCandidate("node", "compute", "linux-amd64", blank, property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		}
	case familyNodePorts:
		var ports []int
		if variant%2 == 0 {
			ports = []int{80, 80}
		} else {
			ports = []int{0}
		}
		_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, ports, nil, nil, nil, nil, nil, nil, nil)
		rejected = err != nil
	case familyNodeFacts:
		switch variant % 4 {
		case 0:
			_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, []string{"zone", "zone"}, nil, nil, nil, nil, nil)
			rejected = err != nil
		case 1:
			_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, nil, []string{""}, nil, nil, nil, nil)
			rejected = err != nil
		case 2:
			_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, nil, nil, []string{"zone", "zone"}, nil, nil, nil)
			rejected = err != nil
		default:
			_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, nil, nil, nil, nil, []string{""}, nil, nil)
			rejected = err != nil
		}
	case familyNodeLabels:
		_, err := NewNodeCandidate("node", "compute", "linux-amd64", "fd-a", property.Workload.Resources, nil, map[string]string{"": "value"}, nil, nil, nil, nil, nil, nil)
		rejected = err != nil
	case familyWorkloadIdentity:
		switch variant % 3 {
		case 0:
			_, err := NewWorkloadRequest(" ", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		case 1:
			_, err := NewWorkloadRequest("workload", " ", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		default:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, ptr(""), nil, nil, nil, nil, nil, nil, nil)
			rejected = err != nil
		}
	case familyWorkloadPorts:
		var ports []int
		if variant%2 == 0 {
			ports = []int{65_536}
		} else {
			ports = []int{80, 80}
		}
		_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, ports, nil, nil, nil, nil, nil, nil, nil, nil)
		rejected = err != nil
	case familyWorkloadFacts:
		switch variant % 6 {
		case 0:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, []string{"zone", "zone"}, nil, nil, nil, nil, nil)
			rejected = err != nil
		case 1:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, []string{""}, nil, nil, nil, nil)
			rejected = err != nil
		case 2:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, nil, []string{"zone", "zone"}, nil, nil, nil)
			rejected = err != nil
		case 3:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, nil, nil, []string{""}, nil, nil)
			rejected = err != nil
		case 4:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, []string{"a", "a"}, nil)
			rejected = err != nil
		default:
			_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, nil, nil, nil, nil, nil, nil, []string{""})
			rejected = err != nil
		}
	case familyDuplicateCandidate:
		_, err := scheduler.Schedule(property.Workload, []*NodeCandidate{property.Candidates[0], property.Candidates[0]}, property.Policy)
		rejected = err != nil
	case familyNullCandidate:
		_, err := scheduler.Schedule(property.Workload, []*NodeCandidate{nil}, property.Policy)
		rejected = err != nil
	case familyUnknownScoreDimension:
		dimensions := make([]ScoreDimension, 0, len(AllResourceDimensions))
		for _, dimension := range AllResourceDimensions[1:] {
			dimensions = append(dimensions, ScoreDimension{Dimension: dimension, Weight: 1})
		}
		dimensions = append(dimensions, ScoreDimension{Dimension: ResourceDimension(99), Weight: 1})
		_, err := NewLeastWastePolicy(dimensions)
		rejected = err != nil
	case familyWorkloadLabels:
		_, err := NewWorkloadRequest("workload", "linux-amd64", property.Workload.Resources, nil, nil, map[string]string{"key": ""}, nil, nil, nil, nil, nil, nil)
		rejected = err != nil
	case familyNullScheduleInput:
		switch variant % 3 {
		case 0:
			_, err := scheduler.Schedule(nil, property.Candidates, property.Policy)
			rejected = err != nil
		case 1:
			_, err := scheduler.Schedule(property.Workload, nil, property.Policy)
			rejected = err != nil
		default:
			_, err := scheduler.Schedule(property.Workload, property.Candidates, nil)
			rejected = err != nil
		}
	}
	return family, rejected, nil
}

func invalidCandidate(id string, requested ResourceVector, violation schedulerViolation, capacityDimension int) (*NodeCandidate, error) {
	var available ResourceVector
	if violation == violationCapacity {
		available = propertyWithOneDimension(requested, capacityDimension, -1)
	} else {
		var err error
		available, err = propertyAdd(requested, 20)
		if err != nil {
			return nil, err
		}
	}
	nodeClass := "compute"
	if violation == violationNodeClass {
		nodeClass = "storage"
	}
	architecture := "linux-amd64"
	if violation == violationArchitecture {
		architecture = "linux-arm64"
	}
	failureDomain := "fd-a"
	if violation == violationFailureDomain {
		failureDomain = "fd-z"
	}
	var ports []int
	if violation == violationPort {
		ports = []int{8080}
	}
	labels := map[string]string{"region": "gru"}
	if violation == violationLabels {
		labels = map[string]string{"region": "sfo"}
	}
	var trustZones []string = []string{"trusted"}
	if violation == violationTrustZone {
		trustZones = []string{}
	}
	var networkZones []string = []string{"product"}
	if violation == violationNetworkZone {
		networkZones = []string{}
	}
	var secretZones []string = []string{"runtime"}
	if violation == violationSecretZone {
		secretZones = []string{}
	}
	var affinityFacts []string = []string{"service"}
	switch violation {
	case violationAffinity:
		affinityFacts = []string{}
	case violationAntiAffinity:
		affinityFacts = []string{"service", "noisy"}
	}
	var cap *AllocationSafetyCap
	if violation == violationSafetyCap {
		cap = &AllocationSafetyCap{CurrentAllocations: 1, MaximumAllocations: 1}
	} else {
		cap = &AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 10}
	}
	var veto *CandidateVeto
	if violation == violationVeto {
		veto = &CandidateVeto{Code: CandidateVetoCodeControllerHold}
	}
	return NewNodeCandidate(id, nodeClass, architecture, failureDomain, available,
		ports, labels, trustZones, networkZones, secretZones, affinityFacts, cap, veto)
}

func propertyCandidate(id string, index int, requested ResourceVector, sequence *deterministicSequence, veto *CandidateVeto) (*NodeCandidate, error) {
	available, err := propertyAddRandom(requested, sequence)
	if err != nil {
		return nil, err
	}
	cap := AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 100}
	return NewNodeCandidate(id, "compute", "linux-amd64",
		fmt.Sprintf("fd-%c", rune('a'+index%3)), available, []int{},
		map[string]string{"region": "gru"}, []string{"trusted"}, []string{"product"},
		[]string{"runtime"}, []string{"service"}, &cap, veto)
}

func candidateWithAvailable(id string, available ResourceVector) (*NodeCandidate, error) {
	cap := AllocationSafetyCap{CurrentAllocations: 0, MaximumAllocations: 100}
	return NewNodeCandidate(id, "compute", "linux-amd64", "fd-a", available, []int{},
		map[string]string{"region": "gru"}, []string{"trusted"}, []string{"product"},
		[]string{"runtime"}, []string{"service"}, &cap, nil)
}

func propertyPolicy(sequence *deterministicSequence) (*LeastWastePolicy, error) {
	offset := sequence.Int(0, len(AllResourceDimensions))
	ordered := append(append([]ResourceDimension{}, AllResourceDimensions[offset:]...), AllResourceDimensions[:offset]...)
	scores := make([]ScoreDimension, 0, len(ordered))
	for _, dimension := range ordered {
		weight := sequence.Long(1, 6)
		scores = append(scores, ScoreDimension{Dimension: dimension, Weight: weight})
	}
	return NewLeastWastePolicy(scores)
}

func propertyVector(sequence *deterministicSequence, minimum, maximum int64) (ResourceVector, error) {
	values := make([]int64, 8)
	for index := range values {
		values[index] = sequence.Long(minimum, maximum)
	}
	return NewResourceVector(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7])
}

func propertyAdd(value ResourceVector, amount int64) (ResourceVector, error) {
	return value.AddChecked(ResourceVector{
		Cpu: amount, Memory: amount, BlockIo: amount, EphemeralDisk: amount,
		Bandwidth: amount, Pids: amount, FileDescriptors: amount, HugePages: amount,
	})
}

func propertyAddRandom(value ResourceVector, sequence *deterministicSequence) (ResourceVector, error) {
	result := value
	for index := 0; index < 8; index++ {
		amount := sequence.Long(0, 31)
		dimension := int64(0)
		switch index {
		case 0:
			dimension = result.Cpu
		case 1:
			dimension = result.Memory
		case 2:
			dimension = result.BlockIo
		case 3:
			dimension = result.EphemeralDisk
		case 4:
			dimension = result.Bandwidth
		case 5:
			dimension = result.Pids
		case 6:
			dimension = result.FileDescriptors
		case 7:
			dimension = result.HugePages
		}
		// propertyAdd mirrors checked addition; emulate per-dimension addition.
		sum, addErr := checkedAdd(dimension, amount)
		if addErr != nil {
			return ResourceVector{}, addErr
		}
		switch index {
		case 0:
			result.Cpu = sum
		case 1:
			result.Memory = sum
		case 2:
			result.BlockIo = sum
		case 3:
			result.EphemeralDisk = sum
		case 4:
			result.Bandwidth = sum
		case 5:
			result.Pids = sum
		case 6:
			result.FileDescriptors = sum
		case 7:
			result.HugePages = sum
		}
	}
	return result, nil
}

// propertyWithOneDimension returns a vector with one dimension shifted by delta
// (unchecked: the shifted value may be invalid on purpose).
func propertyWithOneDimension(value ResourceVector, index int, delta int64) ResourceVector {
	result := value
	switch index {
	case 0:
		result.Cpu += delta
	case 1:
		result.Memory += delta
	case 2:
		result.BlockIo += delta
	case 3:
		result.EphemeralDisk += delta
	case 4:
		result.Bandwidth += delta
	case 5:
		result.Pids += delta
	case 6:
		result.FileDescriptors += delta
	case 7:
		result.HugePages += delta
	}
	return result
}

func propertyWithOneDimensionErr(value ResourceVector, index int, delta int64) (ResourceVector, bool) {
	result := propertyWithOneDimension(value, index, delta)
	_, err := NewResourceVector(result.Cpu, result.Memory, result.BlockIo, result.EphemeralDisk,
		result.Bandwidth, result.Pids, result.FileDescriptors, result.HugePages)
	return result, err != nil
}

func violationToCheck(violation schedulerViolation, seed uint64) PlacementCheck {
	switch violation {
	case violationArchitecture:
		return PlacementCheckArchitecture
	case violationNodeClass:
		return PlacementCheckNodeClass
	case violationLabels:
		return PlacementCheckLabels
	case violationTrustZone:
		return PlacementCheckTrustZones
	case violationNetworkZone:
		return PlacementCheckNetworkZones
	case violationSecretZone:
		return PlacementCheckSecretZones
	case violationFailureDomain:
		return PlacementCheckFailureDomain
	case violationAffinity:
		return PlacementCheckAffinity
	case violationAntiAffinity:
		return PlacementCheckAntiAffinity
	case violationPort:
		return PlacementCheckPorts
	case violationSafetyCap:
		return PlacementCheckSafetyCap
	case violationVeto:
		return PlacementCheckCallerVeto
	case violationCapacity:
		return PlacementCheck(int(PlacementCheckCpu) + int(seed%8))
	default:
		panic("violation out of range")
	}
}

type availabilityPropertyCase struct {
	Seed         uint64
	Policy       *ServiceAvailabilityPolicy
	Observations []ReplicaObservation
	Maintenance  MaintainReplicaChange
}

var availabilityPropertyService = mustServiceId("scheduler-service")

func mustServiceId(value string) ServiceId {
	id, err := NewServiceId(value)
	if err != nil {
		panic(err)
	}
	return id
}

func availabilityPropertyMaintenance(seed uint64) (*availabilityPropertyCase, error) {
	sequence := newDeterministicSequence(seed)
	count := sequence.Int(2, 9)
	observations := make([]ReplicaObservation, 0, count)
	for index := 0; index < count; index++ {
		observation, err := availabilityPropertyObservation(index, index, ReplicaAvailabilityStateAvailable)
		if err != nil {
			return nil, err
		}
		observations = append(observations, observation)
	}
	policy, err := availabilityPropertyPolicy(
		uint64(count), uint64(count-1), uint64(count-1), 1, uint64(count-1), true, ResourceVectorZero)
	if err != nil {
		return nil, err
	}
	replicaZero, err := NewReplicaId("replica-0")
	if err != nil {
		return nil, err
	}
	return &availabilityPropertyCase{
		Seed:         seed,
		Policy:       policy,
		Observations: observations,
		Maintenance:  MaintainReplicaChange{ReplicaId: replicaZero},
	}, nil
}

func availabilityPropertyPolicy(
	desired, minimum, quorum, disruptions, domains uint64,
	onePerHost bool,
	reserve ResourceVector,
) (*ServiceAvailabilityPolicy, error) {
	return NewServiceAvailabilityPolicy(
		availabilityPropertyService,
		NewAvailabilityCount(desired),
		NewAvailabilityCount(minimum),
		NewAvailabilityCount(quorum),
		NewAvailabilityCount(disruptions),
		ServiceCriticalityCritical,
		onePerHost,
		NewAvailabilityCount(domains),
		reserve,
		ReserveDispositionPreserve)
}

func availabilityPropertyObservation(replica, node int, state ReplicaAvailabilityState) (ReplicaObservation, error) {
	replicaId, err := NewReplicaId(fmt.Sprintf("replica-%d", replica))
	if err != nil {
		return ReplicaObservation{}, err
	}
	nodeId, err := NewAvailabilityNodeId(fmt.Sprintf("node-%d", node))
	if err != nil {
		return ReplicaObservation{}, err
	}
	domainId, err := NewFailureDomainId(fmt.Sprintf("fd-%d", node))
	if err != nil {
		return ReplicaObservation{}, err
	}
	return NewReplicaObservation(replicaId, availabilityPropertyService, &nodeId, &domainId, state)
}

func availabilityPropertyInvalidValidator(seed uint64) (availabilityValidatorFamily, bool, error) {
	family := allAvailabilityValidatorFamilies[seed%uint64(len(allAvailabilityValidatorFamilies))]
	variant := seed / uint64(len(allAvailabilityValidatorFamilies))
	policy, err := availabilityPropertyPolicy(1, 1, 1, 0, 1, true, ResourceVectorZero)
	if err != nil {
		return family, false, err
	}
	observation, err := availabilityPropertyObservation(0, 0, ReplicaAvailabilityStateAvailable)
	if err != nil {
		return family, false, err
	}
	change := MaintainReplicaChange{ReplicaId: observation.ReplicaId}
	generation, err := NewAvailabilityGeneration(1)
	if err != nil {
		return family, false, err
	}
	rejected := false
	switch family {
	case familyCountOverflow:
		_, err := NewAvailabilityCount(^uint64(0)).AddChecked(NewAvailabilityCount(1))
		rejected = err != nil
	case familyCountUnderflow:
		_, err := NewAvailabilityCount(0).SubtractChecked(NewAvailabilityCount(1))
		rejected = err != nil
	case familyIdentity:
		switch variant % 4 {
		case 0:
			_, err := NewReplicaId("Not Canonical")
			rejected = err != nil
		case 1:
			_, err := NewServiceId("")
			rejected = err != nil
		case 2:
			_, err := NewAvailabilityNodeId("UPPER")
			rejected = err != nil
		default:
			_, err := NewFailureDomainId("bad_value")
			rejected = err != nil
		}
	case familyPolicyRelation:
		_, err := availabilityPropertyPolicy(1, 2, 1, 0, 1, true, ResourceVectorZero)
		rejected = err != nil
	case familyPolicyEnum:
		if variant%2 == 0 {
			_, err := NewServiceAvailabilityPolicy(
				availabilityPropertyService, NewAvailabilityCount(1), NewAvailabilityCount(1),
				NewAvailabilityCount(1), NewAvailabilityCount(0), ServiceCriticality(99), true,
				NewAvailabilityCount(1), ResourceVectorZero, ReserveDispositionPreserve)
			rejected = err != nil
		} else {
			_, err := NewServiceAvailabilityPolicy(
				availabilityPropertyService, NewAvailabilityCount(1), NewAvailabilityCount(1),
				NewAvailabilityCount(1), NewAvailabilityCount(0), ServiceCriticalityCritical, true,
				NewAvailabilityCount(1), ResourceVectorZero, ReserveDisposition(99))
			rejected = err != nil
		}
	case familyObservationEnum:
		_, err := NewReplicaObservation(observation.ReplicaId, observation.ServiceId,
			observation.NodeId, observation.FailureDomainId, ReplicaAvailabilityState(99))
		rejected = err != nil
	case familyRequestPolicyNull:
		_, err := NewAvailabilityEvaluationRequest(nil, change,
			ObservationCompletenessComplete, generation, generation,
			[]ReplicaObservation{observation})
		rejected = err != nil
	case familyRequestChangeNull:
		_, err := NewAvailabilityEvaluationRequest(policy, nil,
			ObservationCompletenessComplete, generation, generation,
			[]ReplicaObservation{observation})
		rejected = err != nil
	case familyRequestEnum:
		_, err := NewAvailabilityEvaluationRequest(policy, change,
			ObservationCompleteness(99), generation, generation,
			[]ReplicaObservation{observation})
		rejected = err != nil
	case familyRequestObservationNull:
		_, err := NewAvailabilityEvaluationRequest(policy, change,
			ObservationCompletenessComplete, generation, generation, nil)
		rejected = err != nil
	case familyEvaluatorNull:
		rejected = throwsArgument(func() {
			_ = AvailabilityPolicyEvaluator{}.Evaluate(nil)
		})
	}
	return family, rejected, nil
}

func propertySerializeSchedule(result ScheduleResult) string {
	switch typed := result.(type) {
	case PlacementSelected:
		return fmt.Sprintf("selected:%s:%s:%s", typed.WorkloadId, typed.SelectedCandidateId,
			propertySerializeCandidates(typed.Candidates))
	case Unschedulable:
		return fmt.Sprintf("unschedulable:%s:%s", typed.WorkloadId,
			propertySerializeCandidates(typed.Candidates))
	default:
		panic("result out of range")
	}
}

func propertySerializeCandidates(candidates []CandidateTrace) string {
	texts := make([]string, len(candidates))
	for index, candidate := range candidates {
		waste := "-"
		if candidate.Score != nil {
			waste = candidate.Score.WeightedWaste.String()
		}
		reasons := make([]string, len(candidate.Reasons))
		for reasonIndex, reason := range candidate.Reasons {
			reasons[reasonIndex] = fmt.Sprintf("%d:%d:%s",
				int(reason.Check), int(reason.Outcome), reason.Detail)
		}
		texts[index] = fmt.Sprintf("%s:%t:%s:%s", candidate.CandidateId, candidate.Eligible,
			waste, strings.Join(reasons, ","))
	}
	return strings.Join(texts, "|")
}

func propertySerializeAvailability(decision AvailabilityDecision) string {
	rows := make([]string, len(decision.Trace))
	for index, reason := range decision.Trace {
		rows[index] = fmt.Sprintf("%d:%d:%d:%d",
			int(reason.Code), int(reason.Outcome), reason.Observed, reason.Required)
	}
	return fmt.Sprintf("%t|%s", decision.Admitted(), strings.Join(rows, ";"))
}

type oraclePlacement struct {
	CandidateId      string
	WeightedWaste    *big.Int
	OrderedRemaining []int64
}

func oracleSelect(property *schedulerPropertyCase) oraclePlacement {
	scores := make([]oraclePlacement, 0, len(property.Candidates))
	for _, candidate := range property.Candidates {
		scores = append(scores, oracleScore(candidate, property.Workload, property.Policy))
	}
	best := scores[0]
	for _, score := range scores[1:] {
		if oracleCompare(score, best) < 0 {
			best = score
		}
	}
	return best
}

func oracleHasCrossDimensionTradeoff(property *schedulerPropertyCase) bool {
	remaining := make([][]int64, len(property.Candidates))
	for index, candidate := range property.Candidates {
		remaining[index] = oracleNaturalRemaining(candidate, property.Workload)
	}
	for left := 0; left < len(remaining); left++ {
		for right := left + 1; right < len(remaining); right++ {
			hasLess, hasMore := false, false
			for dimension := 0; dimension < 8; dimension++ {
				if remaining[left][dimension] < remaining[right][dimension] {
					hasLess = true
				}
				if remaining[left][dimension] > remaining[right][dimension] {
					hasMore = true
				}
			}
			if hasLess && hasMore {
				return true
			}
		}
	}
	return false
}

func oracleValues(value ResourceVector) []int64 {
	return []int64{value.Cpu, value.Memory, value.BlockIo, value.EphemeralDisk,
		value.Bandwidth, value.Pids, value.FileDescriptors, value.HugePages}
}

func oracleNaturalRemaining(candidate *NodeCandidate, workload *WorkloadRequest) []int64 {
	available := oracleValues(candidate.Available)
	requested := oracleValues(workload.Resources)
	remaining := make([]int64, len(available))
	for index := range available {
		difference := new(big.Int).Sub(big.NewInt(available[index]), big.NewInt(requested[index]))
		if !difference.IsInt64() {
			panic("Oracle remainder is not representable.")
		}
		remaining[index] = difference.Int64()
	}
	return remaining
}

func oracleScore(candidate *NodeCandidate, workload *WorkloadRequest, policy *LeastWastePolicy) oraclePlacement {
	natural := oracleNaturalRemaining(candidate, workload)
	byDimension := map[ResourceDimension]int64{
		ResourceDimensionCpu:             natural[0],
		ResourceDimensionMemory:          natural[1],
		ResourceDimensionBlockIo:         natural[2],
		ResourceDimensionEphemeralDisk:   natural[3],
		ResourceDimensionBandwidth:       natural[4],
		ResourceDimensionPids:            natural[5],
		ResourceDimensionFileDescriptors: natural[6],
		ResourceDimensionHugePages:       natural[7],
	}
	ordered := make([]int64, len(policy.Dimensions))
	total := new(big.Int)
	for index, dimension := range policy.Dimensions {
		ordered[index] = byDimension[dimension.Dimension]
		total.Add(total, new(big.Int).Mul(big.NewInt(ordered[index]), big.NewInt(dimension.Weight)))
	}
	return oraclePlacement{CandidateId: candidate.Id, WeightedWaste: total, OrderedRemaining: ordered}
}

func oracleCompare(left, right oraclePlacement) int {
	comparison := left.WeightedWaste.Cmp(right.WeightedWaste)
	if comparison != 0 {
		return comparison
	}
	for index := range left.OrderedRemaining {
		switch {
		case left.OrderedRemaining[index] < right.OrderedRemaining[index]:
			return -1
		case left.OrderedRemaining[index] > right.OrderedRemaining[index]:
			return 1
		}
	}
	return strings.Compare(left.CandidateId, right.CandidateId)
}

func sortedCopy(values []string) []string {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	return sorted
}

func formatUint(value uint64) string { return strconv.FormatUint(value, 10) }
