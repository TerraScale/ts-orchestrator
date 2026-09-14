package scheduling

import (
	"math/big"
	"strings"
	"testing"
)

func propertyReverse[T any](values []T) []T {
	reversed := make([]T, len(values))
	for index, value := range values {
		reversed[len(values)-1-index] = value
	}
	return reversed
}

func propertyRotate[T any](values []T) []T {
	rotated := make([]T, len(values))
	if len(values) > 0 {
		copy(rotated, values[1:])
		rotated[len(values)-1] = values[0]
	}
	return rotated
}

func TestValidCasesAreDeterministicAndPermutationInvariantForOneThousandExplicitSeeds(t *testing.T) {
	scheduler := DeterministicScheduler{}
	for seed := uint64(1); seed <= propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		baseline, err := scheduler.Schedule(property.Workload, property.Candidates, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		serialized := propertySerializeSchedule(baseline)
		for _, candidates := range [][]*NodeCandidate{
			propertyReverse(property.Candidates),
			propertyRotate(property.Candidates),
		} {
			result, err := scheduler.Schedule(property.Workload, candidates, property.Policy)
			if err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			if propertySerializeSchedule(result) != serialized {
				t.Fatalf("seed %d: permutation changed the serialized schedule", seed)
			}
		}
	}
}

func TestSelectedCandidatesConserveEveryResourceAndNeverExceedCapacity(t *testing.T) {
	scheduler := DeterministicScheduler{}
	for seed := uint64(10_001); seed < 10_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		result, err := scheduler.Schedule(property.Workload, property.Candidates, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		selected, ok := result.(PlacementSelected)
		if !ok {
			t.Fatalf("seed %d: expected PlacementSelected", seed)
		}
		oracle := oracleSelect(property)
		if selected.SelectedCandidateId != oracle.CandidateId {
			t.Fatalf("seed %d: oracle mismatch: got %s want %s",
				seed, selected.SelectedCandidateId, oracle.CandidateId)
		}
		var candidate *NodeCandidate
		for _, item := range property.Candidates {
			if item.Id == selected.SelectedCandidateId {
				candidate = item
			}
		}
		var trace *CandidateTrace
		for index := range selected.Candidates {
			if selected.Candidates[index].CandidateId == selected.SelectedCandidateId {
				trace = &selected.Candidates[index]
			}
		}
		expected := oracleNaturalRemaining(candidate, property.Workload)
		values := oracleValues(trace.Score.Remaining)
		for index := range expected {
			if values[index] != expected[index] {
				t.Fatalf("seed %d: remaining mismatch at %d", seed, index)
			}
		}
		if trace.Score.WeightedWaste.Cmp(oracle.WeightedWaste) != 0 {
			t.Fatalf("seed %d: weighted waste mismatch", seed)
		}
		for index, component := range trace.Score.Components {
			if component.Remaining != oracle.OrderedRemaining[index] {
				t.Fatalf("seed %d: component remaining mismatch at %d", seed, index)
			}
			if component.Remaining < 0 || component.WeightedWaste.Cmp(
				new(big.Int).Mul(big.NewInt(component.Remaining), big.NewInt(component.Weight))) != 0 {
				t.Fatalf("seed %d: component arithmetic mismatch at %d", seed, index)
			}
		}
		for _, reason := range trace.Reasons {
			if reason.Check >= PlacementCheckCpu && reason.Check <= PlacementCheckHugePages &&
				reason.Outcome != CheckOutcomePassed {
				t.Fatalf("seed %d: capacity check must pass for the selected candidate", seed)
			}
		}
	}
}

func TestRandomizedInvalidCasesRejectEachHardConstraintAndAreMutationSensitive(t *testing.T) {
	scheduler := DeterministicScheduler{}
	hits := make(map[schedulerViolation]int)
	for seed := uint64(20_001); seed < 20_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyInvalid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		hits[property.Violation]++
		result, err := scheduler.Schedule(property.Case.Workload, property.Case.Candidates, property.Case.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if _, ok := result.(Unschedulable); !ok {
			t.Fatalf("seed %d: expected Unschedulable", seed)
		}
		trace := resultCandidates(result)[0]
		if trace.Eligible {
			t.Fatalf("seed %d: expected ineligible candidate", seed)
		}
		found := false
		for _, reason := range trace.Reasons {
			if reason.Check == property.Check {
				found = true
				if reason.Outcome != CheckOutcomeRejected {
					t.Fatalf("seed %d: expected rejection for %v", seed, property.Check)
				}
			}
		}
		if !found {
			t.Fatalf("seed %d: missing reason for %v", seed, property.Check)
		}
		if trace.Score != nil {
			t.Fatalf("seed %d: rejected candidate must not carry a score", seed)
		}
	}
	for violation, count := range hits {
		if count < 50 {
			t.Fatalf("violation %d only hit %d times", violation, count)
		}
	}
}

func TestTypedCallerSafetyHoldsAlwaysPreventSelection(t *testing.T) {
	scheduler := DeterministicScheduler{}
	for seed := uint64(30_001); seed < 30_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		veto := AllCandidateVetoCodes[seed%uint64(len(AllCandidateVetoCodes))]
		vetoed, err := schedulerPropertyVetoed(property.Workload, veto)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		result, err := scheduler.Schedule(property.Workload, []*NodeCandidate{vetoed}, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if _, ok := result.(Unschedulable); !ok {
			t.Fatalf("seed %d: expected Unschedulable", seed)
		}
		found := false
		for _, reason := range resultCandidates(result)[0].Reasons {
			if reason.Check == PlacementCheckCallerVeto {
				found = true
				if reason.Outcome != CheckOutcomeRejected {
					t.Fatalf("seed %d: expected rejection", seed)
				}
				if !strings.Contains(reason.Detail, veto.String()) {
					t.Fatalf("seed %d: veto detail must name the code", seed)
				}
			}
		}
		if !found {
			t.Fatalf("seed %d: missing caller veto reason", seed)
		}
	}
}

func TestCheckedResourceArithmeticIsConservativeAndOverflowSafe(t *testing.T) {
	for seed := uint64(35_001); seed < 35_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		amount := int64(seed % 1_000)
		increment := ResourceVector{Cpu: amount, Memory: amount, BlockIo: amount,
			EphemeralDisk: amount, Bandwidth: amount, Pids: amount,
			FileDescriptors: amount, HugePages: amount}
		expanded, err := property.Workload.Resources.AddChecked(increment)
		if err != nil {
			t.Fatalf("seed %d: add: %v", seed, err)
		}
		difference, err := expanded.SubtractChecked(property.Workload.Resources)
		if err != nil {
			t.Fatalf("seed %d: subtract: %v", seed, err)
		}
		if difference != increment {
			t.Fatalf("seed %d: round trip mismatch", seed)
		}
	}
}

func TestRandomizedInvalidGeneratorsReachEveryPublicSchedulerValidationFamily(t *testing.T) {
	hits := make(map[schedulerValidatorFamily]int)
	for seed := uint64(36_001); seed < 36_001+propertyFeatureCases; seed++ {
		family, rejected, err := schedulerPropertyInvalidValidator(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		hits[family]++
		if !rejected {
			t.Fatalf("seed %d: family %d must be rejected", seed, family)
		}
	}
	for family, count := range hits {
		if count < 50 {
			t.Fatalf("family %d only hit %d times", family, count)
		}
	}
}

func TestGeneratorDiversityCoversCandidateCountsDimensionsWeightsTradeoffsAndWinners(t *testing.T) {
	candidateCounts := map[int]bool{}
	winners := map[string]bool{}
	weightValues := map[ResourceDimension]map[int64]bool{}
	for _, dimension := range AllResourceDimensions {
		weightValues[dimension] = map[int64]bool{}
	}
	dimensionValues := make([]map[int64]bool, 8)
	for index := range dimensionValues {
		dimensionValues[index] = map[int64]bool{}
	}
	tradeoffs := 0
	for seed := uint64(37_001); seed < 37_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		candidateCounts[len(property.Candidates)] = true
		oracle := oracleSelect(property)
		winners[oracle.CandidateId] = true
		for _, dimension := range property.Policy.Dimensions {
			weightValues[dimension.Dimension][dimension.Weight] = true
		}
		for _, candidate := range property.Candidates {
			values := oracleNaturalRemaining(candidate, property.Workload)
			for index := 0; index < 8; index++ {
				dimensionValues[index][values[index]] = true
			}
		}
		if oracleHasCrossDimensionTradeoff(property) {
			tradeoffs++
		}
	}
	for _, count := range []int{2, 3, 4, 5} {
		if !candidateCounts[count] {
			t.Fatalf("candidate count %d never appeared", count)
		}
	}
	for _, dimension := range AllResourceDimensions {
		for _, weight := range []int64{1, 2, 3, 4, 5} {
			if !weightValues[dimension][weight] {
				t.Fatalf("weight %d never appeared for %v", weight, dimension)
			}
		}
	}
	for index := 0; index < 8; index++ {
		if len(dimensionValues[index]) < 25 {
			t.Fatalf("dimension %d only saw %d distinct values", index, len(dimensionValues[index]))
		}
	}
	if tradeoffs < 900 {
		t.Fatalf("expected at least 900 tradeoffs, got %d", tradeoffs)
	}
	if len(winners) < 4 {
		t.Fatalf("expected at least 4 distinct winners, got %d", len(winners))
	}
}

func TestEqualScoreAndComponentTiesUseOrdinalCandidateIdentity(t *testing.T) {
	scheduler := DeterministicScheduler{}
	for seed := uint64(38_001); seed < 38_001+propertyFeatureCases; seed++ {
		property, err := schedulerPropertyValid(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		candidates, err := schedulerPropertyTiedCandidates(property.Workload)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		ordered := candidates
		if seed%2 == 0 {
			ordered = propertyReverse(candidates)
		}
		result, err := scheduler.Schedule(property.Workload, ordered, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		selected, ok := result.(PlacementSelected)
		if !ok {
			t.Fatalf("seed %d: expected PlacementSelected", seed)
		}
		if selected.SelectedCandidateId != "node-a" {
			t.Fatalf("seed %d: expected node-a, got %s", seed, selected.SelectedCandidateId)
		}
	}
}
