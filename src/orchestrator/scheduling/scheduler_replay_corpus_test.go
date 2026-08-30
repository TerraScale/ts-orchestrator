// The scheduler replay corpus is kept beside this package's tests so it stays
// available to `go test` from any working directory.
package scheduling

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode"
)

const schedulerReplayMaximumBytes = 8_192
const schedulerReplayMaximumEntries = 32

//go:embed testdata/scheduler-replay-v1.json
var schedulerReplayCorpus []byte

type schedulerReplayKind int

const (
	replayHardConstraint schedulerReplayKind = 1 + iota
	replayCallerHold
	replayAvailabilityFloor
	replayObservationConflict
	replayReserveBoundary
)

type schedulerReplayEntry struct {
	Identity string
	Seed     uint64
	Kind     schedulerReplayKind
	Expected string
}

type schedulerReplayDocument struct {
	ContentSha256 string
	Entries       []schedulerReplayEntry
}

func schedulerReplayLoad(t *testing.T) schedulerReplayDocument {
	t.Helper()
	document, err := schedulerReplayParse(schedulerReplayCorpus)
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	return document
}

func schedulerReplayParse(bytes []byte) (schedulerReplayDocument, error) {
	if len(bytes) > schedulerReplayMaximumBytes {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus exceeds its byte bound.")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &root); err != nil {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus envelope is invalid.")
	}
	if len(root) != 2 {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus envelope is invalid.")
	}
	var version int
	if err := json.Unmarshal(root["version"], &version); err != nil || version != 1 {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus envelope is invalid.")
	}
	if _, present := root["entries"]; !present {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus envelope is invalid.")
	}
	var rawEntries []map[string]json.RawMessage
	if err := json.Unmarshal(root["entries"], &rawEntries); err != nil {
		return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus entries are invalid.")
	}
	entries := make([]schedulerReplayEntry, 0, len(rawEntries))
	for _, item := range rawEntries {
		if len(entries) == schedulerReplayMaximumEntries || len(item) != 4 {
			return schedulerReplayDocument{}, fmt.Errorf("The scheduler replay corpus entry bound or shape is invalid.")
		}
		var identity, expected, kindText string
		var seed uint64
		if err := json.Unmarshal(item["identity"], &identity); err != nil {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay identity is invalid.")
		}
		if err := json.Unmarshal(item["expected"], &expected); err != nil {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay expectation is invalid.")
		}
		if err := json.Unmarshal(item["kind"], &kindText); err != nil {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay kind is invalid.")
		}
		if err := json.Unmarshal(item["seed"], &seed); err != nil || seed == 0 {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay seed is invalid.")
		}
		if len(identity) < 1 || len(identity) > 80 {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay identity is invalid.")
		}
		for _, character := range identity {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-') {
				return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay identity is invalid.")
			}
		}
		if len(expected) < 1 || len(expected) > 120 || strings.ContainsFunc(expected, unicode.IsControl) {
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay expectation is invalid.")
		}
		var kind schedulerReplayKind
		switch kindText {
		case "hard-constraint":
			kind = replayHardConstraint
		case "caller-hold":
			kind = replayCallerHold
		case "availability-floor":
			kind = replayAvailabilityFloor
		case "observation-conflict":
			kind = replayObservationConflict
		case "reserve-boundary":
			kind = replayReserveBoundary
		default:
			return schedulerReplayDocument{}, fmt.Errorf("A scheduler replay kind is invalid.")
		}
		entries = append(entries, schedulerReplayEntry{
			Identity: identity, Seed: seed, Kind: kind, Expected: expected,
		})
	}
	if len(entries) == 0 {
		return schedulerReplayDocument{}, fmt.Errorf("Scheduler replay identities and seeds must be nonempty and unique.")
	}
	distinctIdentities := map[string]bool{}
	distinctSeeds := map[uint64]bool{}
	for _, entry := range entries {
		distinctIdentities[entry.Identity] = true
		distinctSeeds[entry.Seed] = true
	}
	if len(distinctIdentities) != len(entries) || len(distinctSeeds) != len(entries) {
		return schedulerReplayDocument{}, fmt.Errorf("Scheduler replay identities and seeds must be nonempty and unique.")
	}
	digest := sha256.Sum256(bytes)
	return schedulerReplayDocument{
		ContentSha256: hex.EncodeToString(digest[:]),
		Entries:       entries,
	}, nil
}

func schedulerReplayReplay(t *testing.T, entry schedulerReplayEntry) string {
	t.Helper()
	switch entry.Kind {
	case replayHardConstraint:
		property, err := schedulerPropertyCapacityInvalid(entry.Seed)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		result, err := DeterministicScheduler{}.Schedule(property.Case.Workload,
			property.Case.Candidates, property.Case.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		if _, ok := result.(Unschedulable); ok {
			return fmt.Sprintf("rejected:capacity:%s", property.Check)
		}
		return "unexpected"
	case replayCallerHold:
		property, err := schedulerPropertyValid(entry.Seed)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		vetoed, err := schedulerPropertyVetoed(property.Workload, CandidateVetoCodeStatefulSafetyHold)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		result, err := DeterministicScheduler{}.Schedule(property.Workload,
			[]*NodeCandidate{vetoed}, property.Policy)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		if _, ok := result.(Unschedulable); ok {
			return "rejected:caller-hold"
		}
		return "unexpected"
	case replayAvailabilityFloor:
		property, err := availabilityPropertyMaintenance(entry.Seed)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		count := uint64(len(property.Observations))
		policy, err := availabilityPropertyPolicy(count, count, count, 1, count, true, ResourceVectorZero)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		generation, err := NewAvailabilityGeneration(1)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		request, err := NewAvailabilityEvaluationRequest(policy, property.Maintenance,
			ObservationCompletenessComplete, generation, generation, property.Observations)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		decision := AvailabilityPolicyEvaluator{}.Evaluate(request)
		if decision.Admitted() {
			return "unexpected"
		}
		return "rejected:availability-floor"
	case replayObservationConflict:
		property, err := availabilityPropertyMaintenance(entry.Seed)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		conflictNode := mustAvailabilityNodeId(t, "conflict")
		conflictDomain := mustFailureDomainId(t, "conflict")
		conflict, conflictErr := NewReplicaObservation(property.Observations[0].ReplicaId,
			property.Observations[0].ServiceId, &conflictNode, &conflictDomain,
			ReplicaAvailabilityStateAvailable)
		if conflictErr != nil {
			t.Fatalf("seed %d: %v", entry.Seed, conflictErr)
		}
		generation, err := NewAvailabilityGeneration(1)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		request, err := NewAvailabilityEvaluationRequest(property.Policy, property.Maintenance,
			ObservationCompletenessComplete, generation, generation,
			append(append([]ReplicaObservation{}, property.Observations...), conflict))
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		decision := AvailabilityPolicyEvaluator{}.Evaluate(request)
		if decision.Admitted() {
			return "unexpected"
		}
		return "rejected:observation-conflict"
	case replayReserveBoundary:
		property, err := availabilityPropertyMaintenance(entry.Seed)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		count := uint64(len(property.Observations))
		requested := availabilityResources(2)
		reserve := availabilityResources(3)
		dimension := int(entry.Seed % 8)
		added, addErr := propertyAdd(requested, 3)
		if addErr != nil {
			t.Fatalf("seed %d: %v", entry.Seed, addErr)
		}
		available := propertyWithOneDimension(added, dimension, -1)
		policy, err := availabilityPropertyPolicy(count+1, count, count, 1, count+1, true, reserve)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		placement := PlaceReplicaChange{
			ReplicaId:             mustReplicaId(t, "replica-"+formatUint(count)),
			TargetNodeId:          mustAvailabilityNodeId(t, "node-"+formatUint(count)),
			TargetFailureDomainId: mustFailureDomainId(t, "fd-"+formatUint(count)),
			RequestedResources:    requested,
			AvailableResources:    available,
		}
		generation, err := NewAvailabilityGeneration(1)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		request, err := NewAvailabilityEvaluationRequest(policy, placement,
			ObservationCompletenessComplete, generation, generation, property.Observations)
		if err != nil {
			t.Fatalf("seed %d: %v", entry.Seed, err)
		}
		decision := AvailabilityPolicyEvaluator{}.Evaluate(request)
		if decision.Admitted() {
			return "unexpected"
		}
		code := AvailabilityReasonCode(int(AvailabilityReasonCodeReserveCpu) + dimension)
		return fmt.Sprintf("rejected:reserve-boundary:%s", code)
	default:
		t.Fatalf("unknown replay kind %d", entry.Kind)
		return "unexpected"
	}
}

func TestEmbeddedMinimalSeedCorpusIsStrictContentAddressedBoundedAndReplaysExactly(t *testing.T) {
	const expectedContentSha256 = "10f0e0ed8a72189bf318ede88ca5f78cc8347e1a28840ee77ba0587492420073"
	corpus := schedulerReplayLoad(t)
	if corpus.ContentSha256 != expectedContentSha256 {
		t.Fatalf("corpus content hash mismatch: %s", corpus.ContentSha256)
	}
	if len(corpus.Entries) > schedulerReplayMaximumEntries {
		t.Fatal("corpus entry bound exceeded")
	}
	for _, entry := range corpus.Entries {
		first := schedulerReplayReplay(t, entry)
		second := schedulerReplayReplay(t, entry)
		if first != entry.Expected {
			t.Fatalf("entry %s: replay mismatch: got %q want %q", entry.Identity, first, entry.Expected)
		}
		if second != first {
			t.Fatalf("entry %s: replay must be deterministic", entry.Identity)
		}
	}
}

func TestCorpusParserRejectsVersionUnknownDuplicateOversizedCountAndSeedMutations(t *testing.T) {
	validEntry := `{"identity":"id-a","seed":1,"kind":"caller-hold","expected":"rejected:caller-hold"}`
	mutatedEntry := func(identity string, seed uint64) string {
		return fmt.Sprintf(`{"identity":"%s","seed":%d,"kind":"caller-hold","expected":"rejected:caller-hold"}`,
			identity, seed)
	}
	var oversized strings.Builder
	oversized.WriteString(`{"version":1,"entries":[`)
	for index := 0; index < 33; index++ {
		if index > 0 {
			oversized.WriteByte(',')
		}
		oversized.WriteString(mutatedEntry(fmt.Sprintf("id-%d", index), uint64(index+1)))
	}
	oversized.WriteString("]}")
	invalid := []string{
		`{"version":2,"entries":[]}`,
		`{"version":1,"entries":[],"unknown":1}`,
		`{"version":1,"entries":[` + validEntry + `,` + validEntry + `]}`,
		`{"version":1,"entries":[` + strings.Replace(validEntry, `"seed":1`, `"seed":0`, 1) + `]}`,
		oversized.String(),
	}
	for _, json := range invalid {
		if _, err := schedulerReplayParse([]byte(json)); err == nil {
			t.Fatalf("corpus mutation must be rejected: %s", json)
		}
	}
	tooLarge := make([]byte, schedulerReplayMaximumBytes+1)
	if _, err := schedulerReplayParse(tooLarge); err == nil {
		t.Fatal("oversized corpus must be rejected")
	}
}
