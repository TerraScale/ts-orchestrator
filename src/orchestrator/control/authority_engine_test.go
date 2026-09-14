package control

import (
	"testing"
	"time"
)

var authorityStart = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

var authorityDuration = 10 * time.Minute

func authorityHealthy(at time.Time, elapsed time.Duration) *AuthorityHealth {
	return &AuthorityHealth{ServerTime: at, MonotonicElapsed: elapsed, PartitionCertain: true, ClockCertain: true}
}

func authorityGenesisObservation() *AuthorityObservation {
	return &AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 10, Epoch: 5,
		ObservationId: "baseline", Lease: nil}
}

// TestAcquisitionAdvancesEpochAndOnlyExactCasProducesBoundPermit ports the
// first AuthorityEngineTests scenario.
func TestAcquisitionAdvancesEpochAndOnlyExactCasProducesBoundPermit(t *testing.T) {
	history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
	if pending.State.Status != AuthorityStatusAcquisitionPending {
		t.Fatalf("status = %v, want AcquisitionPending", pending.State.Status)
	}
	if pending.MutationPermit != nil {
		t.Fatal("pending decision must not carry a mutation permit")
	}
	intent, ok := pending.Intents[0].(*CompareAndSetLeaseIntent)
	if !ok {
		t.Fatalf("intent type = %T", pending.Intents[0])
	}
	if intent.ExpectedEpoch != 5 || intent.ProposedEpoch != 6 {
		t.Fatalf("epochs = %d/%d", intent.ExpectedEpoch, intent.ProposedEpoch)
	}

	result := confirmSet(t, history, pending, "candidate-a", "acquire-a")
	if len(result.Errors) != 0 {
		t.Fatalf("errors = %v", result.Errors)
	}
	if result.State.Status != AuthorityStatusLeader {
		t.Fatalf("status = %v, want Leader", result.State.Status)
	}
	if result.MutationPermit == nil {
		t.Fatal("expected bound mutation permit")
	}
	if result.MutationPermit.AuthorityId != "regional-authority" ||
		result.MutationPermit.CandidateId != "candidate-a" ||
		result.MutationPermit.LeaseId != "lease-candidate-a" ||
		result.MutationPermit.Epoch != 6 || result.MutationPermit.KvRevision != 11 {
		t.Fatalf("permit = %+v", result.MutationPermit)
	}
}

// TestMismatchedSuccessfulCasFencesWithoutAuthority ports the second scenario.
func TestMismatchedSuccessfulCasFencesWithoutAuthority(t *testing.T) {
	history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
	proposal := pending.Intents[0].(*CompareAndSetLeaseIntent).ProposedLease
	mismatch, err := AuthorityEngine.Decide(history, NewObserveAuthorityCas("regional-authority",
		"candidate-a", "acquire-a", AuthorityCasOutcomeSucceeded,
		&AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 12, Epoch: 6,
			ObservationId: "wrong-revision", Lease: &proposal},
		authorityHealthy(authorityStart, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.State.Status != AuthorityStatusFenced {
		t.Fatalf("status = %v, want Fenced", mismatch.State.Status)
	}
	if mismatch.MutationPermit != nil {
		t.Fatal("fenced decision must not carry a permit")
	}
	if mismatch.Errors[0].Code != AuthorityErrorCodeRevisionMismatch {
		t.Fatalf("code = %v", mismatch.Errors[0].Code)
	}
}

func beginAcquisition(t *testing.T, candidate, request string) ([]AuthorityEvent, *AuthorityDecision) {
	t.Helper()
	command := NewAcquireAuthority("regional-authority", candidate, request, "lease-"+candidate,
		authorityGenesisObservation(), authorityHealthy(authorityStart, 0), authorityDuration)
	decision, err := AuthorityEngine.Decide([]AuthorityEvent{}, command)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Errors) != 0 {
		t.Fatalf("begin errors = %v", decision.Errors)
	}
	return decision.EventsToAppend, decision
}

func confirmSet(t *testing.T, history []AuthorityEvent, pending *AuthorityDecision,
	candidate, request string) *AuthorityDecision {
	t.Helper()
	intent := pending.Intents[0].(*CompareAndSetLeaseIntent)
	observation := &AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 11, Epoch: 6,
		ObservationId: "winner-observation", Lease: &intent.ProposedLease}
	decision, err := AuthorityEngine.Decide(history, NewObserveAuthorityCas("regional-authority",
		candidate, request, AuthorityCasOutcomeSucceeded, observation, authorityHealthy(authorityStart, 0)))
	if err != nil {
		t.Fatal(err)
	}
	return decision
}
