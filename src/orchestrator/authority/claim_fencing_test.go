package authority

import (
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func TestAcquireRejectsActiveForeignLease(t *testing.T) {
	lease := AuthorityLease{
		CandidateId:    "candidate-b",
		LeaseId:        "lease-b",
		ServerIssuedAt: authorityStart,
		Duration:       authorityDuration,
	}
	baseline := &AuthorityObservation{
		AuthorityId:   "regional-authority",
		KvRevision:    10,
		Epoch:         5,
		ObservationId: "foreign-active",
		Lease:         &lease,
	}
	decision, err := AuthorityEngine.Decide(
		[]AuthorityEvent{},
		NewAcquireAuthority(
			"regional-authority",
			"candidate-a",
			"acquire-active",
			"lease-a",
			baseline,
			authorityHealthy(authorityStart.Add(time.Minute), 0),
			authorityDuration,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorityError(t, decision, AuthorityErrorCodeLeaseActive)
	if len(decision.EventsToAppend) != 0 || len(decision.Intents) != 0 || decision.MutationPermit != nil {
		t.Fatalf("active foreign lease produced authority work: %#v", decision)
	}
}

func TestAcquireReclaimsExpiredForeignLeaseWithHigherEpoch(t *testing.T) {
	lease := AuthorityLease{
		CandidateId:    "candidate-b",
		LeaseId:        "lease-b",
		ServerIssuedAt: authorityStart.Add(-2 * authorityDuration),
		Duration:       authorityDuration,
	}
	baseline := &AuthorityObservation{
		AuthorityId:   "regional-authority",
		KvRevision:    10,
		Epoch:         5,
		ObservationId: "foreign-expired",
		Lease:         &lease,
	}
	decision, err := AuthorityEngine.Decide(
		[]AuthorityEvent{},
		NewAcquireAuthority(
			"regional-authority",
			"candidate-a",
			"acquire-expired",
			"lease-a",
			baseline,
			authorityHealthy(authorityStart, 0),
			authorityDuration,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Errors) != 0 {
		t.Fatalf("expired claim errors = %v", decision.Errors)
	}
	intent := onlySetIntent(t, decision)
	if intent.ExpectedEpoch != 5 || intent.ProposedEpoch != 6 || intent.ExpectedRevision != 10 {
		t.Fatalf("expired claim fencing values = %#v", intent)
	}
}

func TestAcquireHoldsWhenAuthorityHealthIsUncertain(t *testing.T) {
	tests := []struct {
		name     string
		health   AuthorityHealth
		wantCode AuthorityErrorCode
	}{
		{
			name: "partition",
			health: AuthorityHealth{
				ServerTime:   authorityStart,
				ClockCertain: true,
			},
			wantCode: AuthorityErrorCodePartitionUncertain,
		},
		{
			name: "clock",
			health: AuthorityHealth{
				ServerTime:       authorityStart,
				PartitionCertain: true,
			},
			wantCode: AuthorityErrorCodeClockAnomaly,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := AuthorityEngine.Decide(
				[]AuthorityEvent{},
				NewAcquireAuthority(
					"regional-authority",
					"candidate-a",
					"acquire-"+test.name,
					"lease-a",
					authorityGenesisObservation(),
					&test.health,
					authorityDuration,
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, test.wantCode)
			if decision.State.Status != AuthorityStatusReadOnlyHeld || decision.MutationPermit != nil {
				t.Fatalf("unsafe health decision = %#v", decision)
			}
		})
	}
}

func TestAcquireHoldsAtEpochAndRevisionOverflowBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		epoch    int64
		revision int64
	}{
		{name: "epoch", epoch: int64max, revision: 10},
		{name: "revision", epoch: 5, revision: int64max},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := authorityGenesisObservation()
			baseline.Epoch = test.epoch
			baseline.KvRevision = test.revision
			decision, err := AuthorityEngine.Decide(
				[]AuthorityEvent{},
				NewAcquireAuthority(
					"regional-authority",
					"candidate-a",
					"overflow-"+test.name,
					"lease-a",
					baseline,
					authorityHealthy(authorityStart, 0),
					authorityDuration,
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, AuthorityErrorCodeArithmeticOverflow)
			if decision.State.Status != AuthorityStatusReadOnlyHeld || len(decision.Intents) != 0 {
				t.Fatalf("overflow decision = %#v", decision)
			}
		})
	}
}

func TestUnsuccessfulAcquireCASNeverMintsAuthority(t *testing.T) {
	tests := []struct {
		name     string
		outcome  AuthorityCasOutcome
		wantCode AuthorityErrorCode
	}{
		{name: "conflict", outcome: AuthorityCasOutcomeConflict, wantCode: AuthorityErrorCodeCasConflict},
		{name: "failure", outcome: AuthorityCasOutcomeFailed, wantCode: AuthorityErrorCodeCasFailed},
		{name: "uncertain", outcome: AuthorityCasOutcomeUncertain, wantCode: AuthorityErrorCodeCasUncertain},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			history, _ := beginAcquisition(t, "candidate-a", "acquire-a")
			decision, err := AuthorityEngine.Decide(
				history,
				NewObserveAuthorityCas(
					"regional-authority",
					"candidate-a",
					"acquire-a",
					test.outcome,
					nil,
					authorityHealthy(authorityStart, 0),
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, test.wantCode)
			if decision.MutationPermit != nil || len(decision.Intents) != 0 {
				t.Fatalf("unsuccessful CAS produced authority: %#v", decision)
			}
		})
	}
}

func TestSuccessfulAcquireCASRequiresExactLeaseEpochAndRevision(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorityObservation)
	}{
		{name: "revision", mutate: func(observation *AuthorityObservation) { observation.KvRevision++ }},
		{name: "epoch", mutate: func(observation *AuthorityObservation) { observation.Epoch++ }},
		{name: "lease", mutate: func(observation *AuthorityObservation) { observation.Lease.LeaseId = "other" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
			intent := onlySetIntent(t, pending)
			lease := intent.ProposedLease
			observation := &AuthorityObservation{
				AuthorityId:   "regional-authority",
				KvRevision:    intent.ExpectedRevision + 1,
				Epoch:         intent.ProposedEpoch,
				ObservationId: "cas-result",
				Lease:         &lease,
			}
			test.mutate(observation)
			decision, err := AuthorityEngine.Decide(
				history,
				NewObserveAuthorityCas(
					"regional-authority",
					"candidate-a",
					"acquire-a",
					AuthorityCasOutcomeSucceeded,
					observation,
					authorityHealthy(authorityStart, 0),
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, AuthorityErrorCodeRevisionMismatch)
			if decision.State.Status != AuthorityStatusFenced || decision.MutationPermit != nil {
				t.Fatalf("mismatched success did not fence: %#v", decision)
			}
		})
	}
}

func TestFencedCandidateCannotSelfUnfence(t *testing.T) {
	history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
	intent := onlySetIntent(t, pending)
	lease := intent.ProposedLease
	observation := &AuthorityObservation{
		AuthorityId:   "regional-authority",
		KvRevision:    intent.ExpectedRevision + 2,
		Epoch:         intent.ProposedEpoch,
		ObservationId: "wrong-revision",
		Lease:         &lease,
	}
	fenced, err := AuthorityEngine.Decide(
		history,
		NewObserveAuthorityCas(
			"regional-authority",
			"candidate-a",
			"acquire-a",
			AuthorityCasOutcomeSucceeded,
			observation,
			authorityHealthy(authorityStart, 0),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if fenced.State.Status != AuthorityStatusFenced {
		t.Fatalf("setup status = %v, want fenced", fenced.State.Status)
	}

	retry, err := AuthorityEngine.DecideFromState(
		fenced.State,
		NewAcquireAuthority(
			"regional-authority",
			"candidate-a",
			"retry-after-fence",
			"lease-retry",
			observation,
			authorityHealthy(authorityStart, 0),
			authorityDuration,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorityError(t, retry, AuthorityErrorCodeFenced)
	if len(retry.EventsToAppend) != 0 || len(retry.Intents) != 0 || retry.MutationPermit != nil {
		t.Fatalf("fenced retry produced authority work: %#v", retry)
	}
}

func TestRenewalKeepsTheFencingEpochAndLeaseIdentity(t *testing.T) {
	_, leader := acquireLeader(t)
	current := *leader.State.Confirmed
	renewal, err := AuthorityEngine.DecideFromState(
		leader.State,
		NewRenewAuthority(
			"regional-authority",
			"candidate-a",
			"renew-a",
			&current,
			authorityHealthy(authorityStart.Add(time.Minute), time.Minute),
			authorityDuration,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(renewal.Errors) != 0 || renewal.State.Status != AuthorityStatusRenewalPending {
		t.Fatalf("renewal decision = %#v", renewal)
	}
	intent := onlySetIntent(t, renewal)
	if intent.ExpectedEpoch != current.Epoch || intent.ProposedEpoch != current.Epoch {
		t.Fatalf("renewal changed epoch: %#v", intent)
	}
	if intent.ProposedLease.LeaseId != current.Lease.LeaseId {
		t.Fatalf("renewal changed lease identity: %#v", intent.ProposedLease)
	}
}

func TestRenewalFencesWhenADeletedOrNewerLeaseIsObserved(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorityObservation)
		code   AuthorityErrorCode
	}{
		{name: "deleted", mutate: func(current *AuthorityObservation) { current.Lease = nil }, code: AuthorityErrorCodeRevisionMismatch},
		{name: "higher epoch", mutate: func(current *AuthorityObservation) { current.Epoch++ }, code: AuthorityErrorCodeEpochMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, leader := acquireLeader(t)
			current := *leader.State.Confirmed
			test.mutate(&current)
			decision, err := AuthorityEngine.DecideFromState(
				leader.State,
				NewRenewAuthority(
					"regional-authority",
					"candidate-a",
					"renew-"+test.name,
					&current,
					authorityHealthy(authorityStart.Add(time.Minute), time.Minute),
					authorityDuration,
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, test.code)
			if decision.State.Status != AuthorityStatusFenced || decision.MutationPermit != nil {
				t.Fatalf("unsafe renewal decision = %#v", decision)
			}
		})
	}
}

func TestReleaseRequiresExactCompareAndDeleteConfirmation(t *testing.T) {
	_, leader := acquireLeader(t)
	current := *leader.State.Confirmed
	health := authorityHealthy(authorityStart.Add(time.Minute), time.Minute)
	release, err := AuthorityEngine.DecideFromState(
		leader.State,
		NewReleaseAuthority(
			"regional-authority",
			"candidate-a",
			"release-a",
			&current,
			health,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(release.Errors) != 0 || release.State.Status != AuthorityStatusReleasePending {
		t.Fatalf("release decision = %#v", release)
	}
	intent, ok := release.Intents[0].(*CompareAndDeleteLeaseIntent)
	if !ok {
		t.Fatalf("release intent = %T", release.Intents[0])
	}
	absent := &AuthorityObservation{
		AuthorityId:   "regional-authority",
		KvRevision:    intent.ExpectedRevision + 1,
		Epoch:         intent.ExpectedEpoch,
		ObservationId: "delete-confirmed",
	}
	confirmed, err := AuthorityEngine.DecideFromState(
		release.State,
		NewObserveAuthorityDelete(
			"regional-authority",
			"candidate-a",
			"release-a",
			AuthorityCasOutcomeSucceeded,
			absent,
			health,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(confirmed.Errors) != 0 || confirmed.State.Status != AuthorityStatusFollower {
		t.Fatalf("confirmed release = %#v", confirmed)
	}
	if confirmed.MutationPermit != nil || confirmed.State.Confirmed.Lease != nil {
		t.Fatalf("release retained mutation authority: %#v", confirmed)
	}
}

func TestAmbiguousReleaseOutcomesFenceTheCandidate(t *testing.T) {
	tests := []struct {
		name     string
		outcome  AuthorityCasOutcome
		wantCode AuthorityErrorCode
	}{
		{name: "conflict", outcome: AuthorityCasOutcomeConflict, wantCode: AuthorityErrorCodeCasConflict},
		{name: "failed", outcome: AuthorityCasOutcomeFailed, wantCode: AuthorityErrorCodeCasFailed},
		{name: "uncertain", outcome: AuthorityCasOutcomeUncertain, wantCode: AuthorityErrorCodeCasUncertain},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, leader := acquireLeader(t)
			current := *leader.State.Confirmed
			health := authorityHealthy(authorityStart.Add(time.Minute), time.Minute)
			release, err := AuthorityEngine.DecideFromState(
				leader.State,
				NewReleaseAuthority(
					"regional-authority",
					"candidate-a",
					"release-a",
					&current,
					health,
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := AuthorityEngine.DecideFromState(
				release.State,
				NewObserveAuthorityDelete(
					"regional-authority",
					"candidate-a",
					"release-a",
					test.outcome,
					nil,
					health,
				),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertAuthorityError(t, decision, test.wantCode)
			if decision.State.Status != AuthorityStatusFenced || decision.MutationPermit != nil {
				t.Fatalf("ambiguous release did not fence: %#v", decision)
			}
		})
	}
}

func TestMutationPermitRequiresCurrentUnexpiredLease(t *testing.T) {
	_, leader := acquireLeader(t)
	current := *leader.State.Confirmed
	active, err := AuthorityEngine.DecideFromState(
		leader.State,
		NewEvaluateMutationAuthority(
			"regional-authority",
			"candidate-a",
			"evaluate-active",
			&current,
			authorityHealthy(authorityStart.Add(time.Minute), time.Minute),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Errors) != 0 || active.MutationPermit == nil {
		t.Fatalf("active lease did not mint permit: %#v", active)
	}

	expired, err := AuthorityEngine.DecideFromState(
		leader.State,
		NewEvaluateMutationAuthority(
			"regional-authority",
			"candidate-a",
			"evaluate-expired",
			&current,
			authorityHealthy(authorityStart.Add(authorityDuration+time.Second), authorityDuration+time.Second),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertAuthorityError(t, expired, AuthorityErrorCodeLeaseExpired)
	if expired.MutationPermit != nil || expired.State.Status != AuthorityStatusFenced {
		t.Fatalf("expired lease retained authority: %#v", expired)
	}
}

func TestReplayRejectsTamperedAndConflictingJournalEntries(t *testing.T) {
	t.Run("tampered digest", func(t *testing.T) {
		history, _ := beginAcquisition(t, "candidate-a", "acquire-a")
		original := history[0].(*AuthoritySetRequested)
		tampered := *original
		tampered.EventDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		decision, err := AuthorityEngine.Replay([]AuthorityEvent{&tampered})
		if err != nil {
			t.Fatal(err)
		}
		assertAuthorityError(t, decision, AuthorityErrorCodeInvalidJournal)
	})

	t.Run("conflicting sequence", func(t *testing.T) {
		first, _ := beginAcquisition(t, "candidate-a", "acquire-a")
		second, _ := beginAcquisition(t, "candidate-b", "acquire-b")
		decision, err := AuthorityEngine.Replay([]AuthorityEvent{first[0], second[0]})
		if err != nil {
			t.Fatal(err)
		}
		assertAuthorityError(t, decision, AuthorityErrorCodeConflictingJournalEvent)
	})

	t.Run("nil event", func(t *testing.T) {
		decision, err := AuthorityEngine.Replay([]AuthorityEvent{nil})
		if err != nil {
			t.Fatal(err)
		}
		assertAuthorityError(t, decision, AuthorityErrorCodeInvalidJournal)
	})
}

func TestAuthorityBoundariesReturnTypedArgumentErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "nil history",
			call: func() error {
				_, err := AuthorityEngine.Decide(nil, NewRequestAuthorityRead("a", "c", "r"))
				return err
			},
			want: "history",
		},
		{
			name: "nil command",
			call: func() error {
				_, err := AuthorityEngine.Decide([]AuthorityEvent{}, nil)
				return err
			},
			want: "command",
		},
		{
			name: "nil state",
			call: func() error {
				_, err := AuthorityEngine.DecideFromState(nil, NewRequestAuthorityRead("a", "c", "r"))
				return err
			},
			want: "state",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var argument *errs.Argument
			if err := test.call(); !errors.As(err, &argument) || argument.Param != test.want {
				t.Fatalf("error = %#v, want *errs.Argument for %s", err, test.want)
			}
		})
	}
}

func acquireLeader(t *testing.T) ([]AuthorityEvent, *AuthorityDecision) {
	t.Helper()
	history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
	leader := confirmSet(t, history, pending, "candidate-a", "acquire-a")
	if len(leader.Errors) != 0 || leader.State.Status != AuthorityStatusLeader {
		t.Fatalf("leader setup = %#v", leader)
	}
	history = append(history, leader.EventsToAppend...)
	return history, leader
}

func onlySetIntent(t *testing.T, decision *AuthorityDecision) *CompareAndSetLeaseIntent {
	t.Helper()
	if len(decision.Intents) != 1 {
		t.Fatalf("intents = %d, want 1", len(decision.Intents))
	}
	intent, ok := decision.Intents[0].(*CompareAndSetLeaseIntent)
	if !ok {
		t.Fatalf("intent = %T, want *CompareAndSetLeaseIntent", decision.Intents[0])
	}
	return intent
}

func assertAuthorityError(t *testing.T, decision *AuthorityDecision, want AuthorityErrorCode) {
	t.Helper()
	if decision == nil || len(decision.Errors) == 0 {
		t.Fatalf("decision errors = %#v, want %s", decision, want)
	}
	if got := decision.Errors[0].Code; got != want {
		t.Fatalf("error code = %s, want %s", got, want)
	}
}
