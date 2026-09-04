package authority

import (
	"sort"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

var AuthorityEngine authorityEngine

type authorityEngine struct{}

// Decide mirrors AuthorityEngine.Decide(IReadOnlyList<AuthorityEvent>, AuthorityCommand).
func (authorityEngine) Decide(history []AuthorityEvent, command AuthorityCommand) (*AuthorityDecision, error) {
	if history == nil {
		return nil, shared.ArgumentNil("history")
	}
	if command == nil {
		return nil, shared.ArgumentNil("command")
	}
	replay, err := AuthorityEngine.Replay(history)
	if err != nil {
		return nil, err
	}
	if len(replay.Errors) != 0 {
		return replay, nil
	}
	return AuthorityEngine.DecideFromState(replay.State, command)
}

// DecideFromState mirrors AuthorityEngine.Decide(AuthorityState, AuthorityCommand):
// applies one command to an already-replayed authority state without
// replaying the journal so long-running lease renewal stays O(1) per tick.
func (authorityEngine) DecideFromState(state *AuthorityState, command AuthorityCommand) (*AuthorityDecision, error) {
	if state == nil {
		return nil, shared.ArgumentNil("state")
	}
	if command == nil {
		return nil, shared.ArgumentNil("command")
	}
	common := authorityValidateCommand(state, command)
	if common != nil {
		return authorityReject(state, *common), nil
	}
	if state.Status == AuthorityStatusFenced {
		return authorityReject(state, authorityError(AuthorityErrorCodeFenced, "INV-004", "A fenced candidate cannot self-unfence.")), nil
	}

	switch value := command.(type) {
	case *AcquireAuthority:
		return authorityAcquire(state, value), nil
	case *RenewAuthority:
		return authorityRenew(state, value), nil
	case *ReleaseAuthority:
		return authorityRelease(state, value), nil
	case *RequestAuthorityRead:
		return authorityRequestRead(state, value), nil
	case *ObserveAuthorityCas:
		return authorityObserveSet(state, value), nil
	case *ObserveAuthorityDelete:
		return authorityObserveDelete(state, value), nil
	case *ObserveAuthorityRead:
		return authorityObserveRead(state, value), nil
	case *EvaluateMutationAuthority:
		return authorityEvaluate(state, value), nil
	default:
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Unknown authority command.")), nil
	}
}

func (authorityEngine) Replay(history []AuthorityEvent) (*AuthorityDecision, error) {
	if history == nil {
		return nil, shared.ArgumentNil("history")
	}
	state := AuthorityStateEmpty
	if authorityHistoryContainsNil(history) {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority journal contains a null event.")), nil
	}

	grouped := make(map[int64][]AuthorityEvent)
	for _, item := range history {
		grouped[item.authorityEventCommon().Sequence] = append(grouped[item.authorityEventCommon().Sequence], item)
	}
	keys := make([]int64, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, key := range keys {
		group := grouped[key]
		first := group[0]
		unknownType := false
		for _, item := range group {
			digest, err := AuthorityDigest.Event(item)
			if err != nil {
				unknownType = true
				break
			}
			if item.authorityEventCommon().EventDigest != digest {
				return authorityReject(state, authorityError(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority event digest does not match its body.")), nil
			}
		}
		if unknownType {
			return authorityReject(state, authorityError(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority journal contains an unknown event type.")), nil
		}
		for _, item := range group {
			if item.authorityEventCommon().EventDigest != first.authorityEventCommon().EventDigest {
				return authorityReject(state, authorityError(AuthorityErrorCodeConflictingJournalEvent, "INV-005", "A sequence contains conflicting event bodies.")), nil
			}
		}
		if err := authorityValidateNext(state, first); err != nil {
			return authorityReject(state, *err), nil
		}
		state = authorityApply(state, first)
	}

	return NewAuthorityDecision(state, nil, nil, nil, nil), nil
}

func authorityHistoryContainsNil(history []AuthorityEvent) bool {
	for _, item := range history {
		if item == nil {
			return true
		}
	}
	return false
}

func authorityAcquire(state *AuthorityState, command *AcquireAuthority) *AuthorityDecision {
	if state.Status != AuthorityStatusFollower && state.Status != AuthorityStatusReadOnlyHeld {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidTransition, "INV-004", "Acquisition requires follower or held state."))
	}
	if completed := authorityCompletedRequestReuse(state, command.RequestId); completed != nil {
		return authorityReject(state, *completed)
	}
	input := authorityValidateObservation(command.Baseline)
	if input == nil {
		input = authorityValidateHealth(command.Health)
	}
	if input != nil || shared.IsNullOrWhiteSpace(command.LeaseId) || command.LeaseDuration <= 0 {
		if input != nil {
			return authorityReject(state, *input)
		}
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Lease ID and positive duration are required."))
	}
	health := authoritySafetyError(command.Health)
	if health != nil {
		return authorityHold(state, command, *health)
	}
	if command.Baseline.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Acquisition observation belongs to another authority."))
	}
	if command.Baseline.Epoch < state.HighestEpoch {
		return authorityReject(state, authorityError(AuthorityErrorCodeEpochMismatch, "INV-004", "Acquisition baseline epoch is stale."))
	}
	if command.Baseline.KvRevision < state.HighestKvRevision {
		return authorityReject(state, authorityError(AuthorityErrorCodeRevisionMismatch, "INV-004", "Acquisition baseline revision is stale."))
	}
	if command.Baseline.Lease != nil {
		leaseError := authorityLeaseError(command.Baseline, command.Health)
		if leaseError != nil &&
			(leaseError.Code == AuthorityErrorCodeClockAnomaly || leaseError.Code == AuthorityErrorCodeArithmeticOverflow) {
			return authorityHold(state, command, *leaseError)
		}
		if leaseError == nil || leaseError.Code != AuthorityErrorCodeLeaseExpired {
			if leaseError == nil {
				return authorityReject(state, authorityError(AuthorityErrorCodeLeaseActive, "INV-004", "Observed lease is still active."))
			}
			return authorityReject(state, *leaseError)
		}
	}

	epoch, ok := shared.CheckedAddInt64(command.Baseline.Epoch, 1)
	if !ok {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "Fencing epoch overflowed."))
	}
	if command.Baseline.KvRevision == shared.Int64Max {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "KV revision cannot advance."))
	}
	if !shared.CanAddDuration(command.Health.ServerTime, command.LeaseDuration) {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-005", "Lease expiry overflows timestamp range."))
	}

	lease := AuthorityLease{CandidateId: command.CandidateId, LeaseId: command.LeaseId,
		ServerIssuedAt: command.Health.ServerTime, Duration: command.LeaseDuration}
	pending := PendingAuthoritySet{RequestId: command.RequestId, ExpectedRevision: command.Baseline.KvRevision,
		ExpectedEpoch: command.Baseline.Epoch, ProposedEpoch: epoch, ProposedLease: lease,
		ExpectedObservation: command.Baseline, RequestedAtHealth: command.Health, IsRenewal: false}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthoritySetRequested {
		return &AuthoritySetRequested{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Pending: pending}
	})
	intent := NewCompareAndSetLeaseIntent(command.AuthorityId, command.RequestId,
		pending.ExpectedRevision, pending.ExpectedEpoch, pending.ProposedEpoch, pending.ProposedLease)
	return authorityCommit(state, event, []AuthorityIntent{intent}, nil, nil)
}

func authorityRenew(state *AuthorityState, command *RenewAuthority) *AuthorityDecision {
	if state.Status != AuthorityStatusLeader || state.Confirmed == nil || state.Confirmed.Lease == nil {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidTransition, "INV-004", "Renewal requires confirmed leader state."))
	}
	confirmedLease := state.Confirmed.Lease
	if completed := authorityCompletedRequestReuse(state, command.RequestId); completed != nil {
		return authorityReject(state, *completed)
	}
	input := authorityValidateObservation(command.Current)
	if input == nil {
		input = authorityValidateHealth(command.Health)
	}
	if input != nil || command.LeaseDuration <= 0 {
		if input != nil {
			return authorityReject(state, *input)
		}
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Positive renewal duration is required."))
	}
	if command.Current.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Renewal observation belongs to another authority."))
	}
	if command.Current.KvRevision == shared.Int64Max {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "KV revision cannot advance."))
	}
	exact := authorityEnsureExactCurrent(state, command.Current, command.Health)
	if exact != nil {
		return authorityLoseAuthority(state, command, command.Current, *exact)
	}
	if !shared.CanAddDuration(command.Health.ServerTime, command.LeaseDuration) {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "Renewal expiry overflows timestamp range."))
	}

	lease := AuthorityLease{CandidateId: command.CandidateId, LeaseId: confirmedLease.LeaseId,
		ServerIssuedAt: command.Health.ServerTime, Duration: command.LeaseDuration}
	pending := PendingAuthoritySet{RequestId: command.RequestId, ExpectedRevision: command.Current.KvRevision,
		ExpectedEpoch: command.Current.Epoch, ProposedEpoch: command.Current.Epoch, ProposedLease: lease,
		ExpectedObservation: command.Current, RequestedAtHealth: command.Health, IsRenewal: true}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthoritySetRequested {
		return &AuthoritySetRequested{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Pending: pending}
	})
	return authorityCommit(state, event, []AuthorityIntent{NewCompareAndSetLeaseIntent(command.AuthorityId,
		command.RequestId, pending.ExpectedRevision, pending.ExpectedEpoch, pending.ProposedEpoch, lease)}, nil, nil)
}

func authorityRelease(state *AuthorityState, command *ReleaseAuthority) *AuthorityDecision {
	if state.Status != AuthorityStatusLeader || state.Confirmed == nil || state.Confirmed.Lease == nil {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidTransition, "INV-004", "Release requires confirmed leader state."))
	}
	if completed := authorityCompletedRequestReuse(state, command.RequestId); completed != nil {
		return authorityReject(state, *completed)
	}
	input := authorityValidateObservation(command.Current)
	if input == nil {
		input = authorityValidateHealth(command.Health)
	}
	if input != nil {
		return authorityReject(state, *input)
	}
	if command.Current.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Release observation belongs to another authority."))
	}
	if command.Current.KvRevision == shared.Int64Max {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "KV revision cannot advance."))
	}
	exact := authorityEnsureExactCurrent(state, command.Current, command.Health)
	if exact != nil {
		return authorityLoseAuthority(state, command, command.Current, *exact)
	}
	if command.Current.Lease == nil {
		return authorityLoseAuthority(state, command, command.Current,
			authorityError(AuthorityErrorCodeLeaseExpired, "INV-004", "No active lease is observed."))
	}
	currentLease := command.Current.Lease
	pending := PendingAuthorityDelete{RequestId: command.RequestId, ExpectedRevision: command.Current.KvRevision,
		ExpectedEpoch: command.Current.Epoch, ExpectedLease: *currentLease, RequestedAtHealth: command.Health}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityDeleteRequested {
		return &AuthorityDeleteRequested{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Pending: pending}
	})
	return authorityCommit(state, event, []AuthorityIntent{NewCompareAndDeleteLeaseIntent(command.AuthorityId,
		command.RequestId, pending.ExpectedRevision, pending.ExpectedEpoch, pending.ExpectedLease)}, nil, nil)
}

func authorityRequestRead(state *AuthorityState, command *RequestAuthorityRead) *AuthorityDecision {
	if state.Status == AuthorityStatusAcquisitionPending || state.Status == AuthorityStatusRenewalPending ||
		state.Status == AuthorityStatusReleasePending {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidTransition, "INV-004", "A CAS result must resolve before a read request."))
	}
	if completed := authorityCompletedRequestReuse(state, command.RequestId); completed != nil {
		return authorityReject(state, *completed)
	}
	resume := state.Status
	if state.Status == AuthorityStatusReadOnlyHeld && state.ReadResumeStatus != nil &&
		*state.ReadResumeStatus == AuthorityStatusLeader {
		resume = AuthorityStatusLeader
	}
	if resume == AuthorityStatusLeader && (state.Confirmed == nil || state.Confirmed.Lease == nil ||
		state.Confirmed.Lease.CandidateId != command.CandidateId) {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Only the confirmed lease candidate may re-read leader authority."))
	}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityReadRequested {
		return &AuthorityReadRequested{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			ResumeStatus: resume}
	})
	return authorityCommit(state, event, []AuthorityIntent{NewReadAuthorityIntent(command, state, resume)}, nil, nil)
}

func authorityObserveSet(state *AuthorityState, command *ObserveAuthorityCas) *AuthorityDecision {
	if state.LastCompletedRequestId != nil && *state.LastCompletedRequestId == command.RequestId {
		return NewAuthorityDecision(state, nil, nil, nil, nil)
	}
	healthInput := authorityValidateHealth(command.Health)
	if healthInput != nil {
		return authorityReject(state, *healthInput)
	}
	if state.PendingSet == nil || state.PendingSet.RequestId != command.RequestId ||
		state.PendingSet.ProposedLease.CandidateId != command.CandidateId ||
		(state.Status != AuthorityStatusAcquisitionPending && state.Status != AuthorityStatusRenewalPending) {
		return authorityReject(state, authorityError(AuthorityErrorCodeStaleObservation, "INV-005", "CAS observation does not match the pending request."))
	}
	if !authorityCasOutcomeIsDefined(command.Outcome) {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "CAS outcome is outside the closed vocabulary."))
	}
	if command.Observation != nil && command.Observation.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "CAS observation belongs to another authority."))
	}
	if command.Observation != nil {
		if suppliedObservation := authorityValidateObservation(command.Observation); suppliedObservation != nil {
			return authorityReject(state, *suppliedObservation)
		}
	}
	pending := state.PendingSet
	if command.Outcome == AuthorityCasOutcomeSucceeded {
		if command.Observation == nil {
			return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Successful CAS requires an observation."))
		}
		observation := command.Observation
		if observationError := authorityValidateObservation(observation); observationError != nil {
			return authorityReject(state, *observationError)
		}
		revision, ok := shared.CheckedAddInt64(pending.ExpectedRevision, 1)
		if !ok {
			return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "KV revision overflowed."))
		}
		if observation.KvRevision != revision || observation.Epoch != pending.ProposedEpoch ||
			observation.Lease == nil || !observation.Lease.Equal(pending.ProposedLease) {
			return authorityFence(state, command, observation,
				authorityError(AuthorityErrorCodeRevisionMismatch, "INV-004", "Successful CAS observation does not exactly match the proposed lease."))
		}
		safety := authoritySafetyError(command.Health)
		if safety == nil {
			safety = authorityLeaseError(observation, command.Health)
		}
		if safety != nil {
			return authorityLoseAuthority(state, command, observation, *safety)
		}
		confirmed := authorityStamp(state, func(sequence int64, previous, digest string) *AuthoritySetConfirmed {
			return &AuthoritySetConfirmed{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
				EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
				Observation: observation, Health: command.Health, WasRenewal: pending.IsRenewal}
		})
		permit := authorityCreatePermit(command)
		return authorityCommit(state, confirmed, nil, nil, permit)
	}

	var code AuthorityErrorCode
	var message string
	switch command.Outcome {
	case AuthorityCasOutcomeConflict:
		code, message = AuthorityErrorCodeCasConflict, "Lease CAS conflicted."
	case AuthorityCasOutcomeFailed:
		code, message = AuthorityErrorCodeCasFailed, "Lease CAS failed."
	case AuthorityCasOutcomeUncertain:
		code, message = AuthorityErrorCodeCasUncertain, "Lease CAS outcome is uncertain."
	default:
		code, message = AuthorityErrorCodeInvalidInput, "Invalid CAS outcome."
	}
	err := authorityError(code, "INV-004", message)
	rejected := authorityStamp(state, func(sequence int64, previous, digest string) *AuthoritySetRejected {
		return &AuthoritySetRejected{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Outcome: command.Outcome, Observation: command.Observation, Error: err}
	})
	return authorityCommit(state, rejected, nil, []AuthorityError{err}, nil)
}

func authorityObserveDelete(state *AuthorityState, command *ObserveAuthorityDelete) *AuthorityDecision {
	if state.LastCompletedRequestId != nil && *state.LastCompletedRequestId == command.RequestId {
		return NewAuthorityDecision(state, nil, nil, nil, nil)
	}
	healthInput := authorityValidateHealth(command.Health)
	if healthInput != nil {
		return authorityReject(state, *healthInput)
	}
	if state.Status != AuthorityStatusReleasePending || state.PendingDelete == nil ||
		state.PendingDelete.RequestId != command.RequestId ||
		state.PendingDelete.ExpectedLease.CandidateId != command.CandidateId {
		return authorityReject(state, authorityError(AuthorityErrorCodeStaleObservation, "INV-005", "Delete observation does not match pending release."))
	}
	if !authorityCasOutcomeIsDefined(command.Outcome) {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Delete outcome is invalid."))
	}
	if command.Observation != nil && command.Observation.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Delete observation belongs to another authority."))
	}
	if command.Observation != nil {
		if suppliedObservation := authorityValidateObservation(command.Observation); suppliedObservation != nil {
			return authorityReject(state, *suppliedObservation)
		}
	}
	if command.Outcome != AuthorityCasOutcomeSucceeded || command.Observation == nil {
		code := AuthorityErrorCodeCasFailed
		switch command.Outcome {
		case AuthorityCasOutcomeConflict:
			code = AuthorityErrorCodeCasConflict
		case AuthorityCasOutcomeUncertain:
			code = AuthorityErrorCodeCasUncertain
		}
		return authorityFence(state, command, command.Observation, authorityError(code, "INV-004", "Release was not exactly confirmed."))
	}
	if validation := authorityValidateObservation(command.Observation); validation != nil {
		return authorityReject(state, *validation)
	}
	pending := state.PendingDelete
	revision, ok := shared.CheckedAddInt64(pending.ExpectedRevision, 1)
	if !ok {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeArithmeticOverflow, "INV-004", "KV revision overflowed."))
	}
	if command.Observation.KvRevision != revision || command.Observation.Epoch != pending.ExpectedEpoch || command.Observation.Lease != nil {
		return authorityFence(state, command, command.Observation,
			authorityError(AuthorityErrorCodeRevisionMismatch, "INV-004", "Compare-and-delete observation does not exactly confirm absence."))
	}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityDeleteConfirmed {
		return &AuthorityDeleteConfirmed{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Observation: command.Observation}
	})
	return authorityCommit(state, event, nil, nil, nil)
}

func authorityObserveRead(state *AuthorityState, command *ObserveAuthorityRead) *AuthorityDecision {
	if state.LastCompletedRequestId != nil && *state.LastCompletedRequestId == command.RequestId {
		return NewAuthorityDecision(state, nil, nil, nil, nil)
	}
	healthInput := authorityValidateHealth(command.Health)
	if healthInput != nil {
		return authorityReject(state, *healthInput)
	}
	if !authorityCasOutcomeIsDefined(command.Outcome) {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidInput, "INV-005", "Read outcome is outside the closed vocabulary."))
	}
	if state.PendingReadRequestId == nil || *state.PendingReadRequestId != command.RequestId ||
		state.PendingReadCandidateId == nil || *state.PendingReadCandidateId != command.CandidateId {
		return authorityReject(state, authorityError(AuthorityErrorCodeStaleObservation, "INV-005", "Read observation does not match pending read."))
	}
	if command.Outcome != AuthorityCasOutcomeSucceeded || command.Observation == nil {
		return authorityHold(state, command, authorityError(AuthorityErrorCodeCasUncertain, "INV-004", "Authority read is not certain."))
	}
	if command.Observation.AuthorityId != command.AuthorityId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Read observation belongs to another authority."))
	}
	validation := authorityValidateObservation(command.Observation)
	if validation == nil {
		validation = authorityValidateHealth(command.Health)
	}
	if validation != nil {
		return authorityReject(state, *validation)
	}
	if state.ReadResumeStatus != nil && *state.ReadResumeStatus == AuthorityStatusLeader {
		exact := authorityEnsureExactCurrent(state, command.Observation, command.Health)
		if exact != nil {
			return authorityLoseAuthority(state, command, command.Observation, *exact)
		}
	}
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityReadConfirmed {
		return &AuthorityReadConfirmed{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: command.AuthorityId, CandidateId: command.CandidateId, RequestId: command.RequestId},
			Observation: command.Observation, Health: command.Health}
	})
	var permit *MutationAuthorityPermit
	if state.ReadResumeStatus != nil && *state.ReadResumeStatus == AuthorityStatusLeader {
		permit = authorityCreatePermit(command)
	}
	return authorityCommit(state, event, nil, nil, permit)
}

func authorityEvaluate(state *AuthorityState, command *EvaluateMutationAuthority) *AuthorityDecision {
	if state.Status != AuthorityStatusLeader || state.Confirmed == nil {
		return authorityReject(state, authorityError(AuthorityErrorCodeInvalidTransition, "INV-004", "Mutation authority requires confirmed leader state."))
	}
	input := authorityValidateObservation(command.Observation)
	if input == nil {
		input = authorityValidateHealth(command.Health)
	}
	if input != nil {
		return authorityReject(state, *input)
	}
	if command.Observation.AuthorityId != command.AuthorityId || state.Confirmed.Lease == nil ||
		state.Confirmed.Lease.CandidateId != command.CandidateId {
		return authorityReject(state, authorityError(AuthorityErrorCodeIdentityMismatch, "INV-004", "Mutation evaluation identity differs from confirmed lease."))
	}
	exact := authorityEnsureExactCurrent(state, command.Observation, command.Health)
	if exact == nil {
		return NewAuthorityDecision(state, nil, nil, nil, authorityCreatePermit(command))
	}
	return authorityLoseAuthority(state, command, command.Observation, *exact)
}

func authorityEnsureExactCurrent(state *AuthorityState, observation *AuthorityObservation, health *AuthorityHealth) *AuthorityError {
	if safety := authoritySafetyError(health); safety != nil {
		return safety
	}
	if state.Confirmed == nil || observation.AuthorityId != shared.DerefString(state.AuthorityId) {
		return authorityErrorPointer(AuthorityErrorCodeIdentityMismatch, "INV-004", "Authority observation identity differs.")
	}
	if observation.Epoch > state.Confirmed.Epoch {
		return authorityErrorPointer(AuthorityErrorCodeEpochMismatch, "INV-004", "A higher fencing epoch was observed.")
	}
	if !observation.Equal(*state.Confirmed) {
		code := AuthorityErrorCodeRevisionMismatch
		if observation.Epoch != state.Confirmed.Epoch {
			code = AuthorityErrorCodeEpochMismatch
		}
		return authorityErrorPointer(code, "INV-004", "Lease observation does not exactly match confirmed ownership.")
	}
	return authorityLeaseError(observation, health)
}

func authorityLeaseError(observation *AuthorityObservation, health *AuthorityHealth) *AuthorityError {
	if observation.Lease == nil {
		return authorityErrorPointer(AuthorityErrorCodeLeaseExpired, "INV-004", "No active lease is observed.")
	}
	if health.ServerTime.Before(observation.Lease.ServerIssuedAt) || health.MonotonicElapsed < 0 {
		return authorityErrorPointer(AuthorityErrorCodeClockAnomaly, "INV-004", "Lease time moved backwards.")
	}
	if !shared.CanAddDuration(observation.Lease.ServerIssuedAt, observation.Lease.Duration) {
		return authorityErrorPointer(AuthorityErrorCodeArithmeticOverflow, "INV-004", "Lease expiry overflows timestamp range.")
	}
	expiry := observation.Lease.ServerIssuedAt.Add(observation.Lease.Duration)
	if health.MonotonicElapsed >= observation.Lease.Duration || !health.ServerTime.Before(expiry) {
		return authorityErrorPointer(AuthorityErrorCodeLeaseExpired, "INV-004", "Lease is expired at the supplied time boundary.")
	}
	return nil
}

func authoritySafetyError(health *AuthorityHealth) *AuthorityError {
	if !health.PartitionCertain {
		return authorityErrorPointer(AuthorityErrorCodePartitionUncertain, "INV-004", "Partition certainty is lost.")
	}
	if !health.ClockCertain {
		return authorityErrorPointer(AuthorityErrorCodeClockAnomaly, "INV-004", "Clock certainty is lost.")
	}
	return nil
}

func authorityValidateCommand(state *AuthorityState, command AuthorityCommand) *AuthorityError {
	common := command.authorityCommandCommon()
	if shared.IsNullOrWhiteSpace(common.AuthorityId) || shared.IsNullOrWhiteSpace(common.CandidateId) || shared.IsNullOrWhiteSpace(common.RequestId) {
		return authorityErrorPointer(AuthorityErrorCodeInvalidInput, "INV-005", "Authority, candidate, and request identities are required.")
	}
	if state.AuthorityId != nil &&
		(*state.AuthorityId != common.AuthorityId || shared.DerefString(state.CandidateId) != common.CandidateId) {
		return authorityErrorPointer(AuthorityErrorCodeIdentityMismatch, "INV-004", "Command identity differs from journal ownership.")
	}
	return nil
}

func authorityValidateObservation(observation *AuthorityObservation) *AuthorityError {
	if observation == nil || shared.IsNullOrWhiteSpace(observation.AuthorityId) ||
		shared.IsNullOrWhiteSpace(observation.ObservationId) || observation.KvRevision < 0 || observation.Epoch < 0 ||
		((observation.KvRevision == 0 || observation.Epoch == 0) &&
			(observation.KvRevision != 0 || observation.Epoch != 0 || observation.Lease != nil)) {
		return authorityErrorPointer(AuthorityErrorCodeInvalidInput, "INV-005", "Observation requires stable identity and either genesis zeroes or positive revision/epoch.")
	}
	if observation.Lease != nil && (shared.IsNullOrWhiteSpace(observation.Lease.CandidateId) ||
		shared.IsNullOrWhiteSpace(observation.Lease.LeaseId) || observation.Lease.ServerIssuedAt.IsZero() || observation.Lease.Duration <= 0) {
		return authorityErrorPointer(AuthorityErrorCodeInvalidInput, "INV-005", "Observed lease is malformed.")
	}
	return nil
}

func authorityValidateHealth(health *AuthorityHealth) *AuthorityError {
	if health == nil || health.ServerTime.IsZero() || health.MonotonicElapsed < 0 {
		return authorityErrorPointer(AuthorityErrorCodeInvalidInput, "INV-005", "Explicit server time and lease duration are required.")
	}
	return nil
}

func authorityLoseAuthority(state *AuthorityState, command AuthorityCommand, observation *AuthorityObservation, err AuthorityError) *AuthorityDecision {
	if err.Code == AuthorityErrorCodePartitionUncertain || err.Code == AuthorityErrorCodeClockAnomaly {
		return authorityHold(state, command, err)
	}
	return authorityFence(state, command, observation, err)
}

func authorityHold(state *AuthorityState, command AuthorityCommand, err AuthorityError) *AuthorityDecision {
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityHeld {
		common := command.authorityCommandCommon()
		return &AuthorityHeld{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: common.AuthorityId, CandidateId: common.CandidateId, RequestId: common.RequestId},
			HeldFrom: state.Status, Observation: authorityObservationFrom(command), Error: err}
	})
	return authorityCommit(state, event, nil, []AuthorityError{err}, nil)
}

func authorityFence(state *AuthorityState, command AuthorityCommand, observation *AuthorityObservation, err AuthorityError) *AuthorityDecision {
	event := authorityStamp(state, func(sequence int64, previous, digest string) *AuthorityFencedEvent {
		common := command.authorityCommandCommon()
		return &AuthorityFencedEvent{AuthorityEventBase: AuthorityEventBase{Sequence: sequence, PreviousDigest: previous,
			EventDigest: digest, AuthorityId: common.AuthorityId, CandidateId: common.CandidateId, RequestId: common.RequestId},
			Observation: observation, Error: err}
	})
	return authorityCommit(state, event, nil, []AuthorityError{err}, nil)
}

func authorityValidateNext(state *AuthorityState, event AuthorityEvent) *AuthorityError {
	common := event.authorityEventCommon()
	if common.Sequence != state.LastSequence+1 || common.PreviousDigest != state.JournalDigest {
		return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority journal chain is not append-only.")
	}
	digest, err := AuthorityDigest.Event(event)
	if err != nil || common.EventDigest != digest {
		return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority journal chain is not append-only.")
	}
	if shared.IsNullOrWhiteSpace(common.AuthorityId) || shared.IsNullOrWhiteSpace(common.CandidateId) || shared.IsNullOrWhiteSpace(common.RequestId) {
		return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Authority event identity is malformed.")
	}
	if state.AuthorityId != nil &&
		(*state.AuthorityId != common.AuthorityId || shared.DerefString(state.CandidateId) != common.CandidateId) {
		return authorityErrorPointer(AuthorityErrorCodeIdentityMismatch, "INV-004", "Authority journal mixes identities.")
	}
	if semantic := authorityValidateEventSemantics(state, event); semantic != nil {
		return semantic
	}
	allowed := false
	switch event.(type) {
	case *AuthoritySetRequested:
		requested := event.(*AuthoritySetRequested)
		if !requested.Pending.IsRenewal &&
			(state.Status == AuthorityStatusFollower || state.Status == AuthorityStatusReadOnlyHeld) {
			allowed = true
		}
		if requested.Pending.IsRenewal && state.Status == AuthorityStatusLeader {
			allowed = true
		}
	case *AuthoritySetConfirmed:
		allowed = state.Status == AuthorityStatusAcquisitionPending || state.Status == AuthorityStatusRenewalPending
	case *AuthoritySetRejected:
		allowed = state.Status == AuthorityStatusAcquisitionPending || state.Status == AuthorityStatusRenewalPending
	case *AuthorityDeleteRequested:
		allowed = state.Status == AuthorityStatusLeader
	case *AuthorityDeleteConfirmed:
		allowed = state.Status == AuthorityStatusReleasePending
	case *AuthorityReadRequested:
		allowed = state.Status == AuthorityStatusFollower || state.Status == AuthorityStatusLeader ||
			state.Status == AuthorityStatusReadOnlyHeld
	case *AuthorityReadConfirmed:
		allowed = state.Status == AuthorityStatusReadOnlyHeld
	case *AuthorityHeld:
		switch state.Status {
		case AuthorityStatusFollower, AuthorityStatusLeader, AuthorityStatusReadOnlyHeld,
			AuthorityStatusAcquisitionPending, AuthorityStatusRenewalPending, AuthorityStatusReleasePending:
			allowed = true
		}
	case *AuthorityFencedEvent:
		allowed = state.Status != AuthorityStatusFenced
	}
	if !allowed {
		return authorityErrorPointer(AuthorityErrorCodeInvalidTransition, "INV-004", "Authority journal transition is invalid.")
	}
	return nil
}

func authorityValidateEventSemantics(state *AuthorityState, event AuthorityEvent) *AuthorityError {
	switch value := event.(type) {
	case *AuthoritySetRequested:
		requested := value
		pending := requested.Pending
		if pending.RequestId != requested.RequestId || pending.ExpectedRevision < 0 ||
			pending.ExpectedEpoch < 0 || pending.ProposedEpoch <= 0 ||
			authorityValidateLease(pending.ProposedLease) != nil ||
			authorityValidateObservation(pending.ExpectedObservation) != nil ||
			authorityValidateHealth(pending.RequestedAtHealth) != nil ||
			pending.ExpectedRevision != pending.ExpectedObservation.KvRevision ||
			pending.ExpectedEpoch != pending.ExpectedObservation.Epoch ||
			pending.ExpectedObservation.AuthorityId != requested.AuthorityId ||
			authoritySafetyError(pending.RequestedAtHealth) != nil {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Pending CAS set is malformed.")
		}
		if pending.IsRenewal {
			if state.Confirmed == nil || pending.ProposedEpoch != pending.ExpectedEpoch ||
				pending.ExpectedRevision != state.Confirmed.KvRevision ||
				pending.ExpectedEpoch != state.Confirmed.Epoch ||
				!pending.ExpectedObservation.Equal(*state.Confirmed) ||
				pending.ProposedLease.CandidateId != shared.DerefString(state.CandidateId) ||
				state.Confirmed.Lease == nil || pending.ProposedLease.LeaseId != state.Confirmed.Lease.LeaseId ||
				!shared.InstantsEqual(pending.ProposedLease.ServerIssuedAt, pending.RequestedAtHealth.ServerTime) ||
				authorityEnsureExactCurrent(state, pending.ExpectedObservation, pending.RequestedAtHealth) != nil {
				return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Renewal request does not preserve exact lease ownership and epoch.")
			}
		} else {
			if pending.ExpectedEpoch < state.HighestEpoch || pending.ExpectedRevision < state.HighestKvRevision {
				return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Acquisition baseline regresses persisted authority high-water.")
			}
			baselineLease := pending.ExpectedObservation.Lease
			if baselineLease != nil {
				leaseError := authorityLeaseError(pending.ExpectedObservation, pending.RequestedAtHealth)
				if leaseError == nil || leaseError.Code != AuthorityErrorCodeLeaseExpired {
					return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Acquisition baseline lease was not expired.")
				}
			}
			if pending.ProposedLease.CandidateId != requested.CandidateId ||
				!shared.InstantsEqual(pending.ProposedLease.ServerIssuedAt, pending.RequestedAtHealth.ServerTime) {
				return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Acquisition proposal identity/time differs from request evidence.")
			}
			expectedEpoch, ok := shared.CheckedAddInt64(pending.ExpectedEpoch, 1)
			if !ok {
				return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Acquisition epoch overflowed in journal.")
			}
			if pending.ProposedEpoch != expectedEpoch {
				return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Acquisition does not advance exactly one epoch.")
			}
		}

	case *AuthoritySetConfirmed:
		confirmed := value
		if state.PendingSet == nil || state.PendingSet.RequestId != confirmed.RequestId ||
			confirmed.WasRenewal != state.PendingSet.IsRenewal ||
			authorityValidateObservation(confirmed.Observation) != nil ||
			authorityValidateHealth(confirmed.Health) != nil ||
			confirmed.Observation.Epoch != state.PendingSet.ProposedEpoch ||
			confirmed.Observation.Lease == nil || !confirmed.Observation.Lease.Equal(state.PendingSet.ProposedLease) ||
			confirmed.Observation.AuthorityId != confirmed.AuthorityId ||
			confirmed.CandidateId != state.PendingSet.ProposedLease.CandidateId {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Confirmed CAS does not exactly match pending request.")
		}
		expectedRevision, ok := shared.CheckedAddInt64(state.PendingSet.ExpectedRevision, 1)
		if !ok {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Confirmed CAS revision overflowed.")
		}
		if confirmed.Observation.KvRevision != expectedRevision {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Confirmed CAS revision is not the exact successor.")
		}
		if authoritySafetyError(confirmed.Health) != nil || authorityLeaseError(confirmed.Observation, confirmed.Health) != nil {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Confirmed lease was not valid at supplied result time.")
		}

	case *AuthoritySetRejected:
		rejected := value
		expectedCode := rejected.Error.Code
		switch rejected.Outcome {
		case AuthorityCasOutcomeConflict:
			expectedCode = AuthorityErrorCodeCasConflict
		case AuthorityCasOutcomeFailed:
			expectedCode = AuthorityErrorCodeCasFailed
		case AuthorityCasOutcomeUncertain:
			expectedCode = AuthorityErrorCodeCasUncertain
		}
		if state.PendingSet == nil || state.PendingSet.RequestId != rejected.RequestId ||
			!authorityCasOutcomeIsDefined(rejected.Outcome) || rejected.Outcome == AuthorityCasOutcomeSucceeded ||
			!authorityErrorCodeIsDefined(rejected.Error.Code) ||
			(rejected.Observation != nil && authorityValidateObservation(rejected.Observation) != nil) ||
			(rejected.Observation != nil && rejected.Observation.AuthorityId != rejected.AuthorityId) ||
			rejected.Error.Code != expectedCode {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Rejected CAS event does not match pending request.")
		}

	case *AuthorityDeleteRequested:
		requested := value
		if state.Confirmed == nil || state.Confirmed.Lease == nil ||
			requested.Pending.RequestId != requested.RequestId ||
			requested.CandidateId != state.Confirmed.Lease.CandidateId ||
			requested.Pending.ExpectedRevision != state.Confirmed.KvRevision ||
			requested.Pending.ExpectedEpoch != state.Confirmed.Epoch ||
			!requested.Pending.ExpectedLease.Equal(*state.Confirmed.Lease) ||
			authorityValidateHealth(requested.Pending.RequestedAtHealth) != nil ||
			authorityEnsureExactCurrent(state, state.Confirmed, requested.Pending.RequestedAtHealth) != nil {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Delete request does not exactly match confirmed lease.")
		}

	case *AuthorityDeleteConfirmed:
		confirmed := value
		if state.PendingDelete == nil || confirmed.RequestId != state.PendingDelete.RequestId ||
			authorityValidateObservation(confirmed.Observation) != nil || confirmed.Observation.Lease != nil ||
			confirmed.Observation.Epoch != state.PendingDelete.ExpectedEpoch ||
			confirmed.Observation.AuthorityId != confirmed.AuthorityId ||
			confirmed.CandidateId != state.PendingDelete.ExpectedLease.CandidateId {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Delete confirmation does not prove exact absence.")
		}
		expectedRevision, ok := shared.CheckedAddInt64(state.PendingDelete.ExpectedRevision, 1)
		if !ok {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Delete confirmation revision overflowed.")
		}
		if confirmed.Observation.KvRevision != expectedRevision {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Delete confirmation revision is not the exact successor.")
		}

	case *AuthorityReadRequested:
		requested := value
		if !authorityStatusIsDefined(requested.ResumeStatus) || requested.ResumeStatus == AuthorityStatusFenced {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Read request has invalid resume state.")
		}

	case *AuthorityReadConfirmed:
		confirmed := value
		if state.PendingReadRequestId == nil || *state.PendingReadRequestId != confirmed.RequestId ||
			state.PendingReadCandidateId == nil || *state.PendingReadCandidateId != confirmed.CandidateId ||
			authorityValidateObservation(confirmed.Observation) != nil || authorityValidateHealth(confirmed.Health) != nil ||
			confirmed.Observation.AuthorityId != confirmed.AuthorityId {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Read confirmation does not match pending read.")
		}
		if state.ReadResumeStatus != nil && *state.ReadResumeStatus == AuthorityStatusLeader &&
			authorityEnsureExactCurrent(state, confirmed.Observation, confirmed.Health) != nil {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-004", "Read cannot restore leader from mismatched or unsafe lease truth.")
		}

	case *AuthorityHeld:
		held := value
		if !authorityStatusIsDefined(held.HeldFrom) || !authorityErrorCodeIsDefined(held.Error.Code) ||
			held.HeldFrom != state.Status ||
			shared.IsNullOrWhiteSpace(held.Error.Requirement) || shared.IsNullOrWhiteSpace(held.Error.Message) ||
			(held.Observation != nil &&
				(authorityValidateObservation(held.Observation) != nil || held.Observation.AuthorityId != held.AuthorityId)) {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Hold does not match the current state.")
		}

	case *AuthorityFencedEvent:
		fenced := value
		if !authorityErrorCodeIsDefined(fenced.Error.Code) ||
			shared.IsNullOrWhiteSpace(fenced.Error.Requirement) ||
			shared.IsNullOrWhiteSpace(fenced.Error.Message) ||
			(fenced.Observation != nil &&
				(fenced.Observation.AuthorityId != fenced.AuthorityId ||
					authorityValidateObservation(fenced.Observation) != nil)) {
			return authorityErrorPointer(AuthorityErrorCodeInvalidJournal, "INV-005", "Fence evidence is outside the closed vocabulary or authority scope.")
		}
	}

	return nil
}

func authorityValidateLease(lease AuthorityLease) *AuthorityError {
	if shared.IsNullOrWhiteSpace(lease.CandidateId) || shared.IsNullOrWhiteSpace(lease.LeaseId) ||
		lease.ServerIssuedAt.IsZero() || lease.Duration <= 0 || !shared.CanAddDuration(lease.ServerIssuedAt, lease.Duration) {
		return authorityErrorPointer(AuthorityErrorCodeInvalidInput, "INV-005", "Lease is malformed.")
	}
	return nil
}

func authorityApply(state *AuthorityState, event AuthorityEvent) *AuthorityState {
	common := event.authorityEventCommon()
	next := *state
	next.AuthorityId = stringPointer(common.AuthorityId)
	next.CandidateId = stringPointer(common.CandidateId)
	next.LastSequence = common.Sequence
	next.JournalDigest = common.EventDigest

	switch value := event.(type) {
	case *AuthoritySetRequested:
		if value.Pending.IsRenewal {
			next.Status = AuthorityStatusRenewalPending
		} else {
			next.Status = AuthorityStatusAcquisitionPending
		}
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, value.Pending.ExpectedEpoch)
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, value.Pending.ExpectedRevision)
		pending := value.Pending
		next.PendingSet = &pending
		next.PendingDelete = nil
		next.PendingReadRequestId = nil
		next.PendingReadCandidateId = nil
		next.LastError = nil
	case *AuthoritySetConfirmed:
		next.Status = AuthorityStatusLeader
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, value.Observation.Epoch)
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, value.Observation.KvRevision)
		observation := *value.Observation
		next.Confirmed = &observation
		next.PendingSet = nil
		next.LastCompletedRequestId = stringPointer(value.RequestId)
		next.LastError = nil
	case *AuthoritySetRejected:
		if state.PendingSet != nil && state.PendingSet.IsRenewal {
			next.Status = AuthorityStatusFenced
		} else {
			next.Status = AuthorityStatusReadOnlyHeld
		}
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, authorityObservationEpochOrZero(value.Observation))
		next.PendingSet = nil
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, authorityObservationKvRevisionOrZero(value.Observation))
		next.LastCompletedRequestId = stringPointer(value.RequestId)
		err := value.Error
		next.LastError = &err
	case *AuthorityDeleteRequested:
		next.Status = AuthorityStatusReleasePending
		pending := value.Pending
		next.PendingDelete = &pending
		next.LastError = nil
	case *AuthorityDeleteConfirmed:
		next.Status = AuthorityStatusFollower
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, value.Observation.Epoch)
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, value.Observation.KvRevision)
		observation := *value.Observation
		next.Confirmed = &observation
		next.PendingDelete = nil
		next.LastCompletedRequestId = stringPointer(value.RequestId)
		next.LastError = nil
	case *AuthorityReadRequested:
		next.Status = AuthorityStatusReadOnlyHeld
		next.PendingReadRequestId = stringPointer(value.RequestId)
		next.PendingReadCandidateId = stringPointer(value.CandidateId)
		resume := value.ResumeStatus
		next.ReadResumeStatus = &resume
		next.LastError = nil
	case *AuthorityReadConfirmed:
		if state.ReadResumeStatus != nil && *state.ReadResumeStatus == AuthorityStatusLeader {
			next.Status = AuthorityStatusLeader
		} else {
			next.Status = AuthorityStatusFollower
		}
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, value.Observation.Epoch)
		observation := *value.Observation
		next.Confirmed = &observation
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, value.Observation.KvRevision)
		next.PendingReadRequestId = nil
		next.PendingReadCandidateId = nil
		next.ReadResumeStatus = nil
		next.LastError = nil
		next.LastCompletedRequestId = stringPointer(value.RequestId)
	case *AuthorityHeld:
		next.Status = AuthorityStatusReadOnlyHeld
		next.PendingSet = nil
		next.PendingDelete = nil
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, authorityObservationEpochOrZero(value.Observation))
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, authorityObservationKvRevisionOrZero(value.Observation))
		next.PendingReadRequestId = nil
		next.PendingReadCandidateId = nil
		if value.HeldFrom == AuthorityStatusLeader {
			next.ReadResumeStatus = statusPointer(AuthorityStatusLeader)
		} else {
			next.ReadResumeStatus = state.ReadResumeStatus
		}
		err := value.Error
		next.LastError = &err
	case *AuthorityFencedEvent:
		next.Status = AuthorityStatusFenced
		next.HighestEpoch = shared.MaxInt64(state.HighestEpoch, authorityObservationEpochOrZero(value.Observation))
		next.HighestKvRevision = shared.MaxInt64(state.HighestKvRevision, authorityObservationKvRevisionOrZero(value.Observation))
		next.PendingSet = nil
		next.PendingDelete = nil
		next.PendingReadRequestId = nil
		next.PendingReadCandidateId = nil
		next.ReadResumeStatus = nil
		err := value.Error
		next.LastError = &err
	default:
		panic(shared.InvalidArgument("Unsupported authority event."))
	}
	return &next
}

func authorityStamp[T AuthorityEvent](state *AuthorityState, factory func(sequence int64, previousDigest, eventDigest string) T) T {
	provisional := factory(state.LastSequence+1, state.JournalDigest, "")
	digest, err := AuthorityDigest.Event(provisional)
	if err != nil {
		panic(err)
	}
	return factory(provisional.authorityEventCommon().Sequence, provisional.authorityEventCommon().PreviousDigest, digest)
}

func authorityCommit(state *AuthorityState, event AuthorityEvent, intents []AuthorityIntent,
	errors []AuthorityError, mutationPermit *MutationAuthorityPermit) *AuthorityDecision {
	validation := authorityValidateNext(state, event)
	if validation != nil {
		return authorityReject(state, *validation)
	}
	return NewAuthorityDecision(authorityApply(state, event), []AuthorityEvent{event}, intents, errors, mutationPermit)
}

func authorityReject(state *AuthorityState, err AuthorityError) *AuthorityDecision {
	return NewAuthorityDecision(state, nil, nil, []AuthorityError{err}, nil)
}

func authorityCompletedRequestReuse(state *AuthorityState, requestId string) *AuthorityError {
	if state.LastCompletedRequestId != nil && *state.LastCompletedRequestId == requestId {
		return authorityErrorPointer(AuthorityErrorCodeStaleObservation, "INV-005",
			"A completed request identity cannot initiate another authority action.")
	}
	return nil
}

func authorityError(code AuthorityErrorCode, requirement, message string) AuthorityError {
	return AuthorityError{Code: code, Requirement: requirement, Message: message}
}

func authorityCreatePermit(command AuthorityCommand) *MutationAuthorityPermit {
	permit, err := NewMutationAuthorityPermit(command)
	if err != nil {
		panic(err)
	}
	return permit
}

func authorityObservationFrom(command AuthorityCommand) *AuthorityObservation {
	switch value := command.(type) {
	case *AcquireAuthority:
		return value.Baseline
	case *RenewAuthority:
		return value.Current
	case *ReleaseAuthority:
		return value.Current
	case *ObserveAuthorityCas:
		return value.Observation
	case *ObserveAuthorityDelete:
		return value.Observation
	case *ObserveAuthorityRead:
		return value.Observation
	case *EvaluateMutationAuthority:
		return value.Observation
	default:
		return nil
	}
}

func authorityErrorPointer(code AuthorityErrorCode, requirement, message string) *AuthorityError {
	err := authorityError(code, requirement, message)
	return &err
}
