package control

// AuthorityDigestEmptyJournalDigest mirrors AuthorityDigest.EmptyJournalDigest.
var AuthorityDigestEmptyJournalDigest = digestHash("TerraScale.AuthorityJournal.v1")

var AuthorityDigest authorityDigest

type authorityDigest struct{}

func (authorityDigest) Event(event AuthorityEvent) (string, error) {
	return authorityEncodeEvent(event, false)
}

func (authorityDigest) State(state *AuthorityState) string {
	w := newDigestWriter()
	w.WriteString("authority-state-v1")
	authorityAppendStateValues(w, state)
	return digestHash(w.Finish())
}

func (authorityDigest) Decision(state *AuthorityState, events []AuthorityEvent, intents []AuthorityIntent,
	errors []AuthorityError, permit *MutationAuthorityPermit) string {
	w := newDigestWriter()
	w.WriteString("authority-decision-v1")
	w.WriteString(AuthorityDigest.State(state))
	w.WriteArrayHeader(len(events))
	for _, item := range events {
		encoded, err := authorityEncodeEvent(item, true)
		if err != nil {
			panic(err)
		}
		w.WriteRaw(encoded)
	}
	w.WriteArrayFooter()
	w.WriteArrayHeader(len(intents))
	for _, item := range intents {
		authorityAppendIntent(w, item)
	}
	w.WriteArrayFooter()
	w.WriteArrayHeader(len(errors))
	for _, item := range errors {
		authorityAppendErrorValue(w, item)
	}
	w.WriteArrayFooter()
	if permit == nil {
		w.WriteNull()
	} else {
		w.WriteRaw(authorityEncodePermit(permit))
	}
	return digestHash(w.Finish())
}

func authorityAppendStateValues(w *digestWriter, state *AuthorityState) {
	w.WriteStringPointer(state.AuthorityId)
	w.WriteStringPointer(state.CandidateId)
	w.WriteInt64(int64(state.Status))
	w.WriteInt64(state.LastSequence)
	w.WriteString(state.JournalDigest)
	w.WriteInt64(state.HighestEpoch)
	w.WriteInt64(state.HighestKvRevision)
	authorityAppendObservation(w, state.Confirmed)
	authorityAppendPendingSetPointer(w, state.PendingSet)
	authorityAppendPendingDeletePointer(w, state.PendingDelete)
	w.WriteStringPointer(state.PendingReadRequestId)
	w.WriteStringPointer(state.PendingReadCandidateId)
	if state.ReadResumeStatus == nil {
		w.WriteNull()
	} else {
		w.WriteInt64(int64(*state.ReadResumeStatus))
	}
	w.WriteStringPointer(state.LastCompletedRequestId)
	if state.LastError == nil {
		w.WriteNull()
	} else {
		authorityAppendErrorValue(w, *state.LastError)
	}
}

func authorityEncodeEvent(event AuthorityEvent, includeDigest bool) (string, error) {
	w := newDigestWriter()
	switch value := event.(type) {
	case *AuthoritySetRequested:
		w.WriteString("set-requested")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendPendingSetValue(w, value.Pending)
	case *AuthoritySetConfirmed:
		w.WriteString("set-confirmed")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendObservation(w, value.Observation)
		authorityAppendHealth(w, value.Health)
		w.WriteBool(value.WasRenewal)
	case *AuthoritySetRejected:
		w.WriteString("set-rejected")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		w.WriteInt64(int64(value.Outcome))
		authorityAppendObservation(w, value.Observation)
		authorityAppendErrorValue(w, value.Error)
	case *AuthorityDeleteRequested:
		w.WriteString("delete-requested")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendPendingDeleteValue(w, value.Pending)
	case *AuthorityDeleteConfirmed:
		w.WriteString("delete-confirmed")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendObservation(w, value.Observation)
	case *AuthorityReadRequested:
		w.WriteString("read-requested")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		w.WriteInt64(int64(value.ResumeStatus))
	case *AuthorityReadConfirmed:
		w.WriteString("read-confirmed")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendObservation(w, value.Observation)
		authorityAppendHealth(w, value.Health)
	case *AuthorityHeld:
		w.WriteString("held")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		w.WriteInt64(int64(value.HeldFrom))
		authorityAppendObservation(w, value.Observation)
		authorityAppendErrorValue(w, value.Error)
	case *AuthorityFencedEvent:
		w.WriteString("fenced")
		authorityAppendEventCommon(w, value.authorityEventCommon(), includeDigest)
		authorityAppendObservation(w, value.Observation)
		authorityAppendErrorValue(w, value.Error)
	default:
		return "", invalidArgument("Unsupported digest value for authority event.")
	}
	return w.Finish(), nil
}

func authorityAppendEventCommon(w *digestWriter, value *AuthorityEventBase, includeDigest bool) {
	w.WriteInt64(value.Sequence)
	w.WriteString(value.PreviousDigest)
	if includeDigest {
		w.WriteString(value.EventDigest)
	} else {
		w.WriteNull()
	}
	w.WriteString(value.AuthorityId)
	w.WriteString(value.CandidateId)
	w.WriteString(value.RequestId)
}

func authorityAppendLease(w *digestWriter, lease AuthorityLease) {
	w.WriteRaw(authorityEncode(
		"lease-v1", func(next *digestWriter) {
			next.WriteString(lease.CandidateId)
			next.WriteString(lease.LeaseId)
			next.WriteTime(lease.ServerIssuedAt)
			next.WriteDuration(lease.Duration)
		}))
}

func authorityAppendObservation(w *digestWriter, observation *AuthorityObservation) {
	if observation == nil {
		w.WriteNull()
		return
	}
	w.WriteRaw(authorityEncode(
		"observation-v1", func(next *digestWriter) {
			next.WriteString(observation.AuthorityId)
			next.WriteInt64(observation.KvRevision)
			next.WriteInt64(observation.Epoch)
			next.WriteString(observation.ObservationId)
			if observation.Lease == nil {
				next.WriteNull()
			} else {
				authorityAppendLease(next, *observation.Lease)
			}
		}))
}

func authorityAppendHealth(w *digestWriter, health *AuthorityHealth) {
	if health == nil {
		w.WriteNull()
		return
	}
	w.WriteRaw(authorityEncode(
		"health-v1", func(next *digestWriter) {
			next.WriteTime(health.ServerTime)
			next.WriteDuration(health.MonotonicElapsed)
			next.WriteBool(health.PartitionCertain)
			next.WriteBool(health.ClockCertain)
		}))
}

func authorityAppendPendingSetPointer(w *digestWriter, pending *PendingAuthoritySet) {
	if pending == nil {
		w.WriteNull()
		return
	}
	authorityAppendPendingSetValue(w, *pending)
}

func authorityAppendPendingSetValue(w *digestWriter, pending PendingAuthoritySet) {
	w.WriteRaw(authorityEncode(
		"pending-set-v1", func(next *digestWriter) {
			next.WriteString(pending.RequestId)
			next.WriteInt64(pending.ExpectedRevision)
			next.WriteInt64(pending.ExpectedEpoch)
			next.WriteInt64(pending.ProposedEpoch)
			authorityAppendLease(next, pending.ProposedLease)
			authorityAppendObservation(next, pending.ExpectedObservation)
			authorityAppendHealth(next, pending.RequestedAtHealth)
			next.WriteBool(pending.IsRenewal)
		}))
}

func authorityAppendPendingDeletePointer(w *digestWriter, pending *PendingAuthorityDelete) {
	if pending == nil {
		w.WriteNull()
		return
	}
	authorityAppendPendingDeleteValue(w, *pending)
}

func authorityAppendPendingDeleteValue(w *digestWriter, pending PendingAuthorityDelete) {
	w.WriteRaw(authorityEncode(
		"pending-delete-v1", func(next *digestWriter) {
			next.WriteString(pending.RequestId)
			next.WriteInt64(pending.ExpectedRevision)
			next.WriteInt64(pending.ExpectedEpoch)
			authorityAppendLease(next, pending.ExpectedLease)
			authorityAppendHealth(next, pending.RequestedAtHealth)
		}))
}

func authorityAppendErrorValue(w *digestWriter, err AuthorityError) {
	w.WriteRaw(authorityEncode(
		"error-v1", func(next *digestWriter) {
			next.WriteInt64(int64(err.Code))
			next.WriteString(err.Requirement)
			next.WriteString(err.Message)
		}))
}

func authorityAppendIntent(w *digestWriter, intent AuthorityIntent) {
	switch value := intent.(type) {
	case *CompareAndSetLeaseIntent:
		w.WriteRaw(authorityEncode(
			"cas-set-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.RequestId)
				next.WriteInt64(value.ExpectedRevision)
				next.WriteInt64(value.ExpectedEpoch)
				next.WriteInt64(value.ProposedEpoch)
				authorityAppendLease(next, value.ProposedLease)
			}))
	case *CompareAndDeleteLeaseIntent:
		w.WriteRaw(authorityEncode(
			"cas-delete-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.RequestId)
				next.WriteInt64(value.ExpectedRevision)
				next.WriteInt64(value.ExpectedEpoch)
				authorityAppendLease(next, value.ExpectedLease)
			}))
	case *ReadAuthorityIntent:
		w.WriteRaw(authorityEncode(
			"read-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.RequestId)
				next.WriteString(value.CandidateId)
				next.WriteInt64(int64(value.ResumeStatus))
				next.WriteInt64(value.ExpectedHighestEpoch)
				next.WriteInt64(value.ExpectedHighestKvRevision)
				authorityAppendObservation(next, value.ExpectedConfirmedObservation)
			}))
	}
}

func authorityEncodePermit(permit *MutationAuthorityPermit) string {
	return authorityEncode(
		"mutation-permit-v1", func(next *digestWriter) {
			next.WriteString(authorityEncodePermitCommand(permit.authorizingCommand))
			next.WriteString(permit.AuthorityId)
			next.WriteString(permit.CandidateId)
			next.WriteString(permit.RequestId())
			next.WriteString(permit.LeaseId)
			next.WriteInt64(permit.Epoch)
			next.WriteInt64(permit.KvRevision)
			next.WriteString(permit.ObservationId)
			next.WriteTime(permit.EvaluatedServerTime)
			next.WriteDuration(permit.EvaluatedMonotonicElapsed)
		})
}

func authorityEncodePermitCommand(command AuthorityCommand) string {
	switch value := command.(type) {
	case *ObserveAuthorityCas:
		return authorityEncode(
			"observe-authority-cas-command-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.CandidateId)
				next.WriteString(value.RequestId)
				next.WriteInt64(int64(value.Outcome))
				authorityAppendObservation(next, value.Observation)
				authorityAppendHealth(next, value.Health)
			})
	case *ObserveAuthorityRead:
		return authorityEncode(
			"observe-authority-read-command-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.CandidateId)
				next.WriteString(value.RequestId)
				next.WriteInt64(int64(value.Outcome))
				authorityAppendObservation(next, value.Observation)
				authorityAppendHealth(next, value.Health)
			})
	case *EvaluateMutationAuthority:
		return authorityEncode(
			"evaluate-mutation-authority-command-v1", func(next *digestWriter) {
				next.WriteString(value.AuthorityId)
				next.WriteString(value.CandidateId)
				next.WriteString(value.RequestId)
				authorityAppendObservation(next, value.Observation)
				authorityAppendHealth(next, value.Health)
			})
	default:
		panic(invalidArgument("Unsupported permit command."))
	}
}

func authorityEncode(label string, body func(w *digestWriter)) string {
	w := newDigestWriter()
	w.WriteString(label)
	body(w)
	return w.Finish()
}
