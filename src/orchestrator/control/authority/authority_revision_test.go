package authority

import "testing"

func TestAuthorityCASAllowsStreamRevisionGapsAndReplays(t *testing.T) {
	history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
	proposal := pending.Intents[0].(*CompareAndSetLeaseIntent).ProposedLease
	observation := &AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 17, Epoch: 6, ObservationId: "interleaved-write", Lease: &proposal}
	confirmed, err := AuthorityEngine.Decide(history, NewObserveAuthorityCas("regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcomeSucceeded, observation, authorityHealthy(authorityStart, 0)))
	if err != nil || len(confirmed.Errors) != 0 || confirmed.State.Status != AuthorityStatusLeader || confirmed.MutationPermit == nil {
		t.Fatalf("successful nonconsecutive CAS: %+v %v", confirmed, err)
	}
	history = append(history, confirmed.EventsToAppend...)
	replayed, err := AuthorityEngine.Replay(history)
	if err != nil || len(replayed.Errors) != 0 || replayed.State.Confirmed.KvRevision != 17 {
		t.Fatalf("replay lost stream revision: %+v %v", replayed, err)
	}
	release, err := AuthorityEngine.Decide(history, NewReleaseAuthority("regional-authority", "candidate-a", "release-a", observation, authorityHealthy(authorityStart, 0)))
	if err != nil || len(release.Errors) != 0 {
		t.Fatalf("release intent: %+v %v", release, err)
	}
	history = append(history, release.EventsToAppend...)
	absent := &AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 25, Epoch: 6, ObservationId: "delete-after-sibling-writes"}
	deleted, err := AuthorityEngine.Decide(history, NewObserveAuthorityDelete("regional-authority", "candidate-a", "release-a", AuthorityCasOutcomeSucceeded, absent, authorityHealthy(authorityStart, 0)))
	if err != nil || len(deleted.Errors) != 0 || deleted.MutationPermit != nil {
		t.Fatalf("nonconsecutive delete: %+v %v", deleted, err)
	}
	history = append(history, deleted.EventsToAppend...)
	replayed, err = AuthorityEngine.Replay(history)
	if err != nil || len(replayed.Errors) != 0 || replayed.State.Confirmed.KvRevision != 25 {
		t.Fatalf("delete replay: %+v %v", replayed, err)
	}
}

func TestAuthorityRevisionGapsDoNotRelaxExactLeaseOrEpoch(t *testing.T) {
	for _, changed := range []string{"revision", "epoch", "candidate", "lease"} {
		t.Run(changed, func(t *testing.T) {
			history, pending := beginAcquisition(t, "candidate-a", "acquire-a")
			proposal := pending.Intents[0].(*CompareAndSetLeaseIntent).ProposedLease
			observation := &AuthorityObservation{AuthorityId: "regional-authority", KvRevision: 17, Epoch: 6, ObservationId: "conflicting-confirmation", Lease: &proposal}
			switch changed {
			case "revision":
				observation.KvRevision = 10
			case "epoch":
				observation.Epoch++
			case "candidate":
				proposal.CandidateId = "candidate-b"
			case "lease":
				proposal.LeaseId = "another-lease"
			}
			decision, err := AuthorityEngine.Decide(history, NewObserveAuthorityCas("regional-authority", "candidate-a", "acquire-a", AuthorityCasOutcomeSucceeded, observation, authorityHealthy(authorityStart, 0)))
			if err != nil || decision.State.Status != AuthorityStatusFenced || decision.MutationPermit != nil {
				t.Fatalf("mismatched confirmation granted authority: %+v %v", decision, err)
			}
		})
	}
}
