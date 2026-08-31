package membership

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

type membershipWatchEntry struct {
	key       string
	value     []byte
	revision  uint64
	operation jetstream.KeyValueOp
}

func (e membershipWatchEntry) Bucket() string                  { return "ORCH_RUNTIME" }
func (e membershipWatchEntry) Key() string                     { return e.key }
func (e membershipWatchEntry) Value() []byte                   { return e.value }
func (e membershipWatchEntry) Revision() uint64                { return e.revision }
func (e membershipWatchEntry) Created() time.Time              { return time.Now().UTC() }
func (e membershipWatchEntry) Delta() uint64                   { return 0 }
func (e membershipWatchEntry) Operation() jetstream.KeyValueOp { return e.operation }

type membershipWatcher struct {
	updates <-chan jetstream.KeyValueEntry
}

func (w membershipWatcher) Updates() <-chan jetstream.KeyValueEntry { return w.updates }
func (w membershipWatcher) Stop() error                             { return nil }

type reconnectingMembershipStore struct {
	jetstream.KeyValue
	mu       sync.Mutex
	watchers []<-chan jetstream.KeyValueEntry
	errors   []error
	calls    int
}

func (s *reconnectingMembershipStore) Watch(
	_ context.Context,
	_ string,
	_ ...jetstream.WatchOpt,
) (jetstream.KeyWatcher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := s.calls
	s.calls++
	if index < len(s.errors) && s.errors[index] != nil {
		return nil, s.errors[index]
	}
	if index >= len(s.watchers) {
		return nil, errors.New("unexpected membership watch")
	}
	return membershipWatcher{updates: s.watchers[index]}, nil
}

func (s *reconnectingMembershipStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func signedRuntimeMember(
	t *testing.T,
	identity *RegionalRuntimeMembershipIdentity,
	instance, session string,
	now time.Time,
) RegionalRuntimeMember {
	t.Helper()
	member := RegionalRuntimeMember{
		SchemaVersion:     protocol.ProtocolVersion.Current(),
		Cell:              "gru",
		Cluster:           "orchestrator-control-gru",
		Instance:          instance,
		SessionId:         session,
		Build:             "test-build",
		Capabilities:      []string{"authority", "runtime"},
		StartedAt:         now.Add(-time.Minute),
		ObservedAt:        now.Add(-time.Second),
		LeaseExpiresAt:    now.Add(20 * time.Second),
		AuthorityState:    "follower",
		AuthorityEpoch:    4,
		AuthorityRevision: 9,
		IdentityKeyId:     identity.KeyId,
		IdentityPublicKey: identity.PublicKey,
	}
	member.IdentitySignature = identity.Sign(member)
	if !member.IsValidFor("gru", now) || !member.VerifySignedIdentity() {
		t.Fatal("test member is not valid and signed")
	}
	return member
}

func watchEntry(t *testing.T, member RegionalRuntimeMember, revision uint64) jetstream.KeyValueEntry {
	t.Helper()
	value, err := json.Marshal(member)
	if err != nil {
		t.Fatalf("marshal member: %v", err)
	}
	return membershipWatchEntry{
		key:       "controller." + member.Instance,
		value:     value,
		revision:  revision,
		operation: jetstream.KeyValuePut,
	}
}

func TestWatchReconnectReconcilesMembersMissingFromReplay(t *testing.T) {
	now := time.Now().UTC()
	selfIdentity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(selfIdentity.Dispose)
	peerIdentity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peerIdentity.Dispose)
	self := signedRuntimeMember(t, selfIdentity, "controller-1", "11111111111111111111111111111111", now)
	peer := signedRuntimeMember(t, peerIdentity, "controller-2", "22222222222222222222222222222222", now)

	initial := make(chan jetstream.KeyValueEntry, 3)
	initial <- watchEntry(t, self, 1)
	initial <- watchEntry(t, peer, 2)
	initial <- nil
	close(initial)
	reconnected := make(chan jetstream.KeyValueEntry, 2)
	reconnected <- watchEntry(t, self, 3)
	reconnected <- nil

	store := &reconnectingMembershipStore{watchers: []<-chan jetstream.KeyValueEntry{initial, reconnected}}
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		store:             store,
		topology:          NewTopology("gru", 1, "controller-1", "ORCH_RUNTIME"),
		key:               "controller.controller-1",
		sessionId:         self.SessionId,
		members:           map[string]RegionalRuntimeMember{},
		previousMembers:   map[string]RegionalRuntimeMember{},
		identityPins:      map[string]string{},
		stoppingCtx:       stoppingCtx,
		stopping:          stopping,
		watchLoopDone:     make(chan struct{}),
		selfObserved:      make(chan struct{}),
		watchRetryDelay:   time.Millisecond,
		HeartbeatInterval: time.Hour,
	}
	go membership.watchLoop()

	deadline := time.Now().Add(time.Second)
	for {
		snapshot := membership.Snapshot()
		if store.callCount() >= 2 && len(snapshot.Members) == 1 && snapshot.Members[0].Instance == "controller-1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reconnect did not reconcile stale peer: calls=%d snapshot=%#v", store.callCount(), snapshot)
		}
		time.Sleep(time.Millisecond)
	}

	stopping()
	close(reconnected)
	select {
	case <-membership.watchLoopDone:
	case <-time.After(time.Second):
		t.Fatal("watch loop did not stop after reconnect test")
	}
}

func TestWatchReconnectRetriesAcquisitionWithoutPublishingPartialState(t *testing.T) {
	now := time.Now().UTC()
	identity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Dispose)
	self := signedRuntimeMember(t, identity, "controller-1", "11111111111111111111111111111111", now)
	reconnected := make(chan jetstream.KeyValueEntry, 2)
	reconnected <- watchEntry(t, self, 1)
	reconnected <- nil
	store := &reconnectingMembershipStore{
		watchers: []<-chan jetstream.KeyValueEntry{nil, reconnected},
		errors:   []error{errors.New("transport disconnected")},
	}
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		store:           store,
		topology:        NewTopology("gru", 1, "controller-1", "ORCH_RUNTIME"),
		key:             "controller.controller-1",
		sessionId:       self.SessionId,
		members:         map[string]RegionalRuntimeMember{},
		previousMembers: map[string]RegionalRuntimeMember{},
		identityPins:    map[string]string{},
		stoppingCtx:     stoppingCtx,
		stopping:        stopping,
		watchLoopDone:   make(chan struct{}),
		selfObserved:    make(chan struct{}),
		watchRetryDelay: time.Millisecond,
	}
	go membership.watchLoop()
	select {
	case <-membership.selfObserved:
	case <-time.After(time.Second):
		t.Fatal("watch acquisition was not retried")
	}
	if store.callCount() != 2 {
		t.Fatalf("Watch call count = %d, want 2", store.callCount())
	}
	stopping()
	close(reconnected)
	<-membership.watchLoopDone
}

func TestMembershipMutationFencesSessionAndAuthorityEpoch(t *testing.T) {
	now := time.Now().UTC()
	identity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Dispose)
	proposed := signedRuntimeMember(t, identity, "controller-1", "11111111111111111111111111111111", now)

	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", proposed, nil, now); got != RegionalRuntimeMembershipMutationClassCreateOwnRecord {
		t.Fatalf("empty slot decision = %s", got)
	}
	existing := proposed
	existing.AuthorityRevision--
	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", proposed, &existing, now); got != RegionalRuntimeMembershipMutationClassRenewOwnRecord {
		t.Fatalf("same session renewal decision = %s", got)
	}
	stale := proposed
	stale.AuthorityEpoch--
	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", stale, &existing, now); got != RegionalRuntimeMembershipMutationClassRejectStaleEpoch {
		t.Fatalf("stale epoch decision = %s", got)
	}
	foreign := proposed
	foreign.SessionId = "22222222222222222222222222222222"
	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", foreign, &existing, now); got != RegionalRuntimeMembershipMutationClassHoldForLiveForeignLease {
		t.Fatalf("live foreign lease decision = %s", got)
	}
	existing.ObservedAt = now.Add(-30 * time.Second)
	existing.LeaseExpiresAt = now.Add(-10 * time.Second)
	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", foreign, &existing, now); got != RegionalRuntimeMembershipMutationClassTakeOverExpiredLease {
		t.Fatalf("expired lease takeover decision = %s", got)
	}
	wrongCell := proposed
	wrongCell.Cell = "sfo"
	if got := RegionalRuntimeMembershipMutation.Decide("gru", "controller-1", wrongCell, nil, now); got != RegionalRuntimeMembershipMutationClassRejectWrongBinding {
		t.Fatalf("wrong-cell decision = %s", got)
	}
}

func TestMembershipReaderClassifiesConflictBeforeUnexpectedSlot(t *testing.T) {
	now := time.Now().UTC()
	identity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Dispose)
	previous := signedRuntimeMember(t, identity, "controller-9", "11111111111111111111111111111111", now)
	conflict := signedRuntimeMember(t, identity, "controller-9", "22222222222222222222222222222222", now)
	expected := RegionalRuntimeMembershipReader.ExpectedInstances(3)
	if got := RegionalRuntimeMembershipReader.Classify("gru", "controller-9", expected, &previous, &conflict, now); got != RegionalRuntimeMembershipRecordClassConflictingSession {
		t.Fatalf("classification = %s, want conflicting session", got)
	}
	if conflict.IdentitySignature[0] == 'A' {
		conflict.IdentitySignature = "B" + conflict.IdentitySignature[1:]
	} else {
		conflict.IdentitySignature = "A" + conflict.IdentitySignature[1:]
	}
	if got := RegionalRuntimeMembershipReader.Classify("gru", "controller-9", expected, &previous, &conflict, now); got != RegionalRuntimeMembershipRecordClassInvalidSignature {
		t.Fatalf("invalid-signature classification = %s", got)
	}
}
