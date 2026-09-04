package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

type regionalRuntimeMembershipHeartbeatStore struct {
	jetstream.KeyValue
	update func(context.Context, string, []byte, uint64) (uint64, error)
}

func (s regionalRuntimeMembershipHeartbeatStore) Update(
	ctx context.Context, key string, value []byte, revision uint64,
) (uint64, error) {
	return s.update(ctx, key, value, revision)
}

func newRegionalRuntimeMembershipForHeartbeat(
	ticks <-chan time.Time,
	update func(context.Context, string, []byte, uint64) (uint64, error),
) *RegionalRuntimeMembership {
	now := time.Now().UTC()
	identity, err := RegionalRuntimeMembershipIdentityCreate()
	if err != nil {
		panic(err)
	}
	stoppingCtx, stopping := context.WithCancel(context.Background())

	membership := &RegionalRuntimeMembership{
		HeartbeatInterval: time.Hour,
		LeaseDuration:     20 * time.Second,
		store:             regionalRuntimeMembershipHeartbeatStore{update: update},
		topology:          &messaging.NatsTopology{Cell: "gru", Replicas: 1, Instance: "controller-1"},
		sessionId:         "0123456789abcdef0123456789abcdef",
		build:             "test-build",
		capabilities:      []string{"authority"},
		startedAt:         now.Add(-time.Second),
		authority: func() authority.RegionalAuthoritySnapshot {
			leaseExpiresAt := time.Now().UTC().Add(time.Minute)
			return authority.RegionalAuthoritySnapshot{
				State:          "leader",
				IsLeader:       true,
				Epoch:          1,
				KvRevision:     1,
				LeaseExpiresAt: &leaseExpiresAt,
				ObservedAt:     time.Now().UTC(),
			}
		},
		identity:        identity,
		stoppingCtx:     stoppingCtx,
		stopping:        stopping,
		watchLoopDone:   make(chan struct{}),
		heartbeatDone:   make(chan struct{}),
		heartbeatTicks:  ticks,
		members:         map[string]RegionalRuntimeMember{},
		previousMembers: map[string]RegionalRuntimeMember{},
		identityPins:    map[string]string{},
	}
	return membership
}

func TestRegionalRuntimeMembershipHeartbeatMarshalFailureCompletesWithError(t *testing.T) {
	ticks := make(chan time.Time, 1)
	want := errors.New("marshal failed")
	membership := newRegionalRuntimeMembershipForHeartbeat(ticks, func(context.Context, string, []byte, uint64) (uint64, error) {
		return 0, errors.New("unexpected update call")
	})
	membership.marshal = func(any) ([]byte, error) { return nil, want }
	membership.heartbeatStarted = 1

	completion := membership.Completion()
	go membership.heartbeatLoop()
	ticks <- time.Now()

	select {
	case <-completion:
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure did not complete membership")
	}

	if !errors.Is(membership.LastFailure(), want) {
		t.Fatalf("LastFailure = %v, want %v", membership.LastFailure(), want)
	}
	if got := membership.Dispose(); !errors.Is(got, want) {
		t.Fatalf("Dispose = %v, want %v", got, want)
	}
}

func TestRegionalRuntimeMembershipHeartbeatUpdateFailureDegradesHealth(t *testing.T) {
	ticks := make(chan time.Time, 1)
	want := errors.New("update failed")
	membership := newRegionalRuntimeMembershipForHeartbeat(ticks, func(context.Context, string, []byte, uint64) (uint64, error) {
		return 0, want
	})
	now := time.Now().UTC()
	document, err := membership.document(now)
	if err != nil {
		t.Fatal(err)
	}
	membership.members[membership.key] = document
	membership.heartbeatStarted = 1

	go membership.heartbeatLoop()
	ticks <- now
	select {
	case <-membership.heartbeatDone:
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure did not stop loop")
	}

	health := membership.Health()
	if health.ActiveControllers != 0 || health.Condition != RegionalRuntimeMembershipConditionUnavailable {
		t.Fatalf("health after heartbeat failure = %+v, want unavailable with no active controllers", health)
	}
	if !errors.Is(membership.LastFailure(), want) {
		t.Fatalf("LastFailure = %v, want %v", membership.LastFailure(), want)
	}
	if got := membership.Dispose(); !errors.Is(got, want) {
		t.Fatalf("Dispose = %v, want %v", got, want)
	}
}

func TestRegionalRuntimeMembershipDisposeStopsHeartbeatWithoutFailure(t *testing.T) {
	ticks := make(chan time.Time)
	membership := newRegionalRuntimeMembershipForHeartbeat(ticks, func(context.Context, string, []byte, uint64) (uint64, error) {
		return 1, nil
	})
	close(membership.watchLoopDone)
	membership.heartbeatStarted = 1
	completion := membership.Completion()
	go membership.heartbeatLoop()

	if err := membership.Dispose(); err != nil {
		t.Fatalf("Dispose returned unexpected error: %v", err)
	}
	select {
	case <-completion:
	case <-time.After(time.Second):
		t.Fatal("normal disposal did not complete membership")
	}
	if err := membership.LastFailure(); err != nil {
		t.Fatalf("normal disposal recorded failure: %v", err)
	}
}

func TestRegionalRuntimeMembershipDisposeWaitsForHeartbeat(t *testing.T) {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		stopping:      stopping,
		stoppingCtx:   stoppingCtx,
		watchLoopDone: make(chan struct{}),
		heartbeatDone: make(chan struct{}),
	}
	// This models a normally started membership. The heartbeat must finish
	// before Dispose proceeds to its compare-and-delete section.
	membership.watchStarted = 1
	membership.heartbeatStarted = 1
	close(membership.watchLoopDone)

	disposed := make(chan struct{})
	go func() {
		_ = membership.Dispose()
		close(disposed)
	}()

	select {
	case <-disposed:
		t.Fatal("Dispose returned before heartbeat completion")
	case <-time.After(25 * time.Millisecond):
	}

	close(membership.heartbeatDone)
	select {
	case <-disposed:
	case <-time.After(time.Second):
		t.Fatal("Dispose did not complete after heartbeat completion")
	}
}

func TestRegionalRuntimeMembershipDisposeBeforeHeartbeatStartDoesNotBlock(t *testing.T) {
	stoppingCtx, stopping := context.WithCancel(context.Background())
	membership := &RegionalRuntimeMembership{
		stopping:      stopping,
		stoppingCtx:   stoppingCtx,
		watchLoopDone: make(chan struct{}),
		heartbeatDone: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		_ = membership.Dispose()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Dispose blocked before heartbeat startup")
	}
}

func TestRegionalRuntimeMembershipRejectsNilContext(t *testing.T) {
	topology := messaging.NewNatsTopology("membership-test", 1, "one")
	if _, err := RegionalRuntimeMembershipStartAsync(nil, nil, topology, "build", []string{"runtime"}, time.Now().UTC(), func() authority.RegionalAuthoritySnapshot {
		return authority.RegionalAuthoritySnapshot{}
	}, nil); err == nil {
		t.Fatal("nil context was accepted")
	}
}

func TestRegionalRuntimeMembershipNilReceiverIsSafe(t *testing.T) {
	var membership *RegionalRuntimeMembership
	if membership.Completion() != nil {
		t.Fatal("nil Completion should return nil")
	}
	if snapshot := membership.Snapshot(); snapshot.SchemaVersion != 0 {
		t.Fatalf("nil Snapshot = %#v", snapshot)
	}
	if membership.Health().ActiveControllers != 0 {
		t.Fatal("nil Health should return the zero projection")
	}
	if membership.LastFailure() != nil {
		t.Fatal("nil LastFailure should return nil")
	}
	if err := membership.Dispose(); err != nil {
		t.Fatalf("nil Dispose returned %v", err)
	}
}

func TestRegionalRuntimeMembershipSnapshotDoesNotExposeCapabilityStorage(t *testing.T) {
	membership := newRegionalRuntimeMembershipForHeartbeat(nil, nil)
	document, err := membership.document(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	membership.members[membership.key] = document

	snapshot := membership.Snapshot()
	if len(snapshot.Members) != 1 || len(snapshot.Members[0].Capabilities) != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	snapshot.Members[0].Capabilities[0] = "caller-mutated"
	if got := membership.members[membership.key].Capabilities[0]; got != "authority" {
		t.Fatalf("snapshot mutation changed internal capabilities to %q", got)
	}
}

func TestRegionalRuntimeMembershipRejectsRetiredDiscoveryRecords(t *testing.T) {
	membership := newRegionalRuntimeMembershipForHeartbeat(nil, nil)
	document, err := membership.document(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != protocol.ProtocolVersion.Current() || !document.IsValidFor("gru", time.Now().UTC()) {
		t.Fatalf("current discovery document = %#v", document)
	}

	document.SchemaVersion = protocol.ProtocolVersion.Current() - 1
	if document.IsValidFor("gru", time.Now().UTC()) {
		t.Fatal("retired discovery record was accepted")
	}
}
