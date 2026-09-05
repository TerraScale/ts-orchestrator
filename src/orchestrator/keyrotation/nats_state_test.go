package keyrotation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func rotationTestState() security.PersistedState {
	now := time.Now().UTC()
	return security.PersistedState{OperationID: "capability-rotation-1", Generation: 1, LastVersion: 1, NewVersion: 1, Phase: security.PhasePrepare, LastAt: now, Regions: []string{"gru", "sfo", "fra"}, NewNotBefore: now, NewExpiry: now.Add(time.Hour), Members: map[string][]string{}, Distributed: map[string]bool{}, Verified: map[string]bool{}, Activated: map[string]bool{}, Retired: map[string]bool{}}
}
func newRotationTestSession(t *testing.T, nc *nats.Conn, lease authority.RegionalAuthorityLeaseDocument) *NATSStateStore {
	t.Helper()
	session, err := NewNATSStateStore(NATSStateStoreConfig{Connection: nc, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func readRotationTestLease(t *testing.T, ctx context.Context, kv jetstream.KeyValue) authority.RegionalAuthorityLeaseDocument {
	t.Helper()
	entry, err := kv.Get(ctx, "authority.global")
	if err != nil {
		t.Fatal(err)
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(entry.Value(), &lease) != nil {
		t.Fatal("invalid fixture lease")
	}
	return lease
}

func TestNATSRotationStateRecoveryConcurrentSessionsAndQuorum(t *testing.T) {
	cluster := newRotationStateCluster(t)
	// Setup and restart each receive their own readiness budget. State-store
	// operations retain the production two-second bound.
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, ctx, nc, true)
	global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "rotation-one")
	if err != nil {
		t.Fatal(err)
	}
	defer global.Dispose()
	lease := readRotationTestLease(t, ctx, kv)
	one := newRotationTestSession(t, nc, lease)
	initial := rotationTestState()
	if err := one.Save(ctx, initial); !errors.Is(err, ErrStateNotLoaded) {
		t.Fatalf("save without snapshot: %v", err)
	}
	if _, err := one.Load(ctx); !errors.Is(err, security.ErrNoState) {
		t.Fatalf("absent state: %v", err)
	}
	if err := one.Save(ctx, initial); err != nil {
		t.Fatal(err)
	}
	two := newRotationTestSession(t, nc, lease)
	old, err := two.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current, err := one.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	current.NewIdentityRef = "vault:identity/rotation-1"
	current.NewCapabilityRef = "vault:capability/rotation-1"
	current.NewCapabilityID = "capability-1"
	current.Distributed["gru/member-one"] = true
	current.PublicationCommitted = true
	current.PublicationReceipt = security.PublicationReceipt{OperationID: current.OperationID, Generation: 1, ReceiptID: "provider-receipt-1", CurrentKeyID: "capability-1", Committed: true}
	if err := one.Save(ctx, current); err != nil {
		t.Fatal(err)
	}
	old.Verified["sfo/member-two"] = true
	if err := two.Save(ctx, old); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("same-lease stale snapshot overwrote newer receipt: %v", err)
	}
	changedIdentity := current
	changedIdentity.NewIdentityRef = "vault:unexpected-replacement"
	if err := one.Save(ctx, changedIdentity); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("issued reference changed within one intent: %v", err)
	}
	changedReceipt := current
	changedReceipt.PublicationReceipt.ReceiptID = "replacement-receipt"
	if err := one.Save(ctx, changedReceipt); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("provider receipt changed within one intent: %v", err)
	}
	invalidActive := current
	invalidActive.Phase = security.PhaseActive
	if err := one.Save(ctx, invalidActive); err == nil {
		t.Fatal("active state without current credential obligations admitted")
	}
	// A new session proves the complete identity, intent and receipt after the
	// prior coordinator and all three JetStream processes disappear.
	global.Dispose()
	nc.Close()
	cluster.restart(t)
	nc = cluster.connect(t)
	kv = openRotationTestLeaseStore(t, ctx, nc, false)
	// Renew the same fixture authority after restart; this is a real replicated
	// lease write, not a process-local readiness flag.
	lease.IssuedAt = time.Now().UTC()
	lease.DurationMilliseconds = 60000
	putRotationTestLease(t, ctx, kv, lease)
	recovered := newRotationTestSession(t, nc, lease)
	loaded, err := recovered.Load(ctx)
	if err != nil || !reflect.DeepEqual(loaded, current) {
		t.Fatalf("restart lost identity, intent or receipt: %+v %v", loaded, err)
	}
	// Simulate an indeterminate reply: publish the same transition through the
	// real adapter's commit path, but leave the session's loaded cursor unchanged.
	proposed := loaded
	proposed.EdgeDistributed = true
	snapshot, err := recovered.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The broker sends the real publish acknowledgement to an inbox with no
	// subscriber. Only subsequent recovery can establish the commit outcome.
	envelope := rotationEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &proposed, PriorState: snapshot.state, PriorRevision: snapshot.revision}
	payload, _ := json.Marshal(envelope)
	message := nats.NewMsg(rotationStateSubject)
	message.Data = payload
	message.Reply = nats.NewInbox()
	message.Header.Set(nats.ExpectedStreamHdr, rotationStream)
	message.Header.Set(nats.ExpectedLastSeqHdr, strconv.FormatUint(snapshot.sequence, 10))
	if err := nc.PublishMsg(message); err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	var committed rotationRawMessage
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		observed, found, err := recovered.rawGet(ctx, rotationStateSubject, 0)
		if err == nil && found && observed.Sequence == snapshot.sequence+1 {
			committed = observed
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	sequence := committed.Sequence
	if sequence == 0 {
		t.Fatal("lost-reply fixture did not commit")
	}
	if sequence == recovered.revision {
		t.Fatal("fixture failed to leave an indeterminate session")
	}
	if err := recovered.Save(ctx, proposed); err != nil {
		t.Fatalf("indeterminate identical commit failed recovery: %v", err)
	}
	after, err := recovered.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.revision != sequence || !after.state.EdgeDistributed {
		t.Fatal("retry rewrote committed state instead of proving it")
	}
	// A canceled operation cannot report success from the cached same state.
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := recovered.Save(cancelled, proposed); err == nil {
		t.Fatal("canceled identical save returned success")
	}
	// Without two replicas, even an identical Save and a Load need a quorum
	// barrier. A reachable follower and locally retained state are insufficient.
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	minority, stopMinority := context.WithTimeout(ctx, time.Second)
	defer stopMinority()
	if err := recovered.Save(minority, proposed); err == nil {
		t.Fatal("minority identical save returned success")
	}
	minorityLoad, stopLoad := context.WithTimeout(ctx, time.Second)
	defer stopLoad()
	if _, err := recovered.Load(minorityLoad); err == nil || errors.Is(err, security.ErrNoState) {
		t.Fatalf("minority read authorized work: %v", err)
	}
}

func TestNATSRotationStateLateCommitAndOldMasterFailClosed(t *testing.T) {
	cluster := newRotationStateCluster(t)
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, ctx, nc, true)
	lease := rotationTestLease(7, "global-controller-gru-old")
	putRotationTestLease(t, ctx, kv, lease)
	old := newRotationTestSession(t, nc, lease)
	if _, err := old.Load(ctx); !errors.Is(err, security.ErrNoState) {
		t.Fatal(err)
	}
	valid := rotationTestState()
	valid.NewIdentityRef = "vault:identity/retirement-obligation"
	valid.NewCapabilityRef = "vault:capability/retirement-obligation"
	if err := old.Save(ctx, valid); err != nil {
		t.Fatal(err)
	}
	lease.IssuedAt = time.Now().UTC()
	lease.DurationMilliseconds = 120
	putRotationTestLease(t, ctx, kv, lease)
	late, err := old.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proposed := valid
	proposed.NewIdentityRef = "incorrect-late-reference"
	envelope := rotationEnvelope{SchemaVersion: 1, Lease: late.lease, LeaseRevision: late.leaseRevision, State: &proposed, PriorState: late.state, PriorRevision: late.revision}
	raw, _ := json.Marshal(envelope)
	timer := time.NewTimer(time.Until(lease.IssuedAt.Add(180 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := old.js.Publish(ctx, rotationStateSubject, raw, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(late.sequence)); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Load(ctx); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("expired owner authorized work: %v", err)
	}
	successor, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "successor")
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Dispose()
	currentLease := readRotationTestLease(t, ctx, kv)
	if currentLease.Epoch <= lease.Epoch {
		t.Fatal("actual global takeover failed to advance epoch")
	}
	if _, err := old.js.Publish(ctx, rotationStateSubject, raw, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(late.sequence)); err == nil {
		t.Fatal("delayed old-master stream CAS survived takeover")
	}
	if err := old.Save(ctx, proposed); err == nil {
		t.Fatal("old master saved after takeover")
	}
	resumed := newRotationTestSession(t, nc, currentLease)
	got, err := resumed.Load(ctx)
	if err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatalf("post-expiry commit erased prior state with history one: %+v %v", got, err)
	}
	repaired, err := resumed.snapshot(ctx)
	if err != nil || repaired.recovered {
		t.Fatalf("prior state was not durably repaired: %+v %v", repaired, err)
	}
	if err := resumed.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	// Malformed/oversized state cannot replace the admitted state.
	huge := got
	huge.FailureCode = strings.Repeat("x", maximumRotationStateBytes)
	if err := resumed.Save(ctx, huge); err == nil {
		t.Fatal("oversized state admitted")
	}
	unknown, _ := json.Marshal(rotationEnvelope{SchemaVersion: 1, Lease: currentLease, LeaseRevision: repaired.leaseRevision, State: &got, PriorState: &got, PriorRevision: repaired.revision})
	unknown = append(unknown[:len(unknown)-1], []byte(`,"State":{"OperationID":"duplicate"}}`)...)
	if strictRotationJSON(unknown, &rotationEnvelope{}) == nil {
		t.Fatal("duplicate state key admitted")
	}
}

func TestNATSRotationStateExpiredFirstWriteRecoversAbsenceThenSaves(t *testing.T) {
	cluster := newRotationStateCluster(t)
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, ctx, nc, true)
	lease := rotationTestLease(3, "global-controller-gru-first")
	putRotationTestLease(t, ctx, kv, lease)
	old := newRotationTestSession(t, nc, lease)
	if _, err := old.Load(ctx); !errors.Is(err, security.ErrNoState) {
		t.Fatal(err)
	}
	lease.IssuedAt = time.Now().UTC()
	lease.DurationMilliseconds = 120
	putRotationTestLease(t, ctx, kv, lease)
	snapshot, err := old.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial := rotationTestState()
	raw, _ := json.Marshal(rotationEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &initial})
	timer := time.NewTimer(time.Until(lease.IssuedAt.Add(180 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := old.js.Publish(ctx, rotationStateSubject, raw, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err != nil {
		t.Fatal(err)
	}
	global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "healed-first")
	if err != nil {
		t.Fatal(err)
	}
	defer global.Dispose()
	next := newRotationTestSession(t, nc, readRotationTestLease(t, ctx, kv))
	if _, err := next.Load(ctx); !errors.Is(err, security.ErrNoState) {
		t.Fatalf("expired first write became valid state: %v", err)
	}
	if next.revision == 0 {
		t.Fatal("absent state recovery did not persist a healing record")
	}
	if err := next.Save(ctx, initial); err != nil {
		t.Fatalf("nil prior with durable revision prevented next valid save: %v", err)
	}
	got, err := next.Load(ctx)
	if err != nil || !reflect.DeepEqual(got, initial) {
		t.Fatalf("valid state after absence recovery: %+v %v", got, err)
	}
	// A nonempty prior cannot claim to predate all state revisions.
	current, err := next.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	malformed, _ := json.Marshal(rotationEnvelope{SchemaVersion: 1, Lease: current.lease, LeaseRevision: current.leaseRevision, State: &got, PriorState: &got})
	if _, err := next.js.Publish(ctx, rotationStateSubject, malformed, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(current.sequence)); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Load(ctx); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("nonempty prior with no revision admitted: %v", err)
	}
}
