package serviceidentityrotation

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

func TestNATSIdentityJournalFencesStaleSessionsAndRepairsLateCommit(t *testing.T) {
	cluster := newRotationStateCluster(t)
	ctx := t.Context()
	nc := cluster.connect(t)
	kv := openRotationTestLeaseStore(t, ctx, nc, true)
	lease := rotationTestLease(1, "global-controller-gru-first")
	putRotationTestLease(t, ctx, kv, lease)
	makeStore := func() *NATSStateStore {
		t.Helper()
		store, err := NewNATSStore(nc, lease.CandidateId, uint64(lease.Epoch), lease.LeaseId, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		return store.(*NATSStateStore)
	}
	one, two := makeStore(), makeStore()
	j := Journal{RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "member-one", URL: "https://member-one.internal"}}, Generation: 1, Phase: "bootstrap", Deadline: time.Now().UTC()}
	if err := one.Save(ctx, j); !errors.Is(err, ErrStateNotLoaded) {
		t.Fatalf("unloaded Save: %v", err)
	}
	if got, err := one.Load(ctx); err != nil || !emptyJournal(got) {
		t.Fatalf("empty Load: %+v %v", got, err)
	}
	if _, err := two.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if err := one.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	stale := j
	stale.Deadline = stale.Deadline.Add(time.Second)
	if err := two.Save(ctx, stale); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale overwrite: %v", err)
	}
	j.Pending = hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.oc1.test", VersionNumber: 1, Generation: 1, OperationID: "bootstrap-1"}
	if err := one.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	lease.IssuedAt = time.Now().UTC()
	lease.DurationMilliseconds = 150
	putRotationTestLease(t, ctx, kv, lease)
	snapshot, err := one.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := j
	corrupt.Pending.SecretID = "ocid1.vaultsecret.oc1.late"
	raw, _ := json.Marshal(rotationEnvelope{SchemaVersion: 1, Lease: snapshot.lease, LeaseRevision: snapshot.leaseRevision, State: &corrupt, PriorState: snapshot.state, PriorRevision: snapshot.revision})
	time.Sleep(time.Until(lease.IssuedAt.Add(200 * time.Millisecond)))
	if _, err := one.js.Publish(ctx, rotationStateSubject, raw, jetstream.WithExpectStream(rotationStream), jetstream.WithExpectLastSequence(snapshot.sequence)); err != nil {
		t.Fatal(err)
	}
	if _, err := one.Load(ctx); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("expired owner: %v", err)
	}
	lease = rotationTestLease(2, "global-controller-gru-next")
	putRotationTestLease(t, ctx, kv, lease)
	successor := makeStore()
	got, err := successor.Load(ctx)
	if err != nil || !sameJournal(got, j) {
		t.Fatalf("late commit erased prior journal: %+v %v", got, err)
	}
	healed, err := successor.snapshot(ctx)
	if err != nil || healed.recovered {
		t.Fatalf("repair not durable: %v", err)
	}
	if err := one.Save(ctx, j); !errors.Is(err, ErrStateNotLoaded) && !errors.Is(err, ErrStateFenced) {
		t.Fatalf("stale owner: %v", err)
	}
	// Enrollment and rotation share the exact loaded state cursor.
	idle := j
	idle.Active = idle.Pending
	idle.Pending = hostsecrets.IdentitySecretReference{}
	idle.Phase = ""
	idle.Deadline = time.Time{}
	idle.NextRotation = time.Now().Add(time.Hour)
	if err := successor.Save(ctx, idle); err != nil {
		t.Fatal(err)
	}
	competitor := makeStore()
	staleIdle, err := competitor.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enrolled := idle
	enrolled.RosterRevision++
	enrolled.Members = append(append([]RemoteMemberEndpoint{}, idle.Members...), RemoteMemberEndpoint{NodeID: "member-two", URL: "https://member-two.internal"})
	if err := successor.Save(ctx, enrolled); err != nil {
		t.Fatal(err)
	}
	staleIdle.Generation++
	staleIdle.Phase = "issue"
	staleIdle.Deadline = time.Now().Add(time.Minute)
	if err := competitor.Save(ctx, staleIdle); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("rotation excluded concurrently enrolled member: %v", err)
	}
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	if err := successor.Save(ctx, enrolled); err == nil {
		t.Fatal("minority identical Save succeeded")
	}
}

func TestJournalRejectsSecretMaterialAndChangedReferences(t *testing.T) {
	if strictRotationJSON([]byte(`{"State":{"secret":"plaintext"}}`), &rotationEnvelope{}) == nil {
		t.Fatal("secret admitted")
	}
	if strictRotationJSON([]byte(`{"State":null,"State":null}`), &rotationEnvelope{}) == nil {
		t.Fatal("duplicate admitted")
	}
	j := Journal{RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "member-one", URL: "https://member-one.internal"}}, Generation: 1, Phase: "bootstrap", Deadline: time.Now(), Pending: hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.oc1.test", VersionNumber: 1, Generation: 1, OperationID: "bootstrap-1"}}
	changed := j
	changed.Pending.SecretID = "ocid1.vaultsecret.oc1.changed"
	if rotationIntentTransition(&j, &changed) == nil {
		t.Fatal("issued reference changed")
	}
}

func TestJournalRosterMutationsSerializeWithRotation(t *testing.T) {
	ref := hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.oc1.active", VersionNumber: 1, Generation: 1, OperationID: "bootstrap-1"}
	idle := Journal{Generation: 1, Active: ref, NextRotation: time.Now().Add(time.Hour), RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "one", URL: "https://one.internal"}}}
	enrolled := idle
	enrolled.RosterRevision++
	enrolled.Members = append([]RemoteMemberEndpoint{}, idle.Members...)
	enrolled.Members = append(enrolled.Members, RemoteMemberEndpoint{NodeID: "two", URL: "https://two.internal"})
	if !validJournal(enrolled) || rotationIntentTransition(&idle, &enrolled) != nil {
		t.Fatal("valid idle enrollment rejected")
	}
	skipped := enrolled
	skipped.RosterRevision++
	if rotationIntentTransition(&idle, &skipped) == nil {
		t.Fatal("skipped roster revision admitted")
	}
	changedKey := enrolled
	changedKey.Active.SecretID = "ocid1.vaultsecret.oc1.changed"
	if rotationIntentTransition(&idle, &changedKey) == nil {
		t.Fatal("enrollment changed active reference")
	}
	issue := idle
	issue.Generation++
	issue.Phase = "issue"
	issue.Deadline = time.Now().Add(time.Minute)
	if rotationIntentTransition(&idle, &issue) != nil {
		t.Fatal("rotation with fixed roster rejected")
	}
	issue.Members = enrolled.Members
	if rotationIntentTransition(&idle, &issue) == nil {
		t.Fatal("rotation changed roster")
	}
	duplicate := enrolled
	duplicate.Members = []RemoteMemberEndpoint{idle.Members[0], idle.Members[0]}
	if validJournal(duplicate) {
		t.Fatal("duplicate node admitted")
	}
	duplicate.Members[1].NodeID = "another"
	if validJournal(duplicate) {
		t.Fatal("duplicate destination admitted")
	}
	invalid := enrolled
	invalid.Members = []RemoteMemberEndpoint{{NodeID: "one", URL: "http://one.internal"}}
	if validJournal(invalid) {
		t.Fatal("insecure destination admitted")
	}
	bootstrap := Journal{Generation: 1, Phase: "bootstrap", Deadline: time.Now(), RosterRevision: 2, Members: idle.Members}
	if rotationIntentTransition(nil, &bootstrap) == nil {
		t.Fatal("bootstrap skipped initial revision")
	}
}
