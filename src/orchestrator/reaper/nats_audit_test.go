package reaper

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"time"
)

func TestNATSAuditRestartRetryAndLeaseFence(t *testing.T) {
	cluster := newReaperStateCluster(t)
	ctx := t.Context()
	connection := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, ctx, connection, true)
	lease := reaperTestLease(1, "global-controller-gru-one")
	putReaperTestLease(t, ctx, kv, lease)
	sink, err := NewNATSAuditSink(NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{ID: "pause/db-one", OperationKey: "pause/db-one", DatabaseID: "db-one", Action: "pause", Outcome: "completed", At: time.Now().UTC()}
	if err := sink.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	first, found, err := sink.store.rawGet(ctx, auditSubject(event.ID), 0)
	if err != nil || !found {
		t.Fatal(err)
	}
	if _, err := decodeAudit(first); err != nil {
		t.Fatal(err)
	}
	// Retry with a later scan clock retains the original immutable event.
	event.At = event.At.Add(time.Second)
	if err := sink.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	retry, _, err := sink.store.rawGet(ctx, auditSubject(event.ID), 0)
	if err != nil || retry.Sequence != first.Sequence {
		t.Fatal("retry replaced event", err)
	}
	event.Outcome = "failed"
	if err := sink.Record(ctx, event); !errors.Is(err, ErrStateConflict) {
		t.Fatal("conflicting event accepted", err)
	}
	event.Outcome = "completed"
	cluster.stop()
	cluster.restart(t)
	connection = cluster.connect(t)
	sink, err = NewNATSAuditSink(NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	kv = openReaperTestLeaseStore(t, ctx, connection, false)
	next := reaperTestLease(2, "global-controller-gru-two")
	putReaperTestLease(t, ctx, kv, next)
	if err := sink.Record(ctx, event); !errors.Is(err, ErrStateFenced) {
		t.Fatal("old session accepted after takeover", err)
	}
}
func TestNATSAuditRejectsSignatureTamperingAndExpiredCommit(t *testing.T) {
	cluster := newReaperStateCluster(t)
	ctx := t.Context()
	connection := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, ctx, connection, true)
	lease := reaperTestLease(1, "global-controller-gru-one")
	putReaperTestLease(t, ctx, kv, lease)
	sink, err := NewNATSAuditSink(NATSStateStoreConfig{Connection: connection, CandidateID: lease.CandidateId, AuthorityEpoch: 1, LeaseID: lease.LeaseId})
	if err != nil {
		t.Fatal(err)
	}
	event := AuditEvent{ID: "delete/db-one", OperationKey: "delete/db-one", DatabaseID: "db-one", Action: "delete", Outcome: "completed", At: time.Now().UTC()}
	if err := sink.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	stored, _, err := sink.store.rawGet(ctx, auditSubject(event.ID), 0)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := decodeAudit(stored)
	if err != nil {
		t.Fatal(err)
	}
	expired := stored
	expired.Time = lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond)
	if _, err := decodeAudit(expired); !errors.Is(err, ErrStateFenced) {
		t.Fatal("accepted expired server commit", err)
	}
	envelope.Payload.Event.DatabaseID = "foreign"
	stored.Data, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAudit(stored); err == nil {
		t.Fatal("accepted tampered signed audit")
	}
}
