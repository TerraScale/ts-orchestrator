package databaseadmission

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNATSAllocatePlacementStreamsRestartPreservesPartitionAndFencesStaleAuthority(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	const candidate = "global-controller-gru-one"
	putAdmissionLease(t, ctx, store, admissionLease(1, candidate))

	_, record, now := allocationFixture(t)
	record.CreatedAt = now.Add(-time.Hour)
	journal := newAdmissionJournalClient(t, connection, 1, candidate)
	key := ScopeKey(record.Request)
	if revision, err := journal.Save(ctx, key, 0, record); err != nil || revision != 1 {
		t.Fatalf("save revision=%d err=%v", revision, err)
	}
	const proof = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := journal.AllocatePlacementStreams(ctx, record, proof, now); err != nil {
		t.Fatalf("initial allocation: %v", err)
	}
	_, before, err := journal.LifecycleResources(ctx)
	if err != nil || len(before) != 1 || len(before[0].Streams) != 1 {
		t.Fatalf("initial resources=%+v err=%v", before, err)
	}

	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, "global-controller-gru-two"))
	stale := newAdmissionJournalClient(t, connection, 1, candidate)
	if err := stale.AllocatePlacementStreams(ctx, record, proof, now.Add(time.Minute)); !errors.Is(err, ErrEpochFenced) {
		t.Fatalf("stale allocation error=%v", err)
	}
	successor := newAdmissionJournalClient(t, connection, 2, "global-controller-gru-two")
	if err := successor.AllocatePlacementStreams(ctx, record, proof, now.Add(time.Minute)); err != nil {
		t.Fatalf("restarted allocation: %v", err)
	}
	_, after, err := successor.LifecycleResources(ctx)
	if err != nil || len(after) != 1 || len(after[0].Streams) != 1 || after[0].Streams[0].Partition != before[0].Streams[0].Partition {
		t.Fatalf("restart changed allocation before=%+v after=%+v err=%v", before, after, err)
	}
}
