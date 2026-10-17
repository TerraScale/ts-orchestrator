//go:build linux

package app

import (
	"context"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestRootNodeOperationJournalPinsPresenceAndAbsence(t *testing.T) {
	kv, _, js := fenceBroker(t)
	ctx := t.Context()
	key := nodeOpKey("ctl-1")
	absent, err := readRootNodeJournal(ctx, js, key)
	if err != nil || absent.present() || absent.revision != 0 {
		t.Fatalf("initial absence %+v %v", absent, err)
	}
	revision, err := kv.Put(ctx, key, []byte(`{"state":"queued"}`))
	if err != nil {
		t.Fatal(err)
	}
	queued, err := readRootNodeJournal(ctx, js, key)
	if err != nil || !queued.present() || queued.revision != revision || absent.same(queued) {
		t.Fatalf("queued %+v %v", queued, err)
	}
	if err := kv.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	deleted, err := readRootNodeJournal(ctx, js, key)
	if err != nil || deleted.present() || deleted.revision <= revision || deleted.same(absent) || deleted.same(queued) {
		t.Fatalf("retained deletion %+v %v", deleted, err)
	}
	if _, err := kv.Put(ctx, key, []byte(`{"state":"queued"}`)); err != nil {
		t.Fatal(err)
	}
	replacement, err := readRootNodeJournal(ctx, js, key)
	if err != nil || queued.same(replacement) || deleted.same(replacement) {
		t.Fatalf("replacement %+v %v", replacement, err)
	}
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if _, err := readRootNodeJournal(expired, js, key); err == nil {
		t.Fatal("expired actual journal read admitted")
	}
	archive := nodeOperationRequestKey(entityid.Derive("node-operation", "missing-archive"))
	missing, err := readRootNodeJournal(ctx, js, archive)
	if err != nil || missing.present() {
		t.Fatalf("missing archive %+v %v", missing, err)
	}
}

func TestRootNodeOperationZeroAndExpiredProofsDeny(t *testing.T) {
	empty := rootNodeOperations{}
	if err := empty.Revalidate(t.Context()); err == nil || !empty.Deadline().IsZero() || len(empty.Operations()) != 0 {
		t.Fatal("zero set admitted")
	}
	op := rootNodeOperationAdmission{}
	if err := op.Revalidate(t.Context()); err == nil {
		t.Fatal("zero operation admitted")
	}
	expired := rootNodeOperations{source: &rootNodeOperationSource{lifetime: t.Context(), deadline: time.Now().Add(-time.Second)}}
	if err := expired.Revalidate(t.Context()); err == nil {
		t.Fatal("expired original set admitted")
	}
}
