package hostenroll

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

func completedForgetGrant(t *testing.T, store *GrantStore, suffix string) (Grant, uint64) {
	t.Helper()
	grant, revision, err := store.Claim(t.Context(), terminalTestGrant("ocid1.instance."+suffix))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Finish(t.Context(), grant, revision, []byte("retained-signed-response")); err != nil {
		t.Fatal(err)
	}
	grant, revision, err = ReadCurrentGrant(t.Context(), store.js, grant.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	return grant, revision
}

func TestForgetExpectedConsumesExactRevisionWithoutCertifyingAbsence(t *testing.T) {
	store := terminalTestStore(t)
	grant, revision := completedForgetGrant(t, store, "exact-forget")
	changed := grant
	changed.Response = []byte("different-signed-response")
	if _, err := store.ForgetExpected(t.Context(), changed, revision); !IsGrantMutationNotApplied(err) {
		t.Fatalf("changed grant: %v", err)
	}
	if _, err := store.ForgetExpected(t.Context(), grant, revision+1); !IsGrantMutationNotApplied(err) {
		t.Fatalf("changed revision: %v", err)
	}
	deleted, err := store.ForgetExpected(t.Context(), grant, revision)
	if err != nil || deleted <= revision {
		t.Fatalf("exact delete: revision=%d err=%v", deleted, err)
	}
	if got, err := store.ForgetExpected(t.Context(), grant, revision); got != 0 || err == nil {
		t.Fatalf("absence certified previous deletion: %d %v", got, err)
	}
}

type lostForgetReply struct{ jetstream.KeyValue }

func (kv lostForgetReply) Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	if err := kv.KeyValue.Delete(ctx, key, opts...); err != nil {
		return err
	}
	return context.DeadlineExceeded
}

func TestForgetExpectedLostReplyRemainsUnknownAfterActualDeletion(t *testing.T) {
	store := terminalTestStore(t)
	grant, revision := completedForgetGrant(t, store, "lost-forget-reply")
	lost := *store
	lost.kv = lostForgetReply{store.kv}
	deleted, err := lost.ForgetExpected(t.Context(), grant, revision)
	if deleted != 0 || !errors.Is(err, context.DeadlineExceeded) || IsGrantMutationNotApplied(err) {
		t.Fatalf("lost delete acknowledgement became a known outcome: %d %v", deleted, err)
	}
	if _, _, err := ReadCurrentGrant(t.Context(), store.js, grant.InstanceID); err == nil {
		t.Fatal("fixture did not delete actual enrollment")
	}
}

func TestOpenExistingGrantStoreRequiresOriginalDurableBucket(t *testing.T) {
	store := terminalTestStore(t)
	grant, revision := completedForgetGrant(t, store, "existing-store")
	existing, err := OpenExistingGrantStore(t.Context(), store.js, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, currentRevision, err := ReadCurrentGrant(t.Context(), existing.js, grant.InstanceID)
	if err != nil || revision != currentRevision || !sameGrant(current, grant) {
		t.Fatalf("existing open changed grant: %d %v", currentRevision, err)
	}
	if _, err := OpenExistingGrantStore(t.Context(), store.js, 3); err == nil {
		t.Fatal("accepted different regional replication")
	}
}
