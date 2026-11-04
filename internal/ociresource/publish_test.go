package ociresource

import (
	"errors"
	"testing"
	"time"
)

type testSpec struct {
	Value string `json:"value"`
}

func (s testSpec) Validate() error {
	if s.Value == "" {
		return errors.New("empty")
	}
	return nil
}

func TestPublishSetWritesOnlyChangesAndPrunesOnlyWhenAsked(t *testing.T) {
	store := integrationStore(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	entries := []Entry{{Name: "a", Policy: PolicyEnforce, Spec: testSpec{"1"}}, {Name: "b", Policy: PolicyEnforce, Spec: testSpec{"2"}}}
	result, err := PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, time.Hour, nil)
	if err != nil || result.Published != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, time.Hour, nil)
	if err != nil || result.Unchanged != 2 || result.Published != 0 {
		t.Fatalf("idempotent result=%+v err=%v", result, err)
	}
	entries[0].Spec = testSpec{"changed"}
	if result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, time.Hour, nil); err != nil || result.Published != 1 {
		t.Fatalf("policy change result=%+v err=%v", result, err)
	}
	if desired, _ := store.Get(ctx, Key{Region: "GRU", Kind: "nsg-rules", Name: "a"}); desired.Generation != 2 {
		t.Fatalf("generation=%d", desired.Generation)
	}

	// Without prune an unlisted record stays; with prune it is tombstoned.
	if result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries[1:], false, now, time.Hour, nil); err != nil || result.Tombstoned != 0 {
		t.Fatalf("no-prune result=%+v err=%v", result, err)
	}
	if result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries[1:], true, now, time.Hour, nil); err != nil || result.Tombstoned != 1 {
		t.Fatalf("prune result=%+v err=%v", result, err)
	}
	pruned, _ := store.Get(ctx, Key{Region: "GRU", Kind: "nsg-rules", Name: "a"})
	if pruned.Tombstone == nil || !pruned.Tombstone.NotBefore.Equal(now.Add(time.Hour)) {
		t.Fatalf("tombstone=%+v", pruned.Tombstone)
	}
	// Relisting a name whose record is still being deleted fails that entry only.
	result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries, true, now, time.Hour, nil)
	if err == nil || result.Unchanged != 1 || result.Tombstoned != 0 {
		t.Fatalf("revive result=%+v err=%v", result, err)
	}
}

// Authority is re-checked before every write and every tombstone: losing it
// mid-set stops the set at once.
