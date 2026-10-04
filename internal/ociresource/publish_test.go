package ociresource

import (
	"context"
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
	store := NewMemoryStore()
	ctx := t.Context()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	entries := []Entry{{Name: "a", Policy: PolicyReport, Spec: testSpec{"1"}}, {Name: "b", Policy: PolicyEnforce, Spec: testSpec{"2"}}}
	result, err := PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, time.Hour, nil)
	if err != nil || result.Published != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, time.Hour, nil)
	if err != nil || result.Unchanged != 2 || result.Published != 0 {
		t.Fatalf("idempotent result=%+v err=%v", result, err)
	}
	entries[0].Policy = PolicyEnforce
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
func TestPublishSetFencesEveryWrite(t *testing.T) {
	store := NewMemoryStore()
	ctx := t.Context()
	now := time.Now()
	entries := []Entry{{Name: "a", Policy: PolicyReport, Spec: testSpec{"1"}}, {Name: "b", Policy: PolicyReport, Spec: testSpec{"2"}},
		{Name: "c", Policy: PolicyReport, Spec: testSpec{"3"}}}
	calls := 0
	loseAfter := func(allowed int) func(context.Context) error {
		calls = 0
		return func(context.Context) error {
			calls++
			if calls > allowed {
				return errors.New("lost leadership")
			}
			return nil
		}
	}
	result, err := PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, 0, loseAfter(1))
	if !errors.Is(err, ErrFenced) || result.Published != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if records, _ := store.List(ctx, "GRU", "nsg-rules"); len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	// Publish all three, then lose authority before the prune tombstone.
	if _, err := PublishSet(ctx, store, "GRU", "nsg-rules", entries, false, now, 0, nil); err != nil {
		t.Fatal(err)
	}
	result, err = PublishSet(ctx, store, "GRU", "nsg-rules", entries[:1], true, now, 0, loseAfter(1))
	if !errors.Is(err, ErrFenced) || result.Tombstoned != 0 {
		t.Fatalf("prune result=%+v err=%v", result, err)
	}
	records, _ := store.List(ctx, "GRU", "nsg-rules")
	for _, record := range records {
		if record.Tombstone != nil {
			t.Fatalf("fenced prune tombstoned %s", record.Key)
		}
	}
}

func TestPublishSetValidatesEverythingBeforeWriting(t *testing.T) {
	store := NewMemoryStore()
	for name, entries := range map[string][]Entry{
		"invalid spec": {{Name: "a", Policy: PolicyReport, Spec: testSpec{"1"}}, {Name: "b", Policy: PolicyReport, Spec: testSpec{}}},
		"bad policy":   {{Name: "a", Policy: "adopt", Spec: testSpec{"1"}}},
		"bad name":     {{Name: "A_B", Policy: PolicyReport, Spec: testSpec{"1"}}},
		"duplicate":    {{Name: "a", Policy: PolicyReport, Spec: testSpec{"1"}}, {Name: "a", Policy: PolicyReport, Spec: testSpec{"2"}}},
		"nil spec":     {{Name: "a", Policy: PolicyReport}},
	} {
		if _, err := PublishSet(t.Context(), store, "GRU", "nsg-rules", entries, true, time.Now(), 0, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if records, _ := store.List(t.Context(), "GRU", "nsg-rules"); len(records) != 0 {
			t.Fatalf("%s: wrote %d records", name, len(records))
		}
	}
}
