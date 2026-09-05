package sourcepublication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type journalTestStore struct {
	calls    int
	key      string
	revision uint64
	value    []byte
	err      error
	after    func()
}

func (s *journalTestStore) Get(_ context.Context, key string) ([]byte, uint64, error) {
	s.calls++
	s.key = key
	if s.after != nil {
		s.after()
	}
	return s.value, s.revision, s.err
}
func (s *journalTestStore) CompareAndSwap(_ context.Context, key string, revision uint64, value []byte) error {
	s.calls++
	s.key, s.revision, s.value = key, revision, append([]byte(nil), value...)
	if s.after != nil {
		s.after()
	}
	return s.err
}

func TestJournalCanonicalFiniteKeys(t *testing.T) {
	store := &journalTestStore{}
	guard := func(context.Context) error { return nil }
	digest := strings.Repeat("a", 64)
	for _, keys := range [][]string{nil, {}, {"provider.ownership." + digest, "provider.ownership." + digest}, {digest}, {"provider.intent." + strings.ToUpper(digest)}, {"provider.ownership." + digest + ".extra"}, {"provider.intent." + strings.Repeat("g", 64)}, {"provider.other." + digest}, {"provider.intent." + digest[:63]}} {
		if _, err := NewJournalCAS(store, keys, guard); err == nil {
			t.Fatalf("accepted invalid keys %v", keys)
		}
	}
	keys := make([]string, maximumJournalKeys+1)
	for i := range keys {
		keys[i] = MutationKey(fmt.Sprint(i))
	}
	if _, err := NewJournalCAS(store, keys, guard); err == nil {
		t.Fatal("accepted excessive key count")
	}
	if _, err := NewJournalCAS(store, keys[:maximumJournalKeys], guard); err != nil {
		t.Fatalf("exact key bound: %v", err)
	}
	if _, err := NewJournalCAS(nil, keys[:1], guard); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewJournalCAS(store, keys[:1], nil); err == nil {
		t.Fatal("nil guard accepted")
	}
	// Published SHA-256 test vector proves the helpers hash the unmodified input.
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if OwnershipKey("abc") != "provider.ownership."+want || MutationKey("abc") != "provider.intent."+want {
		t.Fatal("provider journal key derivation differs")
	}
}

func TestJournalExactKeysAndContext(t *testing.T) {
	store := &journalTestStore{}
	guards := 0
	key := OwnershipKey("bucket")
	keys := []string{key}
	wrapped, err := NewJournalCAS(store, keys, func(context.Context) error { guards++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = OwnershipKey("other")
	for _, bad := range []string{keys[0], "provider.ownership.>", key + ".suffix", MutationKey("bucket")} {
		if _, _, err := wrapped.Get(t.Context(), bad); err == nil {
			t.Fatalf("read unadmitted key %q", bad)
		}
		if err := wrapped.CompareAndSwap(t.Context(), bad, 1, nil); err == nil {
			t.Fatalf("wrote unadmitted key %q", bad)
		}
	}
	if _, _, err := wrapped.Get(nil, key); err == nil {
		t.Fatal("nil read context accepted")
	}
	if err := wrapped.CompareAndSwap(nil, key, 0, nil); err == nil {
		t.Fatal("nil write context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := wrapped.Get(ctx, key); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: %v", err)
	}
	if err := wrapped.CompareAndSwap(ctx, key, 0, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write: %v", err)
	}
	if store.calls != 0 || guards != 0 {
		t.Fatalf("invalid request reached store/guard: %d/%d", store.calls, guards)
	}
	if _, _, err := wrapped.Get(t.Context(), key); err != nil {
		t.Fatalf("allowlist mutated by caller: %v", err)
	}
}

func TestJournalGuardBeforeAndAfterStorage(t *testing.T) {
	refused := errors.New("authority revoked")
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprint("write=", write), func(t *testing.T) {
			store := &journalTestStore{value: []byte("private"), revision: 7}
			revoked := true
			checks := 0
			key := MutationKey("snapshot")
			wrapped, err := NewJournalCAS(store, []string{key}, func(context.Context) error {
				checks++
				if revoked {
					return refused
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			call := func() error {
				if write {
					return wrapped.CompareAndSwap(t.Context(), key, 7, []byte("next"))
				}
				raw, rev, err := wrapped.Get(t.Context(), key)
				if err != nil && (raw != nil || rev != 0) {
					t.Fatal("refused read leaked value or revision")
				}
				return err
			}
			if err := call(); !errors.Is(err, refused) {
				t.Fatalf("initial guard refusal: %v", err)
			}
			if store.calls != 0 || checks != 1 {
				t.Fatal("guard refusal touched store")
			}
			revoked = false
			store.after = func() { revoked = true }
			if err := call(); !errors.Is(err, refused) {
				t.Fatalf("post-operation guard refusal: %v", err)
			}
			if store.calls != 1 || checks != 3 {
				t.Fatalf("guard not checked before and after: calls=%d checks=%d", store.calls, checks)
			}
		})
	}
}

func TestJournalBoundsRevisionsAndErrors(t *testing.T) {
	key := OwnershipKey("bucket")
	store := &journalTestStore{value: bytes.Repeat([]byte("x"), maximumJournalValueBytes), revision: 42}
	checks := 0
	wrapped, err := NewJournalCAS(store, []string{key}, func(context.Context) error { checks++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	value, revision, err := wrapped.Get(t.Context(), key)
	if err != nil || revision != 42 || !bytes.Equal(value, store.value) || checks != 2 {
		t.Fatalf("bounded read: revision=%d checks=%d err=%v", revision, checks, err)
	}
	if err := wrapped.CompareAndSwap(t.Context(), key, 42, value); err != nil || store.revision != 42 || store.key != key {
		t.Fatalf("bounded CAS: %v", err)
	}
	calls := store.calls
	if err := wrapped.CompareAndSwap(t.Context(), key, 42, make([]byte, maximumJournalValueBytes+1)); err == nil || store.calls != calls {
		t.Fatal("oversized write reached storage")
	}
	store.value = make([]byte, maximumJournalValueBytes+1)
	if value, revision, err := wrapped.Get(t.Context(), key); err == nil || value != nil || revision != 0 {
		t.Fatal("oversized read escaped")
	}
	store.value = nil
	store.revision = 0
	if value, revision, err := wrapped.Get(t.Context(), key); err != nil || value != nil || revision != 0 {
		t.Fatal("missing key semantics changed")
	}
	conflict := provider.OwnershipCASConflict{}
	store.err = conflict
	if err := wrapped.CompareAndSwap(t.Context(), key, 42, nil); err != conflict {
		t.Fatalf("CAS conflict identity lost: %v", err)
	}
	sentinel := errors.New("storage unavailable")
	store.err = sentinel
	if _, _, err := wrapped.Get(t.Context(), key); err != sentinel {
		t.Fatalf("storage error identity lost: %v", err)
	}
	// Even simultaneous revocation must retain the underlying conflict for errors.As.
	store.err = conflict
	revoked := false
	store.after = func() { revoked = true }
	wrapped, err = NewJournalCAS(store, []string{key}, func(context.Context) error {
		if revoked {
			return sentinel
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = wrapped.CompareAndSwap(t.Context(), key, 42, nil)
	var got provider.OwnershipCASConflict
	if !errors.As(err, &got) || !errors.Is(err, sentinel) {
		t.Fatalf("post-guard error discarded conflict: %v", err)
	}
}
