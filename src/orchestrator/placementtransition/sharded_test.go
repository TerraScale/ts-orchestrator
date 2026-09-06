package placementtransition

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

func TestShardedArchiveSurvivesMoreThanLifetimeStateCap(t *testing.T) {
	stores := map[string]*memoryJournal{}
	j := &shardedJournal{open: func(key string) (transaction, error) {
		if stores[key] == nil {
			stores[key] = &memoryJournal{s: emptyState()}
		}
		return stores[key], nil
	}}
	ctx := scopeContext(t.Context(), "prod/cluster")
	previous := ""
	for n := range 600 {
		r := request()
		r.OperationID = fmt.Sprintf("op%d", n)
		r.Epoch = uint64(n + 1)
		r.Generation = r.Epoch
		r.PriorEpoch = uint64(n)
		d, _ := RequestDigest(r)
		p := Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: r, RequestDigest: d, AuthorityEpoch: 1, JournalRevision: uint64(n + 1), PriorGeneration: uint64(n), PreviousProofDigest: previous}
		if n == 0 {
			p.GenesisGrantID = "genesis"
			p.GenesisGrant = &Signed{Payload: []byte("grant")}
		}
		payload, _ := json.Marshal(p)
		e := entry{d, Signed{Payload: payload}}
		err := j.TransactRevision(ctx, true, func(s *state, _ uint64) error {
			s.Operations[r.OperationID] = e
			s.Heads[r.ScopeID] = r.OperationID
			if n == 0 {
				s.Genesis[p.GenesisGrantID] = r.OperationID
			}
			return nil
		})
		if err != nil {
			t.Fatal(n, err)
		}
		previous = hash(payload)
	}
	for n := range 599 {
		signed, err := j.load(t.Context(), fmt.Sprintf("op%d", n))
		if err != nil || len(signed.Payload) == 0 {
			t.Fatal("lost immutable historical receipt", n, err)
		}
	}
	for key, store := range stores {
		if len(store.s.Operations) > 1 {
			t.Fatal("unbounded journal", key)
		}
	}
	if len(stores) < 600 {
		t.Fatal("history not independently retained")
	}
}

func TestArchiveUnknownCommitDoesNotReplaceHead(t *testing.T) {
	stores := map[string]*memoryJournal{}
	j := &shardedJournal{open: func(key string) (transaction, error) {
		if stores[key] == nil {
			stores[key] = &memoryJournal{s: emptyState()}
		}
		return stores[key], nil
	}}
	r := request()
	d, _ := RequestDigest(r)
	p := Proof{SchemaVersion: 1, Kind: "accepted_epoch", Request: r, RequestDigest: d, AuthorityEpoch: 1, JournalRevision: 1, GenesisGrantID: "g", GenesisGrant: &Signed{Payload: []byte("grant")}}
	b, _ := json.Marshal(p)
	e := entry{d, Signed{Payload: b}}
	ctx := scopeContext(t.Context(), r.ScopeID)
	if err := j.TransactRevision(ctx, true, func(s *state, _ uint64) error {
		s.Operations[r.OperationID] = e
		s.Heads[r.ScopeID] = r.OperationID
		s.Genesis["g"] = r.OperationID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stores["operation."+hash([]byte(r.OperationID))] = &memoryJournal{s: emptyState(), unknown: true}
	called := false
	if err := j.TransactRevision(ctx, true, func(*state, uint64) error { called = true; return nil }); err == nil || called {
		t.Fatal("unknown archive allowed replacement")
	}
	if err := j.TransactRevision(ctx, true, func(*state, uint64) error { called = true; return nil }); err != nil || !called {
		t.Fatal("exact archive retry failed", err)
	}
}
