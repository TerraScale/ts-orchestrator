package placementtransition

import (
	"context"
	"encoding/json/v2"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

// shardedJournal keeps one bounded scope head and separately retained immutable
// operation receipts. The old head is archived before a successor may replace
// it. A crash between archive and replacement merely repeats the same archive.
type shardedJournal struct {
	config authorityjournal.Config
	open   func(string) (transaction, error)
}
type scopeContextKey struct{}

func (j *shardedJournal) reserve(ctx context.Context, kind, id, value string) error {
	if !token(id) || !digest(value) {
		return ErrInvalid
	}
	c := j.config
	c.StateKey = "placement.accepted.reserve." + kind + "." + hash([]byte(id))
	journal, err := authorityjournal.New(c, func() string { return "" }, func(s string) error {
		if s != "" && !digest(s) {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		return err
	}
	return journal.Transact(ctx, true, func(s *string) error {
		if *s != "" && *s != value {
			return ErrConflict
		}
		*s = value
		return nil
	})
}
func scopeContext(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeContextKey{}, scope)
}
func (j *shardedJournal) journal(key string) (transaction, error) {
	if j.open != nil {
		return j.open(key)
	}
	c := j.config
	c.StateKey = "placement.accepted." + key
	return authorityjournal.New(c, emptyState, validState)
}
func (j *shardedJournal) archive(ctx context.Context, op string, e entry) error {
	journal, err := j.journal("operation." + hash([]byte(op)))
	if err != nil {
		return err
	}
	return journal.TransactRevision(ctx, true, func(s *state, _ uint64) error {
		if prior, ok := s.Operations[op]; ok {
			if prior.RequestDigest != e.RequestDigest || string(prior.Proof.Payload) != string(e.Proof.Payload) {
				return ErrConflict
			}
			return nil
		}
		var p Proof
		if json.Unmarshal(e.Proof.Payload, &p) != nil {
			return ErrInvalid
		}
		s.Checkpoint = true
		s.Operations[op] = e
		s.Heads[p.Request.ScopeID] = op
		if p.GenesisGrantID != "" {
			s.Genesis[p.GenesisGrantID] = op
		}
		return nil
	})
}
func (j *shardedJournal) load(ctx context.Context, op string) (Signed, error) {
	journal, err := j.journal("operation." + hash([]byte(op)))
	if err != nil {
		return Signed{}, err
	}
	var result Signed
	err = journal.TransactRevision(ctx, false, func(s *state, _ uint64) error {
		e, ok := s.Operations[op]
		if !ok {
			return ErrMissing
		}
		result = cloneSigned(e.Proof)
		return nil
	})
	if err != nil {
		return Signed{}, err
	}
	return result, nil
}
func (j *shardedJournal) TransactRevision(ctx context.Context, write bool, change func(*state, uint64) error) error {
	scope, ok := ctx.Value(scopeContextKey{}).(string)
	if !ok || !token(scope) {
		return ErrInvalid
	}
	journal, err := j.journal("scope." + hash([]byte(scope)))
	if err != nil {
		return err
	}
	for range 8 {
		prior := emptyState()
		err = journal.TransactRevision(ctx, false, func(s *state, _ uint64) error { prior = *s; return nil })
		if err != nil {
			return err
		}
		for op, e := range prior.Operations {
			if err := j.archive(ctx, op, e); err != nil {
				return err
			}
		}
		priorHead := prior.Heads[scope]
		err = journal.TransactRevision(ctx, write, func(s *state, revision uint64) error {
			if s.Heads[scope] != priorHead {
				return ErrConflict
			}
			if err := change(s, revision); err != nil {
				return err
			}
			// Keep only the current head after its predecessor was archived above.
			head := s.Heads[scope]
			if head != "" {
				e := s.Operations[head]
				var p Proof
				if json.Unmarshal(e.Proof.Payload, &p) != nil {
					return ErrInvalid
				}
				s.Operations = map[string]entry{head: e}
				s.Genesis = map[string]string{}
				if p.GenesisGrantID != "" {
					s.Genesis[p.GenesisGrantID] = head
				}
			}
			s.Checkpoint = true
			return nil
		})
		if errors.Is(err, ErrConflict) {
			continue
		}
		return err
	}
	return ErrConflict
}
