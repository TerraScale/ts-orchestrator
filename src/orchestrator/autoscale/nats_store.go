package autoscale

import (
	"context"
	"errors"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

// NATSTargetStore persists all regional targets in the GRU R3 authority
// journal. The journal checks the exact live lease and stream revision for
// every transaction, so a regional worker cannot write after takeover.
type NATSTargetStore struct {
	journal *authorityjournal.Journal[map[string]Target]
}

func NewNATSTargetStore(journal *authorityjournal.Journal[map[string]Target]) (*NATSTargetStore, error) {
	if journal == nil {
		return nil, errors.New("autoscale: authority journal is required")
	}
	return &NATSTargetStore{journal: journal}, nil
}

func (s *NATSTargetStore) Load(ctx context.Context, region string) (Target, bool, error) {
	var result Target
	var found bool
	err := s.journal.Transact(ctx, false, func(state *map[string]Target) error {
		result, found = (*state)[region]
		return nil
	})
	// Read-only transactions still publish a barrier against the shared
	// stream, so a concurrent writer's CAS can surface here as a conflict;
	// callers must treat it as retryable exactly like the CAS path does.
	if errors.Is(err, authorityjournal.ErrConflict) {
		return Target{}, false, ErrConflict
	}
	return result, found, err
}

func (s *NATSTargetStore) CompareAndSwap(ctx context.Context, region string, expected *Target, next Target) error {
	err := s.journal.Transact(ctx, true, func(state *map[string]Target) error {
		if *state == nil {
			*state = make(map[string]Target)
		}
		current, found := (*state)[region]
		if expected == nil && found || expected != nil && (!found || !reflect.DeepEqual(*expected, current)) {
			return ErrConflict
		}
		if next.Region != region {
			return errors.New("autoscale: target region mismatch")
		}
		(*state)[region] = next
		return nil
	})
	if errors.Is(err, authorityjournal.ErrConflict) {
		return ErrConflict
	}
	return err
}
