package provider

import (
	"context"
	"errors"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// NatsOwnershipCASStore adapts JetStream KV's revision-fenced Update/Create
// operations to the provider journal without importing the control package.
type NatsOwnershipCASStore struct{ Store jetstream.KeyValue }

func NewNatsOwnershipCASStore(store jetstream.KeyValue) (*NatsOwnershipCASStore, error) {
	if store == nil {
		return nil, &errs.Argument{Param: "store", Message: "JetStream ownership KV store is required"}
	}
	return &NatsOwnershipCASStore{Store: store}, nil
}

func (s *NatsOwnershipCASStore) Get(ctx context.Context, key string) ([]byte, uint64, error) {
	if s == nil || s.Store == nil {
		return nil, 0, &InvalidOperationError{Message: "ownership KV store is unavailable"}
	}
	entry, err := s.Store.Get(ctx, key)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return append([]byte(nil), entry.Value()...), entry.Revision(), nil
}

func (s *NatsOwnershipCASStore) CompareAndSwap(ctx context.Context, key string, revision uint64, value []byte) error {
	if s == nil || s.Store == nil {
		return &InvalidOperationError{Message: "ownership KV store is unavailable"}
	}
	var err error
	if revision == 0 {
		_, err = s.Store.Create(ctx, key, value)
		if errors.Is(err, jetstream.ErrKeyExists) {
			return OwnershipCASConflict{}
		}
		return err
	}
	_, err = s.Store.Update(ctx, key, value, revision)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyNotFound) {
		return OwnershipCASConflict{}
	}
	return err
}

var _ OwnershipCASStore = (*NatsOwnershipCASStore)(nil)
