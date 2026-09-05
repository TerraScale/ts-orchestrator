package control

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

type natsDeliveryStore struct {
	ctx        context.Context
	kv         jetstream.KeyValue
	connection *nats.Conn
}

func newNatsDeliveryStore(ctx context.Context, kv jetstream.KeyValue, connection *nats.Conn) (*natsDeliveryStore, error) {
	if ctx == nil || kv == nil || connection == nil {
		return nil, errors.New("signed delivery: durable store is missing")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	status, err := kv.Status(checkCtx)
	if err != nil {
		return nil, err
	}
	config := status.Config()
	if config.Storage != jetstream.FileStorage || config.TTL != 0 || config.MaxValueSize < messaging.DeliveryOperationMaxValueBytes {
		return nil, errors.New("signed delivery: journal requires persistent unexpired request and receipt storage")
	}
	return &natsDeliveryStore{ctx: ctx, kv: kv, connection: connection}, nil
}

func (s *natsDeliveryStore) Get(key string) (delivery.StoreEntry, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	value, revision, err := nodeauthority.ReadLeaderKV(ctx, s.connection, s.kv.Bucket(), key)
	if err != nil {
		return delivery.StoreEntry{}, deliveryStoreError(err)
	}
	return delivery.StoreEntry{Key: key, Value: value, Revision: revision}, nil
}

func (s *natsDeliveryStore) Create(key string, value []byte) (delivery.StoreEntry, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	if len(value) > messaging.DeliveryOperationMaxDocumentBytes {
		return delivery.StoreEntry{}, errors.New("signed delivery: journal value exceeds its bound")
	}
	revision, err := s.kv.Create(ctx, key, value)
	if err != nil {
		return delivery.StoreEntry{}, deliveryStoreError(err)
	}
	return delivery.StoreEntry{Key: key, Value: append([]byte(nil), value...), Revision: revision}, nil
}

func (s *natsDeliveryStore) Update(key string, expected uint64, value []byte) (delivery.StoreEntry, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	if expected == 0 || len(value) > messaging.DeliveryOperationMaxDocumentBytes {
		return delivery.StoreEntry{}, errors.New("signed delivery: invalid journal revision or value")
	}
	revision, err := s.kv.Update(ctx, key, value, expected)
	if err != nil {
		return delivery.StoreEntry{}, deliveryStoreError(err)
	}
	return delivery.StoreEntry{Key: key, Value: append([]byte(nil), value...), Revision: revision}, nil
}

func (s *natsDeliveryStore) List(prefix string) ([]delivery.StoreEntry, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	watcher, err := s.kv.WatchAll(ctx, jetstream.IgnoreDeletes(), jetstream.MetaOnly())
	if err != nil {
		return nil, err
	}
	defer watcher.Stop()
	var result []delivery.StoreEntry
	complete := false
	for !complete {
		var item jetstream.KeyValueEntry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case value, open := <-watcher.Updates():
			if !open {
				return nil, errors.New("signed delivery: journal listing interrupted")
			}
			item = value
		}
		if item == nil {
			complete = true
			break
		}
		if !strings.HasPrefix(item.Key(), prefix) {
			continue
		}
		value, revision, err := nodeauthority.ReadLeaderKV(ctx, s.connection, s.kv.Bucket(), item.Key())
		if err != nil {
			return nil, deliveryStoreError(err)
		}
		result = append(result, delivery.StoreEntry{Key: item.Key(), Value: value, Revision: revision})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !complete {
		return nil, errors.New("signed delivery: journal listing interrupted")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func deliveryStoreError(err error) error {
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound), errors.Is(err, jetstream.ErrKeyDeleted):
		return delivery.ErrStoreNotFound
	case errors.Is(err, jetstream.ErrKeyExists):
		return delivery.ErrStoreConflict
	default:
		return err
	}
}

var _ delivery.DurableStore = (*natsDeliveryStore)(nil)
