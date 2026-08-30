package control

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// NatsCommandReplayStore is the production replay boundary. JetStream KV
// Create is an atomic insert, so concurrent controller instances cannot both
// consume the same canonical command identity. The bucket must be provisioned
// with an expiry at least as long as the command validity window.
type NatsCommandReplayStore struct {
	store   jetstream.KeyValue
	timeout time.Duration
}

func NewNatsCommandReplayStore(store jetstream.KeyValue) (*NatsCommandReplayStore, error) {
	if store == nil {
		return nil, errors.New("a JetStream command replay KV store is required")
	}
	return &NatsCommandReplayStore{store: store, timeout: 5 * time.Second}, nil
}

// DurableCommandReplayStore marks this implementation as safe for
// multi-instance command ingress composition.
func (*NatsCommandReplayStore) DurableCommandReplayStore() {}

func (s *NatsCommandReplayStore) TryConsume(key security.CommandReplayKey, expiresAt time.Time) (security.CommandReplayConsumeResult, error) {
	if s == nil || s.store == nil {
		return security.CommandReplayConsumeRejected, errors.New("command replay store is unavailable")
	}
	if !expiresAt.After(time.Now().UTC()) {
		return security.CommandReplayConsumeRejected, errors.New("command replay expiry is invalid")
	}
	encoded := make([]byte, 8+len(key))
	binary.BigEndian.PutUint64(encoded[:8], uint64(expiresAt.UnixNano()))
	copy(encoded[8:], key[:])
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	_, err := s.store.Create(ctx, commandReplayKVKey(key), encoded)
	if err == nil {
		return security.CommandReplayConsumeConsumed, nil
	}
	if errors.Is(err, jetstream.ErrKeyExists) {
		return security.CommandReplayConsumeAlreadyConsumed, nil
	}
	return security.CommandReplayConsumeRejected, errors.New("durable command replay claim failed")
}

func commandReplayKVKey(key security.CommandReplayKey) string {
	const hex = "0123456789abcdef"
	encoded := make([]byte, len(key)*2)
	for i, value := range key {
		encoded[2*i] = hex[value>>4]
		encoded[2*i+1] = hex[value&15]
	}
	return "command." + string(encoded)
}

var _ security.DurableCommandReplayStore = (*NatsCommandReplayStore)(nil)
