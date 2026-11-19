package rolloutlease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

const Bucket = "TS_ORCH_PULL_ROLLOUT"

const leaseFor = 15 * time.Second
const RenewEvery = 5 * time.Second

type lease struct {
	Owner string    `json:"owner"`
	Until time.Time `json:"until"`
}

func Open(ctx context.Context, fabric *nats.Conn, region string) (jetstream.KeyValue, error) {
	js, err := jetstream.New(fabric)
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, Replicas: mesh.StoreReplicas(region), History: 1, MaxValueSize: 256 << 10, Storage: jetstream.FileStorage})
	if err != nil {
		return nil, fmt.Errorf("pull rollout store: %w", err)
	}
	return kv, nil
}

func Lead(ctx context.Context, kv jetstream.KeyValue, record, self string) (bool, error) {
	key := record + ".lease"
	now := time.Now()
	next, err := json.Marshal(lease{Owner: self, Until: now.Add(leaseFor)})
	if err != nil {
		return false, err
	}
	entry, err := kv.Get(ctx, key)
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		_, err = kv.Create(ctx, key, next)
	case err != nil:
		return false, err
	default:
		var held lease
		if json.Unmarshal(entry.Value(), &held) == nil && held.Owner != self && now.Before(held.Until) {
			return false, nil
		}
		_, err = kv.Update(ctx, key, next, entry.Revision())
	}
	if errors.Is(err, jetstream.ErrKeyExists) {
		return false, nil
	}
	return err == nil, err
}
