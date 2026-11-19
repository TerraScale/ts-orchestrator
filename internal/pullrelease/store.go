package pullrelease

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

const (
	Bucket     = "TS_ORCH_PULL_ROLLOUT"
	leaseFor   = 15 * time.Second
	renewEvery = 5 * time.Second
)

var errChanged = errors.New("pull rollout record changed under this manager")

type lease struct {
	Owner string    `json:"owner"`
	Until time.Time `json:"until"`
}

type sighting struct {
	Release string    `json:"release"`
	Seq     uint64    `json:"seq"`
	At      time.Time `json:"at"`
}

type Store struct {
	kv     jetstream.KeyValue
	fabric *nats.Conn
	region string
}

func Observe(ctx context.Context, fabric *nats.Conn, region string) (Status, error) {
	js, err := jetstream.New(fabric)
	if err != nil {
		return Status{}, err
	}
	kv, err := js.KeyValue(ctx, Bucket)
	if err != nil {
		return Status{}, err
	}
	status, _, err := (&Store{kv: kv, fabric: fabric, region: region}).Load(ctx)
	return status, err
}

func Open(ctx context.Context, fabric *nats.Conn, region, key string) (*Store, error) {
	js, err := jetstream.New(fabric)
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, Replicas: mesh.StoreReplicas(region), History: 1, MaxValueSize: 256 << 10, Storage: jetstream.FileStorage})
	if err != nil {
		return nil, fmt.Errorf("pull rollout store: %w", err)
	}
	return &Store{kv: kv, fabric: fabric, region: key}, nil
}

func (s *Store) Load(ctx context.Context) (Status, uint64, error) {
	entry, err := s.kv.Get(ctx, s.region)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Status{Region: s.region, Phase: PhaseIdle}, 0, nil
	}
	if err != nil {
		return Status{}, 0, err
	}
	var status Status
	if err := json.Unmarshal(entry.Value(), &status); err != nil {
		return Status{}, 0, fmt.Errorf("pull rollout record damaged: %w", err)
	}
	return status, entry.Revision(), nil
}

func (s *Store) Save(ctx context.Context, status Status, revision uint64) (uint64, error) {
	data, err := json.Marshal(status)
	if err != nil {
		return 0, err
	}
	if revision == 0 {
		revision, err = s.kv.Create(ctx, s.region, data)
	} else {
		revision, err = s.kv.Update(ctx, s.region, data, revision)
	}
	if errors.Is(err, jetstream.ErrKeyExists) {
		return 0, errChanged
	}
	return revision, err
}

func (s *Store) Lead(ctx context.Context, self string) (bool, error) {
	key := s.region + ".lease"
	now := time.Now()
	next, err := json.Marshal(lease{Owner: self, Until: now.Add(leaseFor)})
	if err != nil {
		return false, err
	}
	entry, err := s.kv.Get(ctx, key)
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		_, err = s.kv.Create(ctx, key, next)
	case err != nil:
		return false, err
	default:
		var held lease
		if json.Unmarshal(entry.Value(), &held) == nil && held.Owner != self && now.Before(held.Until) {
			return false, nil
		}
		_, err = s.kv.Update(ctx, key, next, entry.Revision())
	}
	if errors.Is(err, jetstream.ErrKeyExists) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) Seen(ctx context.Context, release string, seq uint64, at time.Time) (time.Time, error) {
	key := fmt.Sprintf("%s.discovered.%s.%d", s.region, release, seq)
	data, err := json.Marshal(sighting{Release: release, Seq: seq, At: at})
	if err != nil {
		return at, err
	}
	if _, err := s.kv.Create(ctx, key, data); !errors.Is(err, jetstream.ErrKeyExists) {
		return at, err
	}
	entry, err := s.kv.Get(ctx, key)
	if err != nil {
		return at, err
	}
	var seen sighting
	if err := json.Unmarshal(entry.Value(), &seen); err != nil {
		return at, fmt.Errorf("release sighting %s damaged: %w", key, err)
	}
	return seen.At, nil
}
