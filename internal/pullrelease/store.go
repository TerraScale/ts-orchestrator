package pullrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/rolloutlease"
)

var errChanged = errors.New("pull rollout record changed under this manager")

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
	kv, err := js.KeyValue(ctx, rolloutlease.Bucket)
	if err != nil {
		return Status{}, err
	}
	status, _, err := (&Store{kv: kv, fabric: fabric, region: region}).Load(ctx)
	return status, err
}

func Open(ctx context.Context, fabric *nats.Conn, region string) (*Store, error) {
	kv, err := rolloutlease.Open(ctx, fabric, region)
	if err != nil {
		return nil, err
	}
	return &Store{kv: kv, fabric: fabric, region: region}, nil
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
	return rolloutlease.Lead(ctx, s.kv, s.region, self)
}
