package pullrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	Bucket     = "TS_ORCH_PULL_ROLLOUT"
	leaseFor   = 15 * time.Second
	renewEvery = 5 * time.Second
	pushHold   = 15 * time.Minute
)

var errChanged = errors.New("pull rollout record changed under this manager")

type lease struct {
	Owner string    `json:"owner"`
	Until time.Time `json:"until"`
}

type PushClaim struct {
	Release  string            `json:"release"`
	SHA      string            `json:"sha"`
	Binaries map[string]string `json:"binaries"`
	Host     string            `json:"host"`
	Until    time.Time         `json:"until"`
}

type Store struct {
	kv     jetstream.KeyValue
	region string
}

func Open(ctx context.Context, conn *nats.Conn, region string) (*Store, error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, Replicas: 3, History: 1, MaxValueSize: 256 << 10, Storage: jetstream.FileStorage})
	if err != nil {
		return nil, fmt.Errorf("pull rollout store: %w", err)
	}
	return &Store{kv: kv, region: region}, nil
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

func ClaimPush(ctx context.Context, conn *nats.Conn, region string, claim PushClaim) error {
	store, err := Open(ctx, conn, region)
	if err != nil {
		return err
	}
	for {
		status, revision, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if status.active() {
			target := ""
			if status.Target != nil {
				target = status.Target.Tag()
			}
			return fmt.Errorf("region %s is in a pull rollout of %s (%s): %s", region, target, status.Phase, status.Reason)
		}
		if held := status.Push; held != nil && held.Release != claim.Release && time.Now().Before(held.Until) {
			return fmt.Errorf("region %s is in the release push of %s", region, held.Release)
		}
		claim.Until = time.Now().Add(pushHold)
		status.Region, status.Push = region, &claim
		_, err = store.Save(ctx, status, revision)
		if !errors.Is(err, errChanged) {
			return err
		}
	}
}

func ReleasePush(ctx context.Context, conn *nats.Conn, region, release string) error {
	store, err := Open(ctx, conn, region)
	if err != nil {
		return err
	}
	for {
		status, revision, err := store.Load(ctx)
		if err != nil || status.Push == nil || status.Push.Release != release {
			return err
		}
		status.Push = nil
		_, err = store.Save(ctx, status, revision)
		if !errors.Is(err, errChanged) {
			return err
		}
	}
}
