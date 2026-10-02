package capacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	// UsageBucket holds host- and controller-published measurements.
	UsageBucket       = "TS_STORAGE_USAGE"
	usageMaxValueSize = 4 << 10
	maxUsageRecords   = 4096
)

// UsageStore is the regional TTL'd JetStream KV of storage measurements.
// Entries expire on their own, so a stopped publisher cannot leave stale
// headroom behind for placement.
type UsageStore struct {
	kv     jetstream.KeyValue
	ttl    time.Duration
	policy Policy
	now    func() time.Time
}

// OpenUsageStore creates or opens UsageBucket with a per-bucket TTL.
func OpenUsageStore(ctx context.Context, js jetstream.JetStream, replicas int, ttl time.Duration, policy Policy) (*UsageStore, error) {
	if js == nil || replicas < 1 || replicas > 5 || ttl < time.Second || ttl > time.Hour {
		return nil, errors.New("storage usage store requires JetStream, one to five replicas and a TTL between 1s and 1h")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       UsageBucket,
		Description:  "TTL'd storage capacity measurements",
		MaxValueSize: usageMaxValueSize,
		History:      1,
		TTL:          ttl,
		Storage:      jetstream.FileStorage,
		Replicas:     replicas,
	})
	if err != nil {
		if !errors.Is(err, jetstream.ErrBucketExists) {
			return nil, fmt.Errorf("create storage usage bucket: %w", err)
		}
		if kv, err = js.KeyValue(ctx, UsageBucket); err != nil {
			return nil, fmt.Errorf("open storage usage bucket: %w", err)
		}
		status, err := kv.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("inspect storage usage bucket: %w", err)
		}
		if status.TTL() <= 0 || status.TTL() > time.Hour {
			return nil, errors.New("existing storage usage bucket has no bounded TTL")
		}
		ttl = status.TTL()
	}
	return &UsageStore{kv: kv, ttl: ttl, policy: policy, now: time.Now}, nil
}

func usageKey(usage VolumeUsage) string {
	sum := sha256.Sum256([]byte(usage.Cell + "\x00" + usage.Node + "\x00" + string(usage.Role) + "\x00" + usage.VolumeID + "\x00" + usage.MountPath))
	return "usage." + hex.EncodeToString(sum[:16])
}

// Publish stores one validated measurement under its stable key.
func (store *UsageStore) Publish(ctx context.Context, usage VolumeUsage) error {
	if err := usage.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(usage)
	if err != nil {
		return fmt.Errorf("encode storage usage: %w", err)
	}
	if _, err := store.kv.Put(ctx, usageKey(usage), data); err != nil {
		return fmt.Errorf("publish storage usage: %w", err)
	}
	return nil
}

// Usages returns every current measurement. Records older than the TTL are
// skipped even if the server has not purged them yet.
func (store *UsageStore) Usages(ctx context.Context) ([]VolumeUsage, error) {
	lister, err := store.kv.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list storage usage: %w", err)
	}
	defer func() { _ = lister.Stop() }()
	now := store.now()
	var usages []VolumeUsage
	for key := range lister.Keys() {
		if len(usages) >= maxUsageRecords {
			return nil, errors.New("storage usage inventory exceeds its safety bound")
		}
		entry, err := store.kv.Get(ctx, key)
		if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read storage usage: %w", err)
		}
		var usage VolumeUsage
		if err := json.Unmarshal(entry.Value(), &usage, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("decode storage usage: %w", err)
		}
		if usage.Validate() != nil || usageKey(usage) != key || now.Sub(usage.ObservedAt) > store.ttl {
			continue
		}
		usages = append(usages, usage)
	}
	return usages, nil
}

// Signals implements SignalSource with the store's policy.
func (store *UsageStore) Signals(ctx context.Context) ([]Signal, error) {
	usages, err := store.Usages(ctx)
	if err != nil {
		return nil, err
	}
	signals := make([]Signal, 0, len(usages))
	for _, usage := range usages {
		signals = append(signals, Evaluate(usage, store.policy))
	}
	return signals, nil
}
