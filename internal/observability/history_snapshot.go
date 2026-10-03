package observability

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	historySnapshotVersion = 1
	// HistoryBucket is the KV bucket members snapshot their history into.
	HistoryBucket = "TS_METRIC_HISTORY"
	// DefaultSnapshotInterval is how often a member snapshots its history.
	DefaultSnapshotInterval = 5 * time.Minute
	maxSnapshotInflated     = 64 << 20
)

type historySnapshot struct {
	Version int              `json:"version"`
	SavedAt time.Time        `json:"saved_at"`
	Series  []seriesSnapshot `json:"series"`
}

type seriesSnapshot struct {
	Metric  string              `json:"metric"`
	Labels  []Label             `json:"labels,omitempty"`
	Counter bool                `json:"counter,omitzero"`
	Last    int64               `json:"last"`
	Tiers   map[string][]bucket `json:"tiers"`
}

// Export encodes the 1m and 5m tiers as gzip-compressed JSON of at most
// limit bytes. When everything does not fit it keeps only the 5m tier, and
// then only as many series as fit. Raw samples are not exported: they
// cover an hour and are rebuilt quickly after a restart.
func (history *History) Export(limit int) ([]byte, error) {
	history.mu.RLock()
	keys := slices.Sorted(maps.Keys(history.series))
	all := make([]seriesSnapshot, 0, len(keys))
	for _, key := range keys {
		current := history.series[key]
		all = append(all, seriesSnapshot{Metric: current.metric, Labels: current.labels,
			Counter: current.counter, Last: current.last, Tiers: map[string][]bucket{
				Tier1m: current.tiers[Tier1m].buckets(), Tier5m: current.tiers[Tier5m].buckets()}})
	}
	history.mu.RUnlock()
	encode := func(series []seriesSnapshot) ([]byte, error) {
		var buffer bytes.Buffer
		writer := gzip.NewWriter(&buffer)
		if err := json.NewEncoder(writer).Encode(historySnapshot{Version: historySnapshotVersion,
			SavedAt: time.Now().UTC(), Series: series}); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return buffer.Bytes(), nil
	}
	data, err := encode(all)
	if err != nil || limit <= 0 || len(data) <= limit {
		return data, err
	}
	for index := range all {
		delete(all[index].Tiers, Tier1m)
	}
	for count := len(all); count > 0; count /= 2 {
		data, err = encode(all[:count])
		if err != nil || len(data) <= limit {
			return data, err
		}
	}
	return encode(nil)
}

// Import merges an exported snapshot into the store. Series already
// present keep their newer data; restored series are bounded by MaxSeries.
func (history *History) Import(data []byte) error {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	var snapshot historySnapshot
	if err := json.NewDecoder(io.LimitReader(reader, maxSnapshotInflated)).Decode(&snapshot); err != nil {
		return err
	}
	if snapshot.Version != historySnapshotVersion {
		return errors.New("unsupported history snapshot version")
	}
	history.mu.Lock()
	defer history.mu.Unlock()
	for _, restored := range snapshot.Series {
		labels := sortedLabels(restored.Labels)
		key := seriesKey(restored.Metric, labels)
		if _, exists := history.series[key]; exists || len(history.series) >= history.config.MaxSeries ||
			restored.Metric == "" {
			continue
		}
		current := history.newSeries(restored.Metric, labels, restored.Counter)
		current.last = restored.Last
		latest := int64(0)
		for name, buckets := range restored.Tiers {
			t, ok := current.tiers[name]
			if !ok || name == TierRaw {
				continue
			}
			buckets = slices.DeleteFunc(slices.Clone(buckets), func(b bucket) bool { return b.Count == 0 })
			for index, b := range buckets {
				if index == len(buckets)-1 {
					// Export includes the bucket being filled: restore it
					// open, so samples resuming in the same step extend it
					// instead of opening a second bucket with that start.
					t.open, t.opened = b, true
					continue
				}
				t.push(b)
			}
			// The newest restored counter value is the baseline of the
			// next sample's increase.
			if len(buckets) > 0 && buckets[len(buckets)-1].lastAt() >= latest {
				latest = buckets[len(buckets)-1].lastAt()
				current.lastValue, current.sampled = buckets[len(buckets)-1].Last, true
			}
		}
		history.series[key] = current
	}
	return nil
}

// HistorySnapshots stores and loads one member's exported history.
type HistorySnapshots interface {
	Save(ctx context.Context, member string, data []byte) error
	Load(ctx context.Context, member string) ([]byte, error)
}

// KVHistorySnapshots keeps snapshots in a replicated JetStream KV bucket,
// one key per member.
type KVHistorySnapshots struct {
	kv jetstream.KeyValue
}

// OpenHistorySnapshots creates or opens the history bucket. maxValue bounds
// one member's snapshot and should stay below the connection's payload
// limit.
func OpenHistorySnapshots(ctx context.Context, js jetstream.JetStream, replicas int, maxValue int32) (*KVHistorySnapshots, error) {
	if js == nil || replicas < 1 || replicas > 5 || maxValue <= 0 {
		return nil, errors.New("history snapshots require JetStream, a replica count and a value bound")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: HistoryBucket,
		Description: "Member metric history snapshots for the dashboard", History: 1,
		MaxValueSize: maxValue, MaxBytes: int64(maxValue) * 32, Storage: jetstream.FileStorage,
		Replicas: replicas, TTL: 2 * fiveMinuteRetention})
	if err != nil {
		return nil, err
	}
	return &KVHistorySnapshots{kv: kv}, nil
}

// Save stores member's snapshot.
func (snapshots *KVHistorySnapshots) Save(ctx context.Context, member string, data []byte) error {
	_, err := snapshots.kv.Put(ctx, historyKey(member), data)
	return err
}

// Load returns member's snapshot, or nil when there is none.
func (snapshots *KVHistorySnapshots) Load(ctx context.Context, member string) ([]byte, error) {
	entry, err := snapshots.kv.Get(ctx, historyKey(member))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return entry.Value(), nil
}

// historyKey maps a member name to a valid KV key.
func historyKey(member string) string {
	return "member." + HashKey(member)
}

// HashKey returns a short stable token for an arbitrary identity.
func HashKey(value string) string {
	const alphabet = "0123456789abcdef"
	var hash uint64 = 1469598103934665603
	for index := range len(value) {
		hash ^= uint64(value[index])
		hash *= 1099511628211
	}
	out := make([]byte, 16)
	for index := range out {
		out[15-index] = alphabet[hash&0xf]
		hash >>= 4
	}
	return string(out)
}

// HistorySampler samples Collect every Interval into Store, restores a
// snapshot at start and saves one every SnapshotInterval when Snapshots is
// set. Snapshot failures are logged at debug and never stop sampling.
type HistorySampler struct {
	Store            *History
	Collect          func(ctx context.Context) []Sample
	Interval         time.Duration
	Member           string
	Snapshots        HistorySnapshots
	SnapshotInterval time.Duration
	SnapshotLimit    int
}

// Run samples until ctx ends.
func (sampler HistorySampler) Run(ctx context.Context) error {
	if sampler.Store == nil || sampler.Collect == nil {
		return errors.New("history sampler requires a store and a collector")
	}
	interval := sampler.Interval
	if interval <= 0 {
		interval = sampler.Store.config.Interval
	}
	snapshotEvery := sampler.SnapshotInterval
	if snapshotEvery <= 0 {
		snapshotEvery = DefaultSnapshotInterval
	}
	if sampler.Snapshots != nil {
		loadCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		data, err := sampler.Snapshots.Load(loadCtx, sampler.Member)
		cancel()
		if err == nil && len(data) > 0 {
			err = sampler.Store.Import(data)
		}
		if err != nil {
			slog.Debug("metric history snapshot not restored", ComponentKey, "observability", "error", err)
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastSnapshot := time.Now()
	for {
		sampleCtx, cancel := context.WithTimeout(ctx, interval)
		samples := sampler.Collect(sampleCtx)
		cancel()
		sampler.Store.Append(time.Now(), samples)
		if sampler.Snapshots != nil && time.Since(lastSnapshot) >= snapshotEvery {
			lastSnapshot = time.Now()
			sampler.save(ctx)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (sampler HistorySampler) save(ctx context.Context) {
	data, err := sampler.Store.Export(sampler.SnapshotLimit)
	if err == nil {
		saveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = sampler.Snapshots.Save(saveCtx, sampler.Member, data)
		cancel()
	}
	if err != nil {
		slog.Debug("metric history snapshot not saved", ComponentKey, "observability", "error", err)
	}
}
