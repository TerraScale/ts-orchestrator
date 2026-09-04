package cloudflare

// This file hosts the I-4 KV writer loop skeleton (D-58): the periodic pass
// that keeps the two maps the ts-proxy Worker reads fresh. Region health is
// rewritten every tick (default 10s); database placement is rewritten only
// when its hosting set changes. Health is always written before placement so
// first-contact REST never routes to a Region whose health entry is stale.
// Writes are billed, so the loop counts every tick and fires a budget alert
// hook instead of silently overspending. The loop performs no observation
// itself; health and placement facts are supplied by interfaces so tests never
// touch the network and the writer never invents an observation.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultKVWriterHealthInterval is the I-4 health cadence: every Region health
// entry is rewritten every 10 seconds.
const DefaultKVWriterHealthInterval = 10 * time.Second

// KVRegionHealthSource observes the current Region health facts. Keys are bare
// region codes; the writer stamps UpdatedAt itself so freshness is provable.
type KVRegionHealthSource interface {
	ObserveRegionHealth(context.Context) (map[string]RegionHealth, error)
}

// KVDBPlacementSource observes the current database placement facts. Keys are
// database ids; only the hosting Region set drives change detection.
type KVDBPlacementSource interface {
	ObserveDBPlacement(context.Context) (map[string]DBPlacement, error)
}

// KVWriterStore is the write seam the loop drives. *Client satisfies it; the
// bulk entry point below batches one tick into health-before-placement order.
type KVWriterStore interface {
	SetRegionHealth(context.Context, string, RegionHealth) error
	SetDBPlacement(context.Context, string, DBPlacement) error
}

// KVWriterDeleteStore is implemented by stores that can remove entries that
// disappeared from an observation. The production Cloudflare client
// implements it; a store without delete support is rejected as soon as a
// stale key is detected so stale routing data is never silently retained.
type KVWriterDeleteStore interface {
	DeleteRegionHealth(context.Context, string) error
	DeleteDBPlacement(context.Context, string) error
}

// KVWriterConfig is the fully explicit configuration of one writer loop. No
// ambient environment is read; a zero HealthInterval selects the 10s default
// and a nil Now selects time.Now.
type KVWriterConfig struct {
	Store            KVWriterStore
	Health           KVRegionHealthSource
	Placement        KVDBPlacementSource
	HealthInterval   time.Duration
	MaxWritesPerTick int
	OnBudgetExceeded func(tickWrites int)
	Now              func() time.Time
}

// KVWriter is the I-4 loop: Step performs one tick (observe, write health,
// write changed placement), Start ticks Step until ctx is cancelled.
type KVWriter struct {
	store            KVWriterStore
	health           KVRegionHealthSource
	placement        KVDBPlacementSource
	interval         time.Duration
	maxWritesPerTick int
	onBudgetExceeded func(int)
	now              func() time.Time

	stepMutex     sync.Mutex
	mutex         sync.Mutex
	lastPlacement map[string]string
	lastHealth    map[string]struct{}
	writeCount    int
	lastErr       error

	cancel     context.CancelFunc
	completion chan struct{}
	closeOnce  sync.Once
	started    bool
	closed     bool
}

// NewKVWriter validates the configuration and composes the loop. Nothing is
// started here; Start does that.
func NewKVWriter(config KVWriterConfig) (*KVWriter, error) {
	if config.Store == nil {
		return nil, errors.New("cloudflare: kv writer store is required")
	}
	if config.Health == nil {
		return nil, errors.New("cloudflare: kv writer health source is required")
	}
	if config.Placement == nil {
		return nil, errors.New("cloudflare: kv writer placement source is required")
	}
	interval := config.HealthInterval
	if interval == 0 {
		interval = DefaultKVWriterHealthInterval
	}
	if interval <= 0 {
		return nil, errors.New("cloudflare: kv writer health interval must be positive")
	}
	if config.MaxWritesPerTick < 0 {
		return nil, errors.New("cloudflare: kv writer write budget must be non-negative")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &KVWriter{
		store:            config.Store,
		health:           config.Health,
		placement:        config.Placement,
		interval:         interval,
		maxWritesPerTick: config.MaxWritesPerTick,
		onBudgetExceeded: config.OnBudgetExceeded,
		now:              now,
		lastPlacement:    make(map[string]string),
		lastHealth:       make(map[string]struct{}),
		completion:       make(chan struct{}),
	}, nil
}

// Interval reports the health cadence the loop ticks with.
func (w *KVWriter) Interval() time.Duration {
	if w == nil {
		return 0
	}
	return w.interval
}

// WriteCount reports the cumulative KV writes performed by Step calls.
func (w *KVWriter) WriteCount() int {
	if w == nil {
		return 0
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.writeCount
}

// LastError reports the most recent Step failure, or nil when the last tick
// succeeded.
func (w *KVWriter) LastError() error {
	if w == nil {
		return errors.New("cloudflare: kv writer is unavailable")
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.lastErr
}

// Completion closes when the Start context is cancelled and the loop exits.
func (w *KVWriter) Completion() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.completion
}

// WriteBatch writes one tick in bulk order: every health entry first, then
// every placement entry. Keys are written in sorted order so ticks are
// deterministic. The budget hook fires after the writes when the tick exceeds
// MaxWritesPerTick; writes are never skipped for budget reasons.
func (w *KVWriter) WriteBatch(ctx context.Context, health map[string]RegionHealth, placement map[string]DBPlacement) (int, error) {
	if w == nil {
		return 0, errors.New("cloudflare: kv writer is unavailable")
	}
	w.stepMutex.Lock()
	defer w.stepMutex.Unlock()
	writes, err := w.writeBatch(ctx, health, placement)
	w.recordTickWrites(writes)
	return writes, err
}

// writeBatch performs the sets for one tick without mutating writer state.
// Callers account for the successful operations exactly once after this
// returns, including when a later operation fails.
func (w *KVWriter) writeBatch(ctx context.Context, health map[string]RegionHealth, placement map[string]DBPlacement) (int, error) {
	if ctx == nil {
		return 0, errors.New("cloudflare: kv writer context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if health == nil || placement == nil {
		return 0, errors.New("cloudflare: kv writer batch maps are required")
	}
	now := w.now()
	healthKeys := make([]string, 0, len(health))
	for region := range health {
		if err := validateKVWriterKey(region); err != nil {
			return 0, err
		}
		healthKeys = append(healthKeys, region)
	}
	sort.Strings(healthKeys)
	placementKeys := make([]string, 0, len(placement))
	for database := range placement {
		if err := validateKVWriterKey(database); err != nil {
			return 0, err
		}
		placementKeys = append(placementKeys, database)
	}
	sort.Strings(placementKeys)
	writes := 0
	for _, region := range healthKeys {
		if err := ctx.Err(); err != nil {
			return writes, err
		}
		entry := health[region]
		entry.Region = region
		entry.Members = append([]string(nil), entry.Members...)
		sort.Strings(entry.Members)
		entry.UpdatedAt = now
		if err := w.store.SetRegionHealth(ctx, region, entry); err != nil {
			return writes, err
		}
		writes++
	}
	for _, database := range placementKeys {
		if err := ctx.Err(); err != nil {
			return writes, err
		}
		entry := placement[database]
		entry.Database = database
		entry.Regions = append([]string(nil), entry.Regions...)
		sort.Strings(entry.Regions)
		entry.UpdatedAt = now
		if err := w.store.SetDBPlacement(ctx, database, entry); err != nil {
			return writes, err
		}
		writes++
	}
	return writes, nil
}

// Step performs one writer tick: observe health, rewrite every health entry,
// observe placement, and rewrite only the placement entries whose hosting set
// changed since the last successful tick.
func (w *KVWriter) Step(ctx context.Context) (int, error) {
	if w == nil {
		return 0, errors.New("cloudflare: kv writer is unavailable")
	}
	if ctx == nil {
		return 0, errors.New("cloudflare: kv writer context is required")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	w.stepMutex.Lock()
	defer w.stepMutex.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	health, err := w.health.ObserveRegionHealth(ctx)
	if err != nil {
		w.recordErr(err)
		return 0, err
	}
	if health == nil {
		err = errors.New("cloudflare: region health observation is missing")
		w.recordErr(err)
		return 0, err
	}
	for region := range health {
		if err := validateKVWriterKey(region); err != nil {
			w.recordErr(err)
			return 0, err
		}
	}
	placement, err := w.placement.ObserveDBPlacement(ctx)
	if err != nil {
		w.recordErr(err)
		return 0, err
	}
	if placement == nil {
		err = errors.New("cloudflare: database placement observation is missing")
		w.recordErr(err)
		return 0, err
	}
	for database := range placement {
		if err := validateKVWriterKey(database); err != nil {
			w.recordErr(err)
			return 0, err
		}
	}
	staleHealth, stalePlacement := w.staleKeys(health, placement)
	if len(staleHealth) > 0 || len(stalePlacement) > 0 {
		if _, ok := w.store.(KVWriterDeleteStore); !ok {
			err = errors.New("cloudflare: kv writer store cannot delete stale entries")
			w.recordErr(err)
			return 0, err
		}
	}
	changed := w.filterChangedPlacement(placement)
	writes, err := w.writeBatch(ctx, health, changed)
	if err != nil {
		w.recordTickWrites(writes)
		w.recordErr(err)
		return writes, err
	}
	if len(staleHealth) > 0 || len(stalePlacement) > 0 {
		deleter := w.store.(KVWriterDeleteStore)
		for _, region := range staleHealth {
			if err := ctx.Err(); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			if err := deleter.DeleteRegionHealth(ctx, region); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			writes++
		}
		for _, database := range stalePlacement {
			if err := ctx.Err(); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			if err := deleter.DeleteDBPlacement(ctx, database); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			writes++
		}
	}
	// The observations become the retry baseline only after every set and
	// delete in this tick has succeeded. A partial delete therefore remains in
	// staleKeys for the next tick and is safely retried.
	w.recordChangedPlacement(changed)
	w.recordObservedHealth(health)
	w.removeStalePlacement(stalePlacement)
	w.recordTickWrites(writes)
	w.recordErr(nil)
	return writes, nil
}

// Start ticks Step every HealthInterval until ctx is cancelled. Only the first
// call starts the loop; later calls are no-ops. A tick failure is retained in
// LastError and retried on the next interval; the loop never invents facts.
func (w *KVWriter) Start(ctx context.Context) error {
	if w == nil {
		return errors.New("cloudflare: kv writer is unavailable")
	}
	if ctx == nil {
		return errors.New("cloudflare: kv writer context is required")
	}
	w.mutex.Lock()
	if w.closed || w.started {
		w.mutex.Unlock()
		return nil
	}
	w.started = true
	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.mutex.Unlock()
	go func() {
		defer close(w.completion)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			_, _ = w.Step(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

// Close stops the loop started by Start and waits for it to exit. It is
// idempotent and safe to call without Start.
func (w *KVWriter) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		w.mutex.Lock()
		w.closed = true
		cancel := w.cancel
		started := w.started
		if w.completion == nil {
			w.completion = make(chan struct{})
		}
		if !started {
			close(w.completion)
		}
		w.mutex.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	select {
	case <-w.completion:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("cloudflare: kv writer shutdown timed out")
	}
}

func (w *KVWriter) recordErr(err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.lastErr = err
}

func (w *KVWriter) filterChangedPlacement(placement map[string]DBPlacement) map[string]DBPlacement {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	changed := make(map[string]DBPlacement, len(placement))
	for database, entry := range placement {
		regions := append([]string(nil), entry.Regions...)
		sort.Strings(regions)
		fingerprint := strings.Join(regions, "\n")
		previous, ok := w.lastPlacement[database]
		if !ok || previous != fingerprint {
			changed[database] = entry
		}
	}
	return changed
}

func (w *KVWriter) recordChangedPlacement(changed map[string]DBPlacement) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	for database, entry := range changed {
		regions := append([]string(nil), entry.Regions...)
		sort.Strings(regions)
		w.lastPlacement[database] = strings.Join(regions, "\n")
	}
}

func (w *KVWriter) staleKeys(health map[string]RegionHealth, placement map[string]DBPlacement) ([]string, []string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	var staleHealth []string
	for region := range w.lastHealth {
		if _, ok := health[region]; !ok {
			staleHealth = append(staleHealth, region)
		}
	}
	var stalePlacement []string
	for database := range w.lastPlacement {
		if _, ok := placement[database]; !ok {
			stalePlacement = append(stalePlacement, database)
		}
	}
	sort.Strings(staleHealth)
	sort.Strings(stalePlacement)
	return staleHealth, stalePlacement
}

func (w *KVWriter) recordObservedHealth(health map[string]RegionHealth) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.lastHealth = make(map[string]struct{}, len(health))
	for region := range health {
		w.lastHealth[region] = struct{}{}
	}
}

func (w *KVWriter) removeStalePlacement(databases []string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	for _, database := range databases {
		delete(w.lastPlacement, database)
	}
}

func (w *KVWriter) recordTickWrites(writes int) {
	if writes == 0 {
		return
	}
	w.mutex.Lock()
	w.writeCount += writes
	hook := w.onBudgetExceeded
	budget := w.maxWritesPerTick
	w.mutex.Unlock()
	if budget > 0 && writes > budget && hook != nil {
		hook(writes)
	}
}

func validateKVWriterKey(key string) error {
	if key == "" || len(key) > 128 || strings.ContainsAny(key, "/\n\r\x00") {
		return errors.New("cloudflare: kv key must be a bounded slash-free token")
	}
	return nil
}
