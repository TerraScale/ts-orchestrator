package cloudflare

// This file hosts the production KV writer: the periodic pass
// that keeps the two maps the ts-proxy Worker reads fresh. Region health is
// published as one complete document every tick (default 10s); database placement is rewritten only
// when its hosting set changes. Health is always written before placement so
// first-contact REST never routes to a Region whose health entry is stale.
// Writes are billed, so the loop counts every tick and fires a budget alert
// hook instead of silently overspending. The loop performs no observation
// itself; health and placement facts are supplied by interfaces so tests never
// touch the network and the writer never invents an observation.

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultKVWriterHealthInterval refreshes the full health document every 10 seconds.
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
	SetWorkerHealth(context.Context, WorkerHealthDoc) error
	SetWorkerPlacements(context.Context, map[string]WorkerPlacement) error
}

// KVWriterDeleteStore is implemented by stores that can remove entries that
// disappeared from an observation. The production Cloudflare client
// implements it; a store without delete support is rejected as soon as a
// stale key is detected so stale routing data is never silently retained.
type KVWriterDeleteStore interface {
	DeleteWorkerPlacements(context.Context, []string) error
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
	Catalog          []WorkerRegionCatalog
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
	catalog          []WorkerRegionCatalog

	stepMutex          sync.Mutex
	mutex              sync.Mutex
	lastPlacement      map[string]string
	lastPlacementState map[string]DBPlacement
	writeCount         int
	lastErr            error

	cancel     context.CancelFunc
	completion chan struct{}
	notify     chan struct{}
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
		store:              config.Store,
		health:             config.Health,
		placement:          config.Placement,
		interval:           interval,
		maxWritesPerTick:   config.MaxWritesPerTick,
		onBudgetExceeded:   config.OnBudgetExceeded,
		now:                now,
		catalog:            append([]WorkerRegionCatalog(nil), config.Catalog...),
		lastPlacement:      make(map[string]string),
		lastPlacementState: make(map[string]DBPlacement),
		completion:         make(chan struct{}),
		notify:             make(chan struct{}, 1),
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

// NotifyChange requests an immediate observation pass. It is the production
// placement-change path: the periodic ticker still refreshes Region health,
// while a durable placement update need not wait up to one health interval.
// Bursts coalesce into one pass and never block the caller.
func (w *KVWriter) NotifyChange() {
	if w == nil {
		return
	}
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// WriteBatch writes the complete health document before changed placement keys.
// The client sorts and chunks placement keys into bounded bulk requests. The budget hook fires after the writes when the tick exceeds
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
	now := w.now().Unix()
	doc := WorkerHealthDoc{Updated: now, Regions: make(map[string]WorkerRegionHealth, len(health)), Catalog: append([]WorkerRegionCatalog(nil), w.catalog...)}
	for region, entry := range health {
		var lag *int
		if entry.LagMeasured {
			lag = new(entry.LagMS)
		}
		doc.Regions[region] = WorkerRegionHealth{OK: entry.Healthy && !entry.Draining && !entry.Overloaded, LagMS: lag, Lat: entry.Lat, Lon: entry.Lon}
	}
	normalizedHealth, err := doc.normalized()
	if err != nil {
		return 0, err
	}
	placements := make(map[string]WorkerPlacement, len(placement))
	for database, entry := range placement {
		if _, err := workerPlacementKey(database); err != nil {
			return 0, err
		}
		if err := w.validatePlacement(database, entry); err != nil {
			return 0, err
		}
		residency := WorkerResidency{Label: entry.PlacementLock}
		if entry.PlacementLock == "explicit" {
			residency = WorkerResidency{Codes: entry.Regions}
		}
		wire, err := (WorkerPlacement{R: entry.Regions, Res: residency, G: entry.Generation, U: now}).normalized()
		if err != nil {
			return 0, err
		}
		placements[database] = wire
	}
	if err := w.store.SetWorkerHealth(ctx, normalizedHealth); err != nil {
		return 0, err
	}
	writes := 1
	if len(placements) > 0 {
		if err := w.store.SetWorkerPlacements(ctx, placements); err != nil {
			return writes, err
		}
		writes += len(placements)
	}

	return writes, nil
}

// Step performs one writer tick: observe health, replace the full health document,
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
	stalePlacement := w.stalePlacementKeys(placement)
	if len(stalePlacement) > 0 {
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
	if len(stalePlacement) > 0 {
		deleter := w.store.(KVWriterDeleteStore)
		for _, database := range stalePlacement {
			if err := ctx.Err(); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			if err := deleter.DeleteWorkerPlacements(ctx, []string{database}); err != nil {
				w.recordTickWrites(writes)
				w.recordErr(err)
				return writes, err
			}
			writes++
		}
	}
	// The observations become the retry baseline only after every set and
	// delete in this tick has succeeded. A partial delete therefore remains in
	// stalePlacementKeys for the next tick and is safely retried.
	w.recordChangedPlacement(changed)
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
		_, _ = w.Step(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.notify:
			case <-ticker.C:
			}
			_, _ = w.Step(ctx)
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
		fingerprint := placementFingerprint(entry, regions)
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
		w.lastPlacement[database] = placementFingerprint(entry, regions)
		entry.Regions = slices.Clone(entry.Regions)
		w.lastPlacementState[database] = entry
	}
}

func (w *KVWriter) stalePlacementKeys(placement map[string]DBPlacement) []string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	var stale []string
	for database := range w.lastPlacement {
		if _, ok := placement[database]; !ok {
			stale = append(stale, database)
		}
	}
	slices.Sort(stale)
	return stale
}

func (w *KVWriter) removeStalePlacement(databases []string) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	for _, database := range databases {
		delete(w.lastPlacement, database)
		delete(w.lastPlacementState, database)
	}
}

func placementFingerprint(entry DBPlacement, regions []string) string {
	return strings.Join(regions, "\n") + "\x00" + entry.PlacementLock + "\x00" + strconv.FormatUint(entry.Generation, 10)
}

// validatePlacement rejects malformed lock metadata and widening before the
// tick writes even one health key. This is the atomic-safety boundary: a bad
// placement can never be partially published after a successful observation.
func (w *KVWriter) validatePlacement(database string, entry DBPlacement) error {
	if entry.PlacementLock == "" && entry.Generation != 0 {
		return errors.New("cloudflare: placement generation requires an immutable lock")
	}
	if entry.PlacementLock != "" {
		if entry.PlacementLock != "eu-only" && entry.PlacementLock != "br-only" && entry.PlacementLock != "explicit" {
			return errors.New("cloudflare: placement lock policy is invalid")
		}
		if entry.Generation == 0 {
			return errors.New("cloudflare: placement lock generation must be positive")
		}
	}
	w.mutex.Lock()
	prior, exists := w.lastPlacementState[database]
	w.mutex.Unlock()
	if !exists {
		return nil
	}
	if prior.PlacementLock != entry.PlacementLock {
		return errors.New("cloudflare: placement lock policy cannot be changed")
	}
	if prior.Generation > 0 && entry.Generation < prior.Generation {
		return errors.New("cloudflare: placement lock generation cannot regress")
	}
	if prior.PlacementLock == "explicit" {
		allowed := map[string]struct{}{}
		for _, region := range prior.Regions {
			allowed[region] = struct{}{}
		}
		for _, region := range entry.Regions {
			if _, ok := allowed[region]; !ok {
				return errors.New("cloudflare: placement lock cannot be widened")
			}
		}
		if !sameStringSet(prior.Regions, entry.Regions) && entry.Generation <= prior.Generation {
			return errors.New("cloudflare: placement lock generation must advance")
		}
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
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
