package globalview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	json "encoding/json/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Bucket holds each region's last-known rollup, key = cell.
const Bucket = "TS_DASHBOARD_ROLLUPS"

const maxRegions = 32 // the registry's region limit

// Region is one region of the view. Rollup is nil until one arrives.
type Region struct {
	Cell   string  `json:"cell"`
	Rollup *Rollup `json:"rollup"`
	Stale  bool    `json:"stale"`
}

// View holds the newest rollup of every listed region, in memory.
type View struct {
	mu          sync.Mutex
	local       string
	regions     func() []string
	now         func() time.Time
	rollups     map[string]*Rollup
	persisted   map[string]time.Time // ObservedAt last written to the bucket
	persistedAt map[string]time.Time // wall time of that write
	changed     chan struct{}
}

// NewView follows every region regions() lists; local is always listed.
// now defaults to time.Now.
func NewView(local string, regions func() []string, now func() time.Time) *View {
	if now == nil {
		now = time.Now
	}
	return &View{
		local:       normalize(local),
		regions:     regions,
		now:         now,
		rollups:     map[string]*Rollup{},
		persisted:   map[string]time.Time{},
		persistedAt: map[string]time.Time{},
		changed:     make(chan struct{}),
	}
}

// Regions lists local first, then every other listed region by cell.
func (v *View) Regions() []Region {
	v.mu.Lock()
	defer v.mu.Unlock()
	cells := v.listed()
	out := make([]Region, 0, len(cells))
	for _, cell := range cells {
		out = append(out, v.region(cell))
	}
	return out
}

// Region returns one listed region; false when cell is not listed.
func (v *View) Region(cell string) (Region, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cell = normalize(cell)
	if !slices.Contains(v.listed(), cell) {
		return Region{}, false
	}
	return v.region(cell), true
}

// Changed returns a channel closed on the next accepted rollup.
func (v *View) Changed() <-chan struct{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.changed
}

// Accept keeps r when it is newer than the held rollup of its cell.
func (v *View) Accept(r Rollup) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if validate(r, v.now()) != nil {
		return false
	}
	held := v.rollups[r.Cell]
	if held != nil && !r.ObservedAt.After(held.ObservedAt) {
		return false
	}
	if held == nil && len(v.rollups) >= maxRegions {
		v.prune()
		if len(v.rollups) >= maxRegions {
			return false
		}
	}
	v.rollups[r.Cell] = &r
	close(v.changed)
	v.changed = make(chan struct{})
	return true
}

// Follow accepts every valid rollup on protocol.RegionRollupGrant until ctx
// ends. It needs no bucket, so live rollups flow while JetStream is down.
func (v *View) Follow(ctx context.Context, conn *nats.Conn) error {
	sub, err := conn.Subscribe(protocol.RegionRollupGrant, func(msg *nats.Msg) {
		r, err := decode(msg.Subject, msg.Data)
		if err != nil {
			slog.Debug("dashboard rollup dropped", observability.ComponentKey, "globalview", "error", err)
			return
		}
		v.Accept(r)
	})
	if err != nil {
		return fmt.Errorf("subscribe region rollups: %w", err)
	}
	<-ctx.Done()
	if err := sub.Unsubscribe(); err != nil {
		slog.Debug("dashboard rollup subscription not closed", observability.ComponentKey, "globalview", "error", err)
	}
	return nil
}

// KeepLastKnown loads the last-known bucket into the view, then persists the
// view every PersistEvery while leading() is true, until ctx ends. Each write
// is bounded by PersistEvery, so a stalled bucket never blocks publishing.
func (v *View) KeepLastKnown(ctx context.Context, kv jetstream.KeyValue, leading func() bool) {
	if err := v.load(ctx, kv); err != nil {
		slog.Warn("dashboard last-known rollups not loaded", observability.ComponentKey, "globalview", "error", err)
	}
	ticker := time.NewTicker(PersistEvery)
	defer ticker.Stop()
	for {
		if leading() {
			persistCtx, cancel := context.WithTimeout(ctx, PersistEvery)
			if err := v.Persist(persistCtx, kv); err != nil {
				slog.Warn("dashboard rollups not persisted", observability.ComponentKey, "globalview", "error", err)
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Persist writes each listed region's rollup to kv when it advanced and its
// last write is at least PersistEvery old, and deletes keys of regions no
// longer listed. Only the region's leader calls it.
func (v *View) Persist(ctx context.Context, kv jetstream.KeyValue) error {
	type write struct {
		cell   string
		rollup *Rollup
	}
	v.mu.Lock()
	cells := v.listed()
	var writes []write
	for _, cell := range cells {
		r := v.rollups[cell]
		if r == nil || !r.ObservedAt.After(v.persisted[cell]) || v.now().Sub(v.persistedAt[cell]) < PersistEvery {
			continue
		}
		writes = append(writes, write{cell, r})
	}
	v.mu.Unlock()

	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, w := range writes {
		data, err := json.Marshal(w.rollup)
		if err != nil {
			keep(fmt.Errorf("encode rollup %s: %w", w.cell, err))
			continue
		}
		if _, err := kv.Put(ctx, w.cell, data); err != nil {
			keep(fmt.Errorf("persist rollup %s: %w", w.cell, err))
			continue
		}
		v.markPersisted(w.cell, w.rollup.ObservedAt)
	}

	// Until the registry lists another region, an unlisted key may only
	// mean the roster is not read yet; deleting it would lose last-known data.
	if len(cells) < 2 {
		return firstErr
	}
	keys, err := kv.Keys(ctx)
	if err != nil && !errors.Is(err, jetstream.ErrNoKeysFound) {
		keep(fmt.Errorf("list rollup keys: %w", err))
		return firstErr
	}
	for _, key := range keys {
		if slices.Contains(cells, key) {
			continue
		}
		if err := kv.Delete(ctx, key); err != nil {
			keep(fmt.Errorf("delete rollup %s: %w", key, err))
		}
	}
	return firstErr
}

// OpenBucket opens the regional last-known bucket.
func OpenBucket(ctx context.Context, js jetstream.JetStream, replicas int) (jetstream.KeyValue, error) {
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       Bucket,
		Description:  "TS-805 last-known dashboard rollup per region",
		History:      1,
		Replicas:     max(replicas, 1),
		Storage:      jetstream.FileStorage,
		MaxValueSize: MaxBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s bucket: %w", Bucket, err)
	}
	return kv, nil
}

// listed is local first, then every other listed region sorted. Callers hold mu.
func (v *View) listed() []string {
	var others []string
	if v.regions != nil {
		for _, raw := range v.regions() {
			cell := normalize(raw)
			if cell == "" || cell == v.local || slices.Contains(others, cell) {
				continue
			}
			others = append(others, cell)
		}
	}
	slices.Sort(others)
	if v.local == "" {
		return others
	}
	return append([]string{v.local}, others...)
}

// region reads one listed cell. Callers hold mu.
func (v *View) region(cell string) Region {
	r := v.rollups[cell]
	return Region{
		Cell:   cell,
		Rollup: r,
		Stale:  r != nil && v.now().Sub(r.ObservedAt) > StaleAfter,
	}
}

// prune drops held cells that are no longer listed. Callers hold mu.
func (v *View) prune() {
	listed := v.listed()
	for cell := range v.rollups {
		if slices.Contains(listed, cell) {
			continue
		}
		delete(v.rollups, cell)
		delete(v.persisted, cell)
		delete(v.persistedAt, cell)
	}
}

func (v *View) markPersisted(cell string, observed time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.persisted[cell] = observed
	v.persistedAt[cell] = v.now()
}

func (v *View) load(ctx context.Context, kv jetstream.KeyValue) error {
	keys, err := kv.Keys(ctx)
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list rollup keys: %w", err)
	}
	for _, key := range keys {
		entry, err := kv.Get(ctx, key)
		if err != nil {
			slog.Warn("dashboard rollup not loaded", observability.ComponentKey, "globalview", "cell", key, "error", err)
			continue
		}
		r, err := decode(protocol.RegionRollupSubject(key), entry.Value())
		if err != nil {
			slog.Debug("dashboard rollup dropped", observability.ComponentKey, "globalview", "cell", key, "error", err)
			continue
		}
		v.Accept(r)
	}
	return nil
}

// decode reads one rollup from subject. DecodeTolerant lets a newer region's
// extra fields through during a rolling upgrade.
func decode(subject string, data []byte) (Rollup, error) {
	var r Rollup
	if err := protocol.DecodeTolerant(data, &r, MaxBytes); err != nil {
		return Rollup{}, err
	}
	if err := validate(r, time.Now()); err != nil {
		return Rollup{}, err
	}
	if tokens := strings.Split(subject, "."); len(tokens) < 4 || tokens[3] != r.Cell {
		return Rollup{}, fmt.Errorf("rollup subject %q does not name cell %q", subject, r.Cell)
	}
	// A scaling status the region cannot validate, or that speaks for another
	// region, is no status: its spend is then unknown and growth holds.
	if r.Scale != nil && (r.Scale.Validate() != nil || r.Scale.Cell != r.Cell) {
		r.Scale = nil
	}
	return r, nil
}

// validate checks what a rollup must hold whatever its subject.
func validate(r Rollup, now time.Time) error {
	if r.Version != Version {
		return fmt.Errorf("rollup version %d, want %d", r.Version, Version)
	}
	if token, err := protocol.RegionToken(r.Cell); err != nil || token != r.Cell {
		return fmt.Errorf("rollup cell %q is not a region token", r.Cell)
	}
	if r.ObservedAt.IsZero() || r.ObservedAt.After(now.Add(time.Minute)) {
		return fmt.Errorf("rollup observed_at %s is outside the clock window", r.ObservedAt)
	}
	return nil
}

// normalize returns the region token of cell, or "" when cell is not one.
func normalize(cell string) string {
	token, err := protocol.RegionToken(cell)
	if err != nil {
		return ""
	}
	return token
}
