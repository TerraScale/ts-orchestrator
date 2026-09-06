package cloudflare

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"
)

type kvWriterStoreFake struct {
	events        []string
	health        []WorkerHealthDoc
	placements    []map[string]WorkerPlacement
	deletedDB     []string
	failHealth    error
	failPlacement error
	failDelete    error
}

func (f *kvWriterStoreFake) SetWorkerHealth(_ context.Context, h WorkerHealthDoc) error {
	f.events = append(f.events, "health")
	if f.failHealth != nil {
		return f.failHealth
	}
	f.health = append(f.health, h)
	return nil
}
func (f *kvWriterStoreFake) SetWorkerPlacements(_ context.Context, p map[string]WorkerPlacement) error {
	f.events = append(f.events, "placement")
	if f.failPlacement != nil {
		return f.failPlacement
	}
	f.placements = append(f.placements, p)
	return nil
}
func (f *kvWriterStoreFake) DeleteWorkerPlacements(_ context.Context, names []string) error {
	f.events = append(f.events, "delete")
	if f.failDelete != nil {
		return f.failDelete
	}
	f.deletedDB = append(f.deletedDB, names...)
	return nil
}

type kvWriterSetOnlyFake struct{ delegate *kvWriterStoreFake }

func (f *kvWriterSetOnlyFake) SetWorkerHealth(c context.Context, h WorkerHealthDoc) error {
	return f.delegate.SetWorkerHealth(c, h)
}
func (f *kvWriterSetOnlyFake) SetWorkerPlacements(c context.Context, p map[string]WorkerPlacement) error {
	return f.delegate.SetWorkerPlacements(c, p)
}

type kvWriterHealthFake struct {
	health map[string]RegionHealth
	err    error
}

func (f *kvWriterHealthFake) ObserveRegionHealth(context.Context) (map[string]RegionHealth, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.health, nil
}

type kvWriterPlacementFake struct {
	placement map[string]DBPlacement
	err       error
}

func (f *kvWriterPlacementFake) ObserveDBPlacement(context.Context) (map[string]DBPlacement, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.placement, nil
}

func kvWriterTestConfig(store *kvWriterStoreFake, health map[string]RegionHealth, placement map[string]DBPlacement) KVWriterConfig {
	return KVWriterConfig{
		Store:     store,
		Health:    &kvWriterHealthFake{health: health},
		Placement: &kvWriterPlacementFake{placement: placement},
		Now:       func() time.Time { return time.Unix(1000, 0) },
	}
}

func TestKVWriterDefaultsToTenSecondHealthCadence(t *testing.T) {
	w, err := NewKVWriter(kvWriterTestConfig(&kvWriterStoreFake{},
		map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{}))
	if err != nil {
		t.Fatal(err)
	}
	if w.Interval() != DefaultKVWriterHealthInterval || DefaultKVWriterHealthInterval != 10*time.Second {
		t.Fatalf("interval = %v, want 10s", w.Interval())
	}
}

func TestKVWriterRejectsMissingDependencies(t *testing.T) {
	base := kvWriterTestConfig(&kvWriterStoreFake{},
		map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{})
	for _, mutate := range []func(*KVWriterConfig){
		func(c *KVWriterConfig) { c.Store = nil },
		func(c *KVWriterConfig) { c.Health = nil },
		func(c *KVWriterConfig) { c.Placement = nil },
		func(c *KVWriterConfig) { c.HealthInterval = -time.Second },
		func(c *KVWriterConfig) { c.MaxWritesPerTick = -1 },
	} {
		config := base
		mutate(&config)
		if _, err := NewKVWriter(config); err == nil {
			t.Fatal("invalid config was accepted")
		}
	}
}

func TestKVWriterFailsClosed(t *testing.T) {
	store := &kvWriterStoreFake{}
	w, err := NewKVWriter(kvWriterTestConfig(store,
		map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(nil); err == nil {
		t.Fatal("nil context was accepted")
	}
	if _, err := w.WriteBatch(nil, map[string]RegionHealth{}, map[string]DBPlacement{}); err == nil {
		t.Fatal("nil context was accepted")
	}
	badHealth := &kvWriterHealthFake{health: nil}
	wBad, err := NewKVWriter(KVWriterConfig{Store: store, Health: badHealth,
		Placement: &kvWriterPlacementFake{placement: map[string]DBPlacement{}},
		Now:       func() time.Time { return time.Unix(0, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wBad.Step(context.Background()); err == nil {
		t.Fatal("missing health observation was accepted")
	}
	failing := &kvWriterStoreFake{failHealth: errors.New("kv unavailable")}
	wFail, err := NewKVWriter(kvWriterTestConfig(failing,
		map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wFail.Step(context.Background()); err == nil {
		t.Fatal("store failure was accepted")
	}
	if wFail.LastError() == nil {
		t.Fatal("LastError should retain the tick failure")
	}
}

func TestKVWriterCurrentContractRefreshRemovalAndRetries(t *testing.T) {
	store := &kvWriterStoreFake{}
	health := &kvWriterHealthFake{health: map[string]RegionHealth{"gru": {Healthy: true, Lat: -23, Lon: -46}, "sfo": {Healthy: true, Draining: true}}}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{"app": {Regions: []string{"gru"}, PlacementLock: "explicit", Generation: 1}, "retired": {Regions: []string{"sfo"}}}}
	w, err := NewKVWriter(KVWriterConfig{Store: store, Health: health, Placement: placement, Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if writes, err := w.Step(t.Context()); err != nil || writes != 3 {
		t.Fatalf("initial writes=%d err=%v", writes, err)
	}
	if !reflect.DeepEqual(store.events, []string{"health", "placement"}) {
		t.Fatal(store.events)
	}
	h := store.health[0]
	if h.V != 1 || h.Updated != 1000 || !h.Regions["GRU"].OK || h.Regions["SFO"].OK || h.Regions["GRU"].Lat != -23 {
		t.Fatalf("health %+v", h)
	}
	p := store.placements[0]["app"]
	if p.G != 1 || !reflect.DeepEqual(p.Res.Codes, []string{"GRU"}) {
		t.Fatalf("placement %+v", p)
	}
	if writes, err := w.Step(t.Context()); err != nil || writes != 1 {
		t.Fatalf("refresh writes=%d err=%v", writes, err)
	}
	if len(store.placements) != 1 {
		t.Fatal("unchanged placement rewritten")
	}
	delete(health.health, "sfo")
	delete(placement.placement, "retired")
	store.failDelete = errors.New("interrupted delete")
	if writes, err := w.Step(t.Context()); err == nil || writes != 1 {
		t.Fatalf("failed removal writes=%d err=%v", writes, err)
	}
	if _, exists := store.health[len(store.health)-1].Regions["SFO"]; exists {
		t.Fatal("removed region retained in current health document")
	}
	store.failDelete = nil
	if writes, err := w.Step(t.Context()); err != nil || writes != 2 {
		t.Fatalf("retry writes=%d err=%v", writes, err)
	}
	if !reflect.DeepEqual(store.deletedDB, []string{"retired"}) {
		t.Fatal(store.deletedDB)
	}
	if w.WriteCount() != 7 {
		t.Fatalf("writes %d", w.WriteCount())
	}
}
func TestKVWriterRejectsStalePlacementWithoutDeleteSupport(t *testing.T) {
	delegate := &kvWriterStoreFake{}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{"app": {Regions: []string{"gru"}}}}
	w, err := NewKVWriter(KVWriterConfig{Store: &kvWriterSetOnlyFake{delegate}, Health: &kvWriterHealthFake{health: map[string]RegionHealth{"gru": {}}}, Placement: placement})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	delete(placement.placement, "app")
	before := len(delegate.events)
	if _, err := w.Step(t.Context()); err == nil || len(delegate.events) != before {
		t.Fatal("stale placement not rejected before writes")
	}
}
func TestKVWriterBudgetCountsCurrentDocumentAndPlacementKeys(t *testing.T) {
	store := &kvWriterStoreFake{}
	config := kvWriterTestConfig(store, map[string]RegionHealth{"gru": {}, "sfo": {}}, map[string]DBPlacement{"a": {Regions: []string{"gru"}}, "b": {Regions: []string{"sfo"}}})
	alerts := 0
	config.MaxWritesPerTick = 2
	config.OnBudgetExceeded = func(n int) {
		if n != 3 {
			t.Errorf("budget writes=%d", n)
		}
		alerts++
	}
	w, err := NewKVWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || w.WriteCount() != 3 {
		t.Fatalf("alerts=%d writes=%d", alerts, w.WriteCount())
	}
	if !reflect.DeepEqual(slices.Sorted(maps.Keys(store.placements[0])), []string{"a", "b"}) {
		t.Fatal("budget skipped placement")
	}
}
