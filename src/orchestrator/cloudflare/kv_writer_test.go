package cloudflare

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type kvWriterStoreFake struct {
	healthOrder   []string
	placementKeys []string
	failHealth    error
	failPlacement error
}

func (f *kvWriterStoreFake) SetRegionHealth(_ context.Context, region string, _ RegionHealth) error {
	if f.failHealth != nil {
		return f.failHealth
	}
	f.healthOrder = append(f.healthOrder, region)
	return nil
}

func (f *kvWriterStoreFake) SetDBPlacement(_ context.Context, database string, _ DBPlacement) error {
	if f.failPlacement != nil {
		return f.failPlacement
	}
	f.placementKeys = append(f.placementKeys, database)
	return nil
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

func TestKVWriterHealthEveryTickPlacementOnlyOnChange(t *testing.T) {
	store := &kvWriterStoreFake{}
	w, err := NewKVWriter(kvWriterTestConfig(store,
		map[string]RegionHealth{"gru": {Healthy: true}, "sfo": {Healthy: true}},
		map[string]DBPlacement{"db-1": {Regions: []string{"gru"}}}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := w.Step(ctx)
	if err != nil || first != 3 {
		t.Fatalf("first tick writes=%d err=%v, want 3", first, err)
	}
	second, err := w.Step(ctx)
	if err != nil || second != 2 {
		t.Fatalf("second tick writes=%d err=%v, want health-only 2", second, err)
	}
	if got := len(store.placementKeys); got != 1 {
		t.Fatalf("placement writes=%d, want 1 (change only)", got)
	}
	if got := len(store.healthOrder); got != 4 {
		t.Fatalf("health writes=%d, want 4 (every tick)", got)
	}
}

func TestKVWriterWritesHealthBeforePlacement(t *testing.T) {
	store := &kvWriterStoreFake{}
	w, err := NewKVWriter(kvWriterTestConfig(store,
		map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{"db-1": {}}))
	if err != nil {
		t.Fatal(err)
	}
	// WriteBatch with one health and one placement entry must keep the D-58
	// health-before-placement order even though maps iterate randomly.
	for range 10 {
		store.healthOrder, store.placementKeys = nil, nil
		if _, err := w.WriteBatch(context.Background(),
			map[string]RegionHealth{"gru": {}}, map[string]DBPlacement{"db-1": {}}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(store.healthOrder, []string{"gru"}) || !reflect.DeepEqual(store.placementKeys, []string{"db-1"}) {
			t.Fatalf("batch order health=%v placement=%v", store.healthOrder, store.placementKeys)
		}
	}
}

func TestKVWriterBudgetAlertFiresWithoutSkippingWrites(t *testing.T) {
	store := &kvWriterStoreFake{}
	alerts := 0
	config := kvWriterTestConfig(store,
		map[string]RegionHealth{"gru": {}, "sfo": {}},
		map[string]DBPlacement{"db-1": {Regions: []string{"gru"}}})
	config.MaxWritesPerTick = 2
	config.OnBudgetExceeded = func(tickWrites int) {
		if tickWrites != 3 {
			t.Errorf("alert tickWrites=%d, want 3", tickWrites)
		}
		alerts++
	}
	w, err := NewKVWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("alerts=%d, want 1", alerts)
	}
	if got := w.WriteCount(); got != 3 {
		t.Fatalf("writes=%d, want 3 (budget alerts, never skips)", got)
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
