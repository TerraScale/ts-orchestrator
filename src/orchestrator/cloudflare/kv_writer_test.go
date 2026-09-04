package cloudflare

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type kvWriterStoreFake struct {
	events              []string
	healthOrder         []string
	placementKeys       []string
	deletedHealth       []string
	deletedDB           []string
	failHealth          error
	failPlacement       error
	failDeleteHealthFor string
	failDeleteDBFor     string
	failDelete          error
}

func (f *kvWriterStoreFake) SetRegionHealth(_ context.Context, region string, _ RegionHealth) error {
	f.events = append(f.events, "set-health:"+region)
	if f.failHealth != nil {
		return f.failHealth
	}
	f.healthOrder = append(f.healthOrder, region)
	return nil
}

func (f *kvWriterStoreFake) SetDBPlacement(_ context.Context, database string, _ DBPlacement) error {
	f.events = append(f.events, "set-placement:"+database)
	if f.failPlacement != nil {
		return f.failPlacement
	}
	f.placementKeys = append(f.placementKeys, database)
	return nil
}

func (f *kvWriterStoreFake) DeleteRegionHealth(_ context.Context, region string) error {
	f.events = append(f.events, "delete-health:"+region)
	if region == f.failDeleteHealthFor {
		return f.failDelete
	}
	f.deletedHealth = append(f.deletedHealth, region)
	return nil
}

func (f *kvWriterStoreFake) DeleteDBPlacement(_ context.Context, database string) error {
	f.events = append(f.events, "delete-placement:"+database)
	if database == f.failDeleteDBFor {
		return f.failDelete
	}
	f.deletedDB = append(f.deletedDB, database)
	return nil
}

// kvWriterSetOnlyFake intentionally omits KVWriterDeleteStore. It exercises
// the fail-closed path when an observation removes an entry.
type kvWriterSetOnlyFake struct{ delegate *kvWriterStoreFake }

func (f *kvWriterSetOnlyFake) SetRegionHealth(ctx context.Context, region string, h RegionHealth) error {
	return f.delegate.SetRegionHealth(ctx, region, h)
}

func (f *kvWriterSetOnlyFake) SetDBPlacement(ctx context.Context, database string, p DBPlacement) error {
	return f.delegate.SetDBPlacement(ctx, database, p)
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

func TestKVWriterDeletesRemovedEntriesAfterPlacementWrites(t *testing.T) {
	store := &kvWriterStoreFake{}
	health := &kvWriterHealthFake{health: map[string]RegionHealth{
		"gru": {},
		"sfo": {},
	}}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{
		"db-1": {Regions: []string{"sfo"}},
		"db-2": {Regions: []string{"gru"}},
	}}
	w, err := NewKVWriter(KVWriterConfig{
		Store: store, Health: health, Placement: placement,
		Now: func() time.Time { return time.Unix(1000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes, err := w.Step(context.Background()); err != nil || writes != 4 {
		t.Fatalf("initial step writes=%d err=%v, want 4", writes, err)
	}

	store.events = nil
	health.health = map[string]RegionHealth{"gru": {Healthy: true}}
	placement.placement = map[string]DBPlacement{
		"db-1": {Regions: []string{"gru"}},
	}
	writes, err := w.Step(context.Background())
	if err != nil || writes != 4 {
		t.Fatalf("removal step writes=%d err=%v, want 4", writes, err)
	}
	want := []string{
		"set-health:gru",
		"set-placement:db-1",
		"delete-health:sfo",
		"delete-placement:db-2",
	}
	if !reflect.DeepEqual(store.events, want) {
		t.Fatalf("operation order = %v, want %v", store.events, want)
	}
	if !reflect.DeepEqual(store.deletedHealth, []string{"sfo"}) || !reflect.DeepEqual(store.deletedDB, []string{"db-2"}) {
		t.Fatalf("deletes health=%v db=%v", store.deletedHealth, store.deletedDB)
	}
}

func TestKVWriterRejectsStaleEntriesWithoutDeleteSupport(t *testing.T) {
	delegate := &kvWriterStoreFake{}
	health := &kvWriterHealthFake{health: map[string]RegionHealth{"gru": {}}}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{"db-1": {Regions: []string{"gru"}}}}
	w, err := NewKVWriter(KVWriterConfig{
		Store: &kvWriterSetOnlyFake{delegate: delegate}, Health: health, Placement: placement,
		Now: func() time.Time { return time.Unix(1000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatalf("initial step: %v", err)
	}
	health.health = map[string]RegionHealth{}
	placement.placement = map[string]DBPlacement{}
	before := len(delegate.events)
	if writes, err := w.Step(context.Background()); err == nil || writes != 0 {
		t.Fatalf("stale step writes=%d err=%v, want zero writes and an error", writes, err)
	}
	if got := len(delegate.events); got != before {
		t.Fatalf("unsupported delete store performed %d operations", got-before)
	}
	if w.LastError() == nil {
		t.Fatal("LastError should retain unsupported delete error")
	}
}

func TestKVWriterRetriesAllStaleEntriesAfterPartialDeleteFailure(t *testing.T) {
	store := &kvWriterStoreFake{}
	health := &kvWriterHealthFake{health: map[string]RegionHealth{
		"gru": {}, "sfo": {},
	}}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{
		"db-1": {Regions: []string{"gru"}}, "db-2": {Regions: []string{"sfo"}},
	}}
	w, err := NewKVWriter(KVWriterConfig{
		Store: store, Health: health, Placement: placement,
		Now: func() time.Time { return time.Unix(1000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	health.health = map[string]RegionHealth{"gru": {}}
	placement.placement = map[string]DBPlacement{"db-1": {Regions: []string{"gru"}}}
	store.failDeleteDBFor = "db-2"
	store.failDelete = errors.New("delete unavailable")
	store.events = nil
	writes, err := w.Step(context.Background())
	if err == nil || writes != 2 {
		t.Fatalf("partial-delete step writes=%d err=%v, want 2 and an error", writes, err)
	}
	if got := w.WriteCount(); got != 6 {
		t.Fatalf("write count after partial delete=%d, want 6", got)
	}
	wantFirst := []string{"set-health:gru", "delete-health:sfo", "delete-placement:db-2"}
	if !reflect.DeepEqual(store.events, wantFirst) {
		t.Fatalf("partial-delete order=%v, want %v", store.events, wantFirst)
	}

	store.failDeleteDBFor = ""
	store.events = nil
	writes, err = w.Step(context.Background())
	if err != nil || writes != 3 {
		t.Fatalf("retry step writes=%d err=%v, want 3", writes, err)
	}
	wantRetry := []string{"set-health:gru", "delete-health:sfo", "delete-placement:db-2"}
	if !reflect.DeepEqual(store.events, wantRetry) {
		t.Fatalf("retry order=%v, want %v", store.events, wantRetry)
	}
	if got := w.WriteCount(); got != 9 {
		t.Fatalf("write count after retry=%d, want 9", got)
	}
	if w.LastError() != nil {
		t.Fatalf("LastError after retry=%v, want nil", w.LastError())
	}
}

func TestKVWriterBudgetCountsSetsAndDeletesOncePerTick(t *testing.T) {
	store := &kvWriterStoreFake{}
	health := &kvWriterHealthFake{health: map[string]RegionHealth{"gru": {}, "sfo": {}}}
	placement := &kvWriterPlacementFake{placement: map[string]DBPlacement{
		"db-1": {Regions: []string{"gru"}}, "db-2": {Regions: []string{"sfo"}},
	}}
	var alerts []int
	config := KVWriterConfig{
		Store: store, Health: health, Placement: placement,
		MaxWritesPerTick: 2,
		OnBudgetExceeded: func(writes int) { alerts = append(alerts, writes) },
		Now:              func() time.Time { return time.Unix(1000, 0) },
	}
	w, err := NewKVWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	health.health = map[string]RegionHealth{"gru": {}}
	placement.placement = map[string]DBPlacement{"db-1": {Regions: []string{"gru"}}}
	if _, err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(alerts, []int{4, 3}) {
		t.Fatalf("budget alerts=%v, want one alert per tick with all operations", alerts)
	}
	if got := w.WriteCount(); got != 7 {
		t.Fatalf("write count=%d, want 7", got)
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
