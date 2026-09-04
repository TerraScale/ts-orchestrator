package cloudflare

import (
	"context"
	"sync"
	"testing"
	"time"
)

type notifyingKVSource struct {
	mu         sync.Mutex
	placements map[string]DBPlacement
}

func (s *notifyingKVSource) ObserveRegionHealth(context.Context) (map[string]RegionHealth, error) {
	return map[string]RegionHealth{"gru": {Healthy: true}}, nil
}

func (s *notifyingKVSource) ObserveDBPlacement(context.Context) (map[string]DBPlacement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]DBPlacement, len(s.placements))
	for key, value := range s.placements {
		value.Regions = append([]string(nil), value.Regions...)
		result[key] = value
	}
	return result, nil
}

func (s *notifyingKVSource) setPlacement(value DBPlacement) {
	s.mu.Lock()
	s.placements["db"] = value
	s.mu.Unlock()
}

type notifyingKVStore struct {
	mu      sync.Mutex
	writes  int
	changed chan struct{}
}

func (s *notifyingKVStore) SetRegionHealth(context.Context, string, RegionHealth) error {
	s.record()
	return nil
}

func (s *notifyingKVStore) SetDBPlacement(context.Context, string, DBPlacement) error {
	s.record()
	return nil
}

func (s *notifyingKVStore) record() {
	s.mu.Lock()
	s.writes++
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

func (s *notifyingKVStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestKVWriterNotifyChangeRunsBeforePeriodicTick(t *testing.T) {
	source := &notifyingKVSource{placements: map[string]DBPlacement{
		"db": {Regions: []string{"gru"}, PlacementLock: "br-only", Generation: 1},
	}}
	store := &notifyingKVStore{changed: make(chan struct{}, 8)}
	writer, err := NewKVWriter(KVWriterConfig{
		Store: store, Health: source, Placement: source, HealthInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := writer.Close(); err != nil {
			t.Errorf("close writer: %v", err)
		}
	})
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for store.count() < 2 {
		select {
		case <-store.changed:
		case <-deadline.C:
			t.Fatal("initial KV pass did not finish")
		}
	}

	source.setPlacement(DBPlacement{Regions: []string{"gru"}, PlacementLock: "br-only", Generation: 2})
	started := time.Now()
	writer.NotifyChange()
	for store.count() < 4 {
		select {
		case <-store.changed:
		case <-deadline.C:
			t.Fatal("notified KV pass did not finish")
		}
	}
	if elapsed := time.Since(started); elapsed >= time.Minute {
		t.Fatalf("notified pass waited for periodic interval: %s", elapsed)
	}
}
