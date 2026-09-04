package vmqual

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupAndObserveProviderStateUsesPopulatedFreshObservations(t *testing.T) {
	t.Parallel()
	stateRoot := filepath.Join(t.TempDir(), "state")
	endpoints, driver, err := NewLocalScenarioDriverFromConfig(LocalProviderConfig{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoints.Close()
	stack := &Stack{config: StackConfig{StateRoot: stateRoot}, guests: LaunchGuests(DefaultMemoryMiB)}
	if err := driver.AttachStack(stack); err != nil {
		t.Fatal(err)
	}
	controlRoot := filepath.Join(stateRoot, "control-contract")
	if err := os.MkdirAll(controlRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(controlRoot, "transition.json"), []byte(`{"epoch":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stateRoot, "unrelated-owner")
	if err := os.WriteFile(unrelated, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observation, err := driver.CleanupAndObserveProviderState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(observation.Paths) != 4 || len(observation.Listeners) != 6 {
		t.Fatalf("cleanup observation = %+v", observation)
	}
	for _, path := range observation.Paths {
		if path.Present {
			t.Fatalf("owned provider path remains: %+v", path)
		}
		if _, err := os.Lstat(path.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fresh path observation differs for %s: %v", path.Path, err)
		}
	}
	for _, listener := range observation.Listeners {
		if listener.Reachable {
			t.Fatalf("owned provider listener remains: %+v", listener)
		}
	}
	if payload, err := os.ReadFile(unrelated); err != nil || string(payload) != "preserve" {
		t.Fatalf("unrelated state changed: %q, %v", payload, err)
	}
}

func TestProviderCleanupObservationRejectsEmptyOrClaimedSuccess(t *testing.T) {
	t.Parallel()
	if err := (ProviderCleanupObservation{}).Validate(); err == nil {
		t.Fatal("empty cleanup observation passed")
	}
	now := time.Now().UTC()
	observation := ProviderCleanupObservation{CapturedAt: now}
	for index := 0; index < 4; index++ {
		observation.Paths = append(observation.Paths, ProviderCleanupPathObservation{Kind: "owned", Path: filepath.Join("/owned", string(rune('a'+index)))})
	}
	for index := 0; index < 6; index++ {
		observation.Listeners = append(observation.Listeners, ProviderCleanupListenerObservation{Kind: "owned", Address: "127.0.0.1:" + string(rune('1'+index))})
	}
	observation.Paths[0].Present = true
	if err := observation.Validate(); err == nil {
		t.Fatal("present provider path passed cleanup validation")
	}
	observation.Paths[0].Present = false
	observation.Listeners[0].Reachable = true
	if err := observation.Validate(); err == nil {
		t.Fatal("reachable provider listener passed cleanup validation")
	}
}

func TestCleanupAndObserveProviderStateHonorsCancellation(t *testing.T) {
	t.Parallel()
	stateRoot := filepath.Join(t.TempDir(), "state")
	endpoints, driver, err := NewLocalScenarioDriverFromConfig(LocalProviderConfig{StateRoot: stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	defer endpoints.Close()
	stack := &Stack{config: StackConfig{StateRoot: stateRoot}, guests: LaunchGuests(DefaultMemoryMiB)}
	if err := driver.AttachStack(stack); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.CleanupAndObserveProviderState(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error = %v, want cancellation", err)
	}
}
