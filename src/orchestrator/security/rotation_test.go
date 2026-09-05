package security

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type rotationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *rotationClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *rotationClock) Set(now time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

type rotationStore struct {
	mu     sync.Mutex
	state  PersistedState
	exists bool
	saves  int
}

func (s *rotationStore) Load(context.Context) (PersistedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists {
		return PersistedState{}, ErrNoState
	}
	return cloneState(s.state), nil
}
func (s *rotationStore) Save(_ context.Context, state PersistedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.exists, s.saves = cloneState(state), true, s.saves+1
	return nil
}

func cloneState(in PersistedState) PersistedState {
	out := in
	out.Regions = append([]string(nil), in.Regions...)
	out.Members, out.Distributed, out.Verified, out.Activated, out.Retired = map[string][]string{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for region, members := range in.Members {
		out.Members[region] = append([]string(nil), members...)
	}
	for region, value := range in.Distributed {
		out.Distributed[region] = value
	}
	for region, value := range in.Verified {
		out.Verified[region] = value
	}
	for region, value := range in.Activated {
		out.Activated[region] = value
	}
	for region, value := range in.Retired {
		out.Retired[region] = value
	}
	return out
}

type rotationIssuer struct {
	mu        sync.Mutex
	calls     int
	materials map[string]IdentityMaterial
}

func (i *rotationIssuer) Issue(_ context.Context, r IdentityRequest) (IdentityMaterial, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	ref := "identity-" + string(rune('0'+r.Generation))
	material := IdentityMaterial{Reference: ref, Version: r.Generation, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, WorkloadTLS: []byte("workload-secret"), ControlTLS: []byte("control-secret"), TrustBundle: []byte("trust-secret")}
	if i.materials == nil {
		i.materials = map[string]IdentityMaterial{}
	}
	i.materials[ref] = cloneIdentity(material)
	return material, nil
}
func (i *rotationIssuer) Fetch(_ context.Context, ref string) (IdentityMaterial, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	material, ok := i.materials[ref]
	if !ok {
		return IdentityMaterial{}, errors.New("not found")
	}
	return cloneIdentity(material), nil
}
func (i *rotationIssuer) Retire(context.Context, string, string) error { return nil }
func cloneIdentity(in IdentityMaterial) IdentityMaterial {
	in.WorkloadTLS, in.ControlTLS, in.TrustBundle = append([]byte(nil), in.WorkloadTLS...), append([]byte(nil), in.ControlTLS...), append([]byte(nil), in.TrustBundle...)
	return in
}

type rotationVault struct {
	mu        sync.Mutex
	materials map[string]CapabilityMaterial
}

func (v *rotationVault) Generate(_ context.Context, r CapabilityRequest) (CapabilityMaterial, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ref := "capability-" + string(rune('0'+r.Generation))
	material := CapabilityMaterial{ID: ref, Reference: ref, Version: r.Generation, Bucket: r.Bucket, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Key: []byte("hmac-secret")}
	if v.materials == nil {
		v.materials = map[string]CapabilityMaterial{}
	}
	material.Key = append([]byte(nil), material.Key...)
	v.materials[ref] = material
	return material, nil
}
func (v *rotationVault) Fetch(_ context.Context, ref string) (CapabilityMaterial, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	material, ok := v.materials[ref]
	if !ok {
		return CapabilityMaterial{}, errors.New("not found")
	}
	material.Key = append([]byte(nil), material.Key...)
	return material, nil
}
func (v *rotationVault) Retire(context.Context, string, string) error { return nil }

type rotationConsumers struct {
	mu             sync.Mutex
	failRegion     string
	failActivation bool
	versions       map[string]uint64
	fenced         map[string]bool
	rollback       int
}

func (f *rotationConsumers) Members(context.Context, string) ([]string, error) {
	return []string{"member-a", "member-b"}, nil
}
func (f *rotationConsumers) Distribute(_ context.Context, member string, _ CredentialSet, _ string) error {
	if member == "member-b" && f.failRegion == "distribution" {
		return errors.New("provider leaked secret")
	}
	return nil
}
func (f *rotationConsumers) Verify(_ context.Context, _ string, generation uint64) (ConsumerObservation, error) {
	return ConsumerObservation{Generation: generation, ValidUntil: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}
func (f *rotationConsumers) Activate(_ context.Context, member string, generation uint64, _ string) error {
	if f.failActivation && member == "member-b" {
		return errors.New("activation provider detail")
	}
	f.mu.Lock()
	if f.versions == nil {
		f.versions = map[string]uint64{}
	}
	f.versions[member] = generation
	f.mu.Unlock()
	return nil
}
func (f *rotationConsumers) Retire(context.Context, string, uint64, string) error { return nil }
func (f *rotationConsumers) Rollback(context.Context, string, uint64, string) error {
	f.mu.Lock()
	f.rollback++
	f.mu.Unlock()
	return nil
}
func (f *rotationConsumers) Fence(_ context.Context, region, _ string) error {
	f.mu.Lock()
	if f.fenced == nil {
		f.fenced = map[string]bool{}
	}
	f.fenced[region] = true
	f.mu.Unlock()
	return nil
}

type rotationEdge struct{ rotationConsumers }

func (f *rotationEdge) Distribute(context.Context, CredentialSet, string) error { return nil }
func (f *rotationEdge) Verify(_ context.Context, generation uint64) (ConsumerObservation, error) {
	return ConsumerObservation{Generation: generation, ValidUntil: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}
func (f *rotationEdge) Activate(context.Context, uint64, string) error { return nil }
func (f *rotationEdge) Retire(context.Context, uint64, string) error   { return nil }
func (f *rotationEdge) Rollback(context.Context, uint64, string) error { return nil }
func (f *rotationEdge) Fence(context.Context, string) error            { return nil }

type rotationReload struct{}

func (rotationReload) Reload(context.Context, string, CredentialSet, string) error { return nil }
func (rotationReload) Verify(_ context.Context, _ string, generation uint64) (ConsumerObservation, error) {
	return ConsumerObservation{Generation: generation, ValidUntil: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}
func (rotationReload) Rollback(context.Context, string, uint64, string) error { return nil }
func (rotationReload) Fence(context.Context, string, string) error            { return nil }

func testCoordinator(t *testing.T, consumers *rotationConsumers, clock *rotationClock, store *rotationStore) *Coordinator {
	t.Helper()
	issuer, vault, edge := &rotationIssuer{}, &rotationVault{}, &rotationEdge{}
	coordinator, err := NewCoordinator(Config{Issuer: issuer, Vault: vault, Members: consumers, Secrets: edge, Reloader: rotationReload{}, State: store, Regions: []string{"gru", "sfo", "fra"}, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func TestRotationStagesAndIsIdempotent(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{}
	coordinator := testCoordinator(t, consumers, clock, store)
	got, err := coordinator.Rotate(context.Background(), "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != PhaseActive || got.NewVersion != 1 || got.OldVersion != 0 {
		t.Fatalf("unexpected result: %+v", got)
	}
	again, err := coordinator.Rotate(context.Background(), "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.NewVersion != got.NewVersion || store.saves == 0 {
		t.Fatalf("idempotency failed: %+v", again)
	}
}

func TestRotationResumesDurableStateAndVersionsRemainMonotonic(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{}
	first := testCoordinator(t, consumers, clock, store)
	if _, err := first.Rotate(context.Background(), "op-1"); err != nil {
		t.Fatal(err)
	}
	clock.Set(clock.Now().Add(24*time.Hour - time.Nanosecond))
	second, err := NewCoordinator(Config{Issuer: first.issuer, Vault: first.vault, Members: consumers, Secrets: first.secrets, Reloader: first.reloader, State: store, Regions: first.regions, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Rotate(context.Background(), "op-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.NewVersion != 2 || got.OldVersion != 1 {
		t.Fatalf("versions did not advance: %+v", got)
	}
	if result, err := second.RetireExpired(context.Background()); err != nil || result.OldVersion != 1 {
		t.Fatalf("old bucket should overlap until expiry: %+v %v", result, err)
	}
}

func TestRotationFailureRollsBackAndRedactsProviderDetails(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{failActivation: true}
	coordinator := testCoordinator(t, consumers, clock, store)
	_, err := coordinator.Rotate(context.Background(), "op-secret")
	if err == nil || !strings.Contains(err.Error(), "activation_failed") || strings.Contains(err.Error(), "activation provider detail") || strings.Contains(err.Error(), "hmac-secret") {
		t.Fatalf("error was not safely redacted: %v", err)
	}
	if store.state.Phase != PhaseFailed || consumers.rollback == 0 {
		t.Fatalf("failure was not durable/rolled back: %+v rollback=%d", store.state, consumers.rollback)
	}
}

func TestRotationRetiresOnlyAtExpiry(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{}
	coordinator := testCoordinator(t, consumers, clock, store)
	if _, err := coordinator.Rotate(context.Background(), "op-1"); err != nil {
		t.Fatal(err)
	}
	clock.Set(store.state.NewExpiry.Add(-DefaultExpirySafety))
	result, err := coordinator.RetireExpired(context.Background())
	if err != nil || result.OldVersion != 0 {
		t.Fatalf("first rotation has no old bucket: %+v %v", result, err)
	}
	if store.state.NewExpiry.Sub(clock.Now()) != DefaultExpirySafety {
		t.Fatal("test clock did not reach the safety boundary")
	}
}

func TestRotationRejectsExpiredDurableCandidate(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{}
	coordinator := testCoordinator(t, consumers, clock, store)
	if _, err := coordinator.Rotate(context.Background(), "op-1"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.state.Phase, store.state.OperationID = PhasePrepare, "op-expired"
	store.state.Generation, store.state.NewVersion = 1, 1
	store.state.NewIdentityRef, store.state.NewCapabilityRef = store.state.CurrentIdentityRef, store.state.CurrentCapabilityRef
	store.state.NewNotBefore, store.state.NewExpiry = clock.Now().Add(-2*time.Hour), clock.Now().Add(-time.Minute)
	store.mu.Unlock()
	if _, err := coordinator.Resume(context.Background()); err == nil || !strings.Contains(err.Error(), "generation_expired") {
		t.Fatalf("expired durable candidate was not refused: %v", err)
	}
}

func TestRotationConcurrentCallsSerialize(t *testing.T) {
	clock := &rotationClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	store, consumers := &rotationStore{}, &rotationConsumers{}
	coordinator := testCoordinator(t, consumers, clock, store)
	var wg sync.WaitGroup
	results := make(chan RotationResult, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := coordinator.Rotate(context.Background(), "same-op")
			results <- result
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for result := range results {
		if result.NewVersion != 1 || result.Phase != PhaseActive {
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
	}
}
