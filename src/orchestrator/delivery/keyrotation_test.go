package delivery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// fakeCapabilityRotator records the staged operations the cadence driver
// requests. rotateFail and retireFail force the named failure once.
type fakeCapabilityRotator struct {
	rotateCalls   []string
	retireCalls   int
	result        security.RotationResult
	rotateResults map[string]security.RotationResult
	rotateFail    bool
	retireFail    bool
}

func (f *fakeCapabilityRotator) Rotate(_ context.Context, operationID string) (security.RotationResult, error) {
	f.rotateCalls = append(f.rotateCalls, operationID)
	if f.rotateFail {
		return security.RotationResult{}, errors.New("provider echoed secret-material deadbeef")
	}
	if result, ok := f.rotateResults[operationID]; ok {
		return result, nil
	}
	return f.result, nil
}

func (f *fakeCapabilityRotator) RetireExpired(context.Context) (security.RotationResult, error) {
	f.retireCalls++
	if f.retireFail {
		return security.RotationResult{}, errors.New("retire failed")
	}
	return f.result, nil
}

func capabilityTestClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func TestNewCapabilityRotationValidatesConfiguration(t *testing.T) {
	if _, err := NewCapabilityRotation(CapabilityRotationConfig{}); err == nil {
		t.Fatal("expected a missing rotator to be rejected")
	}
	rotator := &fakeCapabilityRotator{}
	if _, err := NewCapabilityRotation(CapabilityRotationConfig{
		Rotator: rotator, Period: time.Hour, Lead: time.Hour,
	}); err == nil {
		t.Fatal("expected a lead equal to the period to be rejected")
	}
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator})
	if err != nil {
		t.Fatalf("expected defaults to be accepted: %v", err)
	}
	if rotation.period != CapabilityRotationPeriod {
		t.Fatalf("expected the default 24h period, got %s", rotation.period)
	}
	if rotation.lead != security.DefaultExpirySafety {
		t.Fatalf("expected the default lead, got %s", rotation.lead)
	}
}

func TestCapabilityRotationOperationIDIsDeterministicPerBucket(t *testing.T) {
	if CapabilityRotationOperationID(1929) != "capability-rotation-1929" {
		t.Fatalf("unexpected operation ID %q", CapabilityRotationOperationID(1929))
	}
	if CapabilityRotationOperationID(7) == CapabilityRotationOperationID(8) {
		t.Fatal("distinct buckets must map to distinct operation IDs")
	}
}

func TestCapabilityRotationBucketAlignsToUTCPeriodBoundaries(t *testing.T) {
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: &fakeCapabilityRotator{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	midnight := time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)
	if rotation.Bucket(midnight) == rotation.Bucket(midnight.Add(-time.Second)) {
		t.Fatal("expected a bucket boundary at UTC midnight")
	}
	if rotation.Bucket(midnight.Add(23*time.Hour)) != rotation.Bucket(midnight) {
		t.Fatal("a 23h offset must stay inside the same 24h bucket")
	}
}

func TestCapabilityRotationTickRotatesOncePerBucket(t *testing.T) {
	at := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	result := security.RotationResult{
		OperationID: "capability-rotation-19290", Phase: security.PhaseActive,
		Generation: 6, NewVersion: 6, CurrentKeyID: "cap-6", PreviousKeyID: "cap-5",
		NewExpiry: at.Add(24 * time.Hour),
	}
	rotator := &fakeCapabilityRotator{result: result}
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Now: capabilityTestClock(at)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	first, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if !first.Rotated || first.Generation != 6 || first.CurrentKeyID != "cap-6" || first.PreviousKeyID != "cap-5" {
		t.Fatalf("unexpected first fact: %+v", first)
	}
	if first.OperationID != CapabilityRotationOperationID(rotation.Bucket(at)) {
		t.Fatalf("operation ID %q does not match bucket %d", first.OperationID, rotation.Bucket(at))
	}
	if first.ExpiresAt != at.Add(24*time.Hour) || first.Phase != security.PhaseActive {
		t.Fatalf("unexpected fact detail: %+v", first)
	}

	second, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if second.Rotated || len(rotator.rotateCalls) != 1 {
		t.Fatalf("a completed bucket must not rotate again: %+v calls=%v", second, rotator.rotateCalls)
	}
	if rotator.retireCalls != 2 {
		t.Fatalf("each tick must retry overlap retirement, got %d calls", rotator.retireCalls)
	}
}

func TestCapabilityRotationTickStartsInLeadWindow(t *testing.T) {
	// A fresh driver is due immediately: the first generation bootstraps the
	// key ring at startup, whenever that falls inside a bucket.
	base := time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)
	rotator := &fakeCapabilityRotator{}
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Lead: time.Hour})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := base.Add(22*time.Hour + 59*time.Minute)
	rotation.now = capabilityTestClock(before)
	fact, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if fact.Bucket != rotation.Bucket(before) {
		t.Fatalf("before the lead window the current bucket %d must rotate, got %d", rotation.Bucket(before), fact.Bucket)
	}
	if rotation.Due(before) {
		t.Fatal("the completed bucket must not be due again before the lead window opens")
	}

	// Once the one-hour lead window opens at 23:00 the driver targets the
	// bucket that begins at the next midnight, so the staged transition
	// overlaps the boundary instead of racing it.
	leadAt := base.Add(23 * time.Hour)
	rotation.now = capabilityTestClock(leadAt)
	if !rotation.Due(leadAt) {
		t.Fatal("rotation must be due inside the lead window")
	}
	fact, err = rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if fact.Bucket != rotation.Bucket(leadAt)+1 {
		t.Fatalf("expected the next bucket %d, got %d", rotation.Bucket(leadAt)+1, fact.Bucket)
	}
	if fact.OperationID != CapabilityRotationOperationID(fact.Bucket) {
		t.Fatalf("unexpected operation ID %q", fact.OperationID)
	}
	if len(rotator.rotateCalls) != 2 {
		t.Fatalf("expected exactly two rotations, got %v", rotator.rotateCalls)
	}
}

func TestCapabilityRotationTickFailsClosedAndRetriesSameOperation(t *testing.T) {
	at := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	rotator := &fakeCapabilityRotator{rotateFail: true}
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Now: capabilityTestClock(at)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := rotation.Tick(context.Background()); err == nil {
		t.Fatal("a rotation failure must fail the tick")
	}
	if !rotation.Due(at) {
		t.Fatal("a failed bucket must stay due for retry")
	}
	rotator.rotateFail = false
	fact, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected retry error: %v", err)
	}
	if !fact.Rotated || len(rotator.rotateCalls) != 2 {
		t.Fatalf("expected a retry of the same operation: %+v calls=%v", fact, rotator.rotateCalls)
	}
	if rotator.rotateCalls[0] != rotator.rotateCalls[1] {
		t.Fatalf("retries must reuse the operation ID: %v", rotator.rotateCalls)
	}
}

func TestCapabilityRotationTickReportsRetireFailureWithoutStoppingCadence(t *testing.T) {
	at := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	rotator := &fakeCapabilityRotator{retireFail: true}
	rotation, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Now: capabilityTestClock(at)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fact, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("a committed rotation must not fail the tick on retirement: %v", err)
	}
	if !fact.Rotated || !fact.RetireFailed {
		t.Fatalf("expected the retire failure to be reported: %+v", fact)
	}
	rotator.retireFail = false
	next, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if next.Rotated || next.RetireFailed || rotator.retireCalls != 2 {
		t.Fatalf("expected a retirement retry without re-rotation: %+v calls=%d", next, rotator.retireCalls)
	}
}

func TestCapabilityRotationRestartReplaysIdempotentOperation(t *testing.T) {
	at := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	rotator := &fakeCapabilityRotator{}
	first, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Now: capabilityTestClock(at)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := first.Tick(context.Background()); err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	// A restarted process forgets the in-memory guard; the same bucket maps
	// to the same operation, which the durable coordinator treats as a no-op.
	restarted, err := NewCapabilityRotation(CapabilityRotationConfig{Rotator: rotator, Now: capabilityTestClock(at.Add(time.Minute))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fact, err := restarted.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	if fact.OperationID != rotator.rotateCalls[0] {
		t.Fatalf("restart must replay the bucket operation: %q vs %q", fact.OperationID, rotator.rotateCalls[0])
	}
}

// fakeDataKeyHooks records the data-key operations the driver requests.
type fakeDataKeyHooks struct {
	kekCalls   []string
	dekCalls   []string
	kekReceipt func(region, idempotencyKey string) (KEKRotationReceipt, error)
	dekReceipt func(databaseID, idempotencyKey string) (DEKRotationReceipt, error)
	keks       []KEKRotationItem
	deks       []DEKRotationItem
	sourceErr  error
}

func (f *fakeDataKeyHooks) RotateKEK(_ context.Context, region, idempotencyKey string) (KEKRotationReceipt, error) {
	f.kekCalls = append(f.kekCalls, region+"|"+idempotencyKey)
	if f.kekReceipt != nil {
		return f.kekReceipt(region, idempotencyKey)
	}
	return KEKRotationReceipt{Region: region, Generation: 9, RewrappedDEKs: 3, At: time.Now().UTC()}, nil
}

func (f *fakeDataKeyHooks) RotateDEK(_ context.Context, databaseID, idempotencyKey string) (DEKRotationReceipt, error) {
	f.dekCalls = append(f.dekCalls, databaseID+"|"+idempotencyKey)
	if f.dekReceipt != nil {
		return f.dekReceipt(databaseID, idempotencyKey)
	}
	return DEKRotationReceipt{DatabaseID: databaseID, Generation: 4, WrappedUnder: "database-kek", At: time.Now().UTC()}, nil
}

func (f *fakeDataKeyHooks) KEKsDue(context.Context) ([]KEKRotationItem, error) {
	return f.keks, f.sourceErr
}

func (f *fakeDataKeyHooks) DEKsDue(context.Context) ([]DEKRotationItem, error) {
	return f.deks, f.sourceErr
}

func TestDataKeyRotationRequiresEveryHook(t *testing.T) {
	hooks := &fakeDataKeyHooks{}
	if _, err := NewDataKeyRotation(DataKeyRotationConfig{}); err == nil {
		t.Fatal("missing seams must be rejected")
	}
	if _, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks}); err == nil {
		t.Fatal("a missing KEK hook must be rejected")
	}
	if _, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks}); err == nil {
		t.Fatal("a missing source must be rejected")
	}
	if _, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks}); err != nil {
		t.Fatalf("expected a complete configuration to be accepted: %v", err)
	}
}

func TestDataKeyRotationTickRotatesKEKsBeforeDEKsInDeterministicOrder(t *testing.T) {
	hooks := &fakeDataKeyHooks{
		keks: []KEKRotationItem{{Region: "fra", Generation: 7}, {Region: "gru", Generation: 7}},
		deks: []DEKRotationItem{{DatabaseID: "db-b", Generation: 3}, {DatabaseID: "db-a", Generation: 3}},
	}
	hooks.kekReceipt = func(region, _ string) (KEKRotationReceipt, error) {
		return KEKRotationReceipt{Region: region, Generation: 8, At: time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)}, nil
	}
	hooks.dekReceipt = func(databaseID, _ string) (DEKRotationReceipt, error) {
		return DEKRotationReceipt{DatabaseID: databaseID, Generation: 4, WrappedUnder: "database-kek", At: time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)}, nil
	}
	rotation, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks, Now: capabilityTestClock(time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	facts, err := rotation.Tick(context.Background())
	if err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}
	wantKEKs := []string{"fra|kek-rotation/fra/8", "gru|kek-rotation/gru/8"}
	wantDEKs := []string{"db-a|dek-rotation/db-a/4", "db-b|dek-rotation/db-b/4"}
	if fmt.Sprint(hooks.kekCalls) != fmt.Sprint(wantKEKs) {
		t.Fatalf("unexpected KEK calls %v", hooks.kekCalls)
	}
	if fmt.Sprint(hooks.dekCalls) != fmt.Sprint(wantDEKs) {
		t.Fatalf("unexpected DEK calls %v", hooks.dekCalls)
	}
	if len(facts) != 4 || facts[0].Kind != "kek" || facts[0].Region != "fra" || facts[2].Kind != "dek" || facts[2].DatabaseID != "db-a" {
		t.Fatalf("KEKs must precede DEKs in sorted order: %+v", facts)
	}
}

func TestDataKeyRotationTickFailsClosedOnFirstHookError(t *testing.T) {
	hooks := &fakeDataKeyHooks{deks: []DEKRotationItem{
		{DatabaseID: "db-a", Generation: 3}, {DatabaseID: "db-b", Generation: 3}, {DatabaseID: "db-c", Generation: 3},
	}}
	hooks.dekReceipt = func(databaseID, _ string) (DEKRotationReceipt, error) {
		if databaseID == "db-b" {
			return DEKRotationReceipt{}, errors.New("vault echoed ciphertext deadbeef")
		}
		return DEKRotationReceipt{DatabaseID: databaseID, Generation: 4, WrappedUnder: "database-kek"}, nil
	}
	rotation, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	facts, err := rotation.Tick(context.Background())
	if err == nil {
		t.Fatal("a hook failure must fail the pass")
	}
	if len(facts) != 1 || facts[0].DatabaseID != "db-a" {
		t.Fatalf("completed facts must be preserved: %+v", facts)
	}
	if len(hooks.dekCalls) != 2 {
		t.Fatalf("the pass must stop at the first failure: %v", hooks.dekCalls)
	}
	if strings.Contains(err.Error(), "deadbeef") || strings.Contains(err.Error(), "ciphertext") {
		t.Fatalf("the error must be redacted: %v", err)
	}
}

func TestDataKeyRotationTickRejectsMismatchedReceipts(t *testing.T) {
	hooks := &fakeDataKeyHooks{deks: []DEKRotationItem{{DatabaseID: "db-a", Generation: 3}}}
	hooks.dekReceipt = func(databaseID, _ string) (DEKRotationReceipt, error) {
		// Wrong database identity and a non-monotonic generation.
		return DEKRotationReceipt{DatabaseID: "db-z", Generation: 3, WrappedUnder: "database-kek"}, nil
	}
	rotation, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := rotation.Tick(context.Background()); err == nil {
		t.Fatal("a mismatched receipt must fail closed")
	} else {
		var typed *DataKeyRotationError
		if !errors.As(err, &typed) || typed.Stage != "verify" || typed.Code != "receipt_mismatch" {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	hooks = &fakeDataKeyHooks{keks: []KEKRotationItem{{Region: "gru", Generation: 7}}}
	hooks.kekReceipt = func(region, _ string) (KEKRotationReceipt, error) {
		return KEKRotationReceipt{Region: region, Generation: 99}, nil
	}
	rotation, err = NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := rotation.Tick(context.Background()); err == nil {
		t.Fatal("a non-monotonic KEK receipt must fail closed")
	}
}

func TestDataKeyRotationTickRejectsInvalidDueItemsAndSourceErrors(t *testing.T) {
	hooks := &fakeDataKeyHooks{deks: []DEKRotationItem{{DatabaseID: " ", Generation: 3}}}
	rotation, err := NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := rotation.Tick(context.Background()); err == nil {
		t.Fatal("an empty database identity must fail closed")
	}

	hooks = &fakeDataKeyHooks{sourceErr: errors.New("placement store exploded deadbeef")}
	rotation, err = NewDataKeyRotation(DataKeyRotationConfig{DEKs: hooks, KEKs: hooks, Source: hooks})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = rotation.Tick(context.Background())
	if err == nil {
		t.Fatal("a source failure must fail the pass")
	}
	if strings.Contains(err.Error(), "exploded") || strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("the source error must be redacted: %v", err)
	}
}

func TestDataKeyRotationErrorIsBoundedAndStable(t *testing.T) {
	typed := &DataKeyRotationError{Kind: "kek", Region: "gru", Stage: "verify", Code: "receipt_mismatch"}
	want := "delivery: data-key rotation failed: kek region=gru stage=verify code=receipt_mismatch"
	if typed.Error() != want {
		t.Fatalf("unexpected error text %q", typed.Error())
	}
	if id := (&DataKeyRotationError{Kind: "dek", DatabaseID: "db-a", Stage: "rotate", Code: "rotation_failed"}).Error(); !strings.Contains(id, "database=db-a") {
		t.Fatalf("the database identity must be reported: %q", id)
	}
}
