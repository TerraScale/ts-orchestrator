package restoredrill

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

type verifiedSnapshotFixture struct {
	mu       sync.Mutex
	mirrors  []string
	verified []string
}

func (f *verifiedSnapshotFixture) Snapshot(_ context.Context, request SnapshotRequest) (ControlStateSnapshot, error) {
	return ControlStateSnapshot{ID: "js-1", ObjectKey: request.ObjectKey, Checksum: "abc", Size: 3, ControlEpoch: request.ControlEpoch}, nil
}

func (f *verifiedSnapshotFixture) Mirror(_ context.Context, _ ControlStateSnapshot, region string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mirrors = append(f.mirrors, region)
	return nil
}

func (f *verifiedSnapshotFixture) VerifyMirror(_ context.Context, _ ControlStateSnapshot, region string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified = append(f.verified, region)
	return nil
}

func (f *verifiedSnapshotFixture) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mirrors), len(f.verified)
}

type productionObjectStore struct {
	mu      sync.Mutex
	objects map[string]delivery.ObjectIdentity
}

func (s *productionObjectStore) Put(_ context.Context, region, bucket, object string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[region+"/"+bucket+"/"+object] = delivery.ObjectIdentity{Digest: delivery.SHA256Digest(body), Size: int64(len(body)), ETag: "etag"}
	return nil
}

func (s *productionObjectStore) Head(_ context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.objects[region+"/"+bucket+"/"+object]
	return identity, ok, nil
}

func productionArtifact(t *testing.T, body []byte) *delivery.ReleaseArtifact {
	t.Helper()
	digest := sha256.Sum256(body)
	return &delivery.ReleaseArtifact{Service: "terrabase", Digest: "sha256:" + hex.EncodeToString(digest[:]), Body: body}
}

func TestProductionCompositionRejectsUnverifiableBoundaries(t *testing.T) {
	fixture := &verifiedSnapshotFixture{}
	if _, err := NewProductionSnapshotMirrorAdapter(SnapshotMirrorFunc(fixture.Mirror)); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("plain snapshot mirror error = %v, want verification refusal", err)
	}
	store := &productionObjectStore{objects: map[string]delivery.ObjectIdentity{}}
	mirror, err := delivery.NewArtifactMirror(estate.Default(), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProductionArtifactMirrorAdapter(mirror); err != nil {
		t.Fatalf("provider-backed artifact mirror rejected: %v", err)
	}
	plainMirror, err := delivery.NewArtifactMirror(estate.Default(), putOnlyStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProductionArtifactMirrorAdapter(plainMirror); !errors.Is(err, ErrArtifactVerification) {
		t.Fatalf("put-only artifact mirror error = %v, want verification refusal", err)
	}
}

type putOnlyStore struct{}

func (putOnlyStore) Put(context.Context, string, string, string, []byte) error { return nil }

func TestProductionSnapshotMirrorVerifiesEveryRegion(t *testing.T) {
	f := &verifiedSnapshotFixture{}
	adapter, err := NewProductionSnapshotMirrorAdapter(f)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ControlStateSnapshot{ID: "js-1", ObjectKey: "jetstream/control/run.snapshot", Checksum: "abc", Size: 3, ControlEpoch: 9}
	for _, region := range []string{"gru", "sfo", "fra"} {
		if err := adapter.Mirror(context.Background(), snapshot, region); err != nil {
			t.Fatalf("mirror %s: %v", region, err)
		}
	}
	mirrors, verified := f.counts()
	if mirrors != 3 || verified != 3 {
		t.Fatalf("mirror calls=%d verified=%d, want 3/3", mirrors, verified)
	}
}

func TestProductionHistoryRequiresCompleteSnapshotEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*RunRecord)
	}{
		{"missing snapshot", func(r *RunRecord) { r.Snapshot = ControlStateSnapshot{} }},
		{"partial Regions", func(r *RunRecord) { r.SnapshotRegions = []string{"gru", "sfo"} }},
		{"invalid identity", func(r *RunRecord) { r.Snapshot.ObjectKey = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drill, backup, branches, journal, pager := drillFixture()
			verified := &verifiedSnapshotFixture{}
			mirror, err := delivery.NewArtifactMirror(estate.Default(), &productionObjectStore{objects: map[string]delivery.ObjectIdentity{}})
			if err != nil {
				t.Fatal(err)
			}
			config := drill.config
			config.AcceptedControlEpoch = 9
			composed, err := NewProductionComposition(ProductionConfig{
				Backup: backup, Branches: branches, Journal: journal, Scheduler: &fakeScheduler{}, Pager: pager,
				Drill: config, Snapshotter: verified, SnapshotMirror: verified,
				SnapshotRegions: []string{"gru", "sfo", "fra"}, ArtifactMirror: mirror,
			})
			if err != nil {
				t.Fatal(err)
			}
			run, err := composed.Drill.Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&run)
			if err := journal.SaveRun(t.Context(), run); err != nil {
				t.Fatal(err)
			}
			history, err := composed.Drill.History(t.Context(), run.ScheduledAt)
			if err != nil {
				t.Fatal(err)
			}
			if history.SuccessfulDays != 0 || history.Ready {
				t.Fatalf("incomplete snapshot counted: %+v", history)
			}
			if _, err := composed.Drill.RunAt(t.Context(), run.ScheduledAt); err != nil {
				t.Fatal(err)
			}
			history, err = composed.Drill.History(t.Context(), run.ScheduledAt)
			if err != nil {
				t.Fatal(err)
			}
			if history.SuccessfulDays != 1 {
				t.Fatalf("repaired snapshot not counted: %+v", history)
			}
		})
	}
}

func TestProductionCompositionCrashRetryKeepsDurableSelectionAndIdempotency(t *testing.T) {
	drill, backup, branches, journal, pager := drillFixture()
	// Restarting the composition with the same durable journal must resume the
	// existing run and skip the item which completed before the crash.
	ctx, cancel := context.WithCancel(context.Background())
	backup.onRestore = func(context.Context) { cancel() }
	first, firstErr := drill.Run(ctx)
	if firstErr == nil || first.Status != RunCanceled {
		t.Fatalf("first run = %#v, err=%v", first, firstErr)
	}
	firstRestores := len(backup.restores)
	backup.onRestore = nil

	verified := &verifiedSnapshotFixture{}
	objectStore := &productionObjectStore{objects: map[string]delivery.ObjectIdentity{}}
	artifactMirror, err := delivery.NewArtifactMirror(estate.Default(), objectStore)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := NewProductionComposition(ProductionConfig{
		Backup: backup, Branches: branches, Journal: journal, Scheduler: &fakeScheduler{}, Pager: pager,
		Drill:       Config{ControlPlaneID: "control", SampleSize: 2, Seed: 7, Now: func() time.Time { return time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC) }, AcceptedControlEpoch: 9},
		Snapshotter: verified, SnapshotMirror: verified, SnapshotRegions: []string{"gru", "sfo", "fra"}, ArtifactMirror: artifactMirror,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, secondErr := composed.Drill.Run(context.Background())
	if secondErr != nil || second.Status != RunSucceeded {
		t.Fatalf("retry run = %#v, err=%v", second, secondErr)
	}
	if len(backup.restores) != firstRestores+3 {
		t.Fatalf("retry restored %d items, total=%d; durable successful item was not skipped", len(backup.restores)-firstRestores, len(backup.restores))
	}
	if len(branches.deleted) != 4 {
		t.Fatalf("scratch cleanup count=%d, want 4", len(branches.deleted))
	}
	if len(second.SnapshotRegions) != 3 {
		t.Fatalf("snapshot regions=%v, want all Regions", second.SnapshotRegions)
	}
	if mirrors, verifiedCalls := verified.counts(); mirrors != 3 || verifiedCalls != 3 {
		t.Fatalf("snapshot mirror calls=%d verified=%d, want 3/3", mirrors, verifiedCalls)
	}
	if err := composed.ArtifactMirror.MirrorAll(context.Background(), productionArtifact(t, []byte("release"))); err != nil {
		t.Fatalf("artifact mirror = %v", err)
	}
}
