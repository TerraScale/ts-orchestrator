package backup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
)

var (
	now   = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	scope = Scope{Owner: "owner-a", Region: oci.RegionGRU}
)

const volume = "ocid1.volume.a"

func owned(id, state, kind string, age time.Duration) oci.CloudVolumeBackup {
	return oci.CloudVolumeBackup{ID: id, VolumeID: volume, LifecycleState: state, Type: kind,
		CreatedAt: now.Add(-age), FreeformTags: scope.Tags(volume, entityid.Derive("test-backup", id)), ETag: "etag-" + id}
}

func TestScopeOwnsRequiresExactTagsAndSourceVolume(t *testing.T) {
	backup := owned("b1", "AVAILABLE", TypeFull, time.Hour)
	if !scope.Owns(backup, volume) {
		t.Fatal("exact backup is not owned")
	}
	for name, mutate := range map[string]func(*oci.CloudVolumeBackup){
		"other source volume": func(b *oci.CloudVolumeBackup) { b.VolumeID = "ocid1.volume.b" },
		"other owner":         func(b *oci.CloudVolumeBackup) { b.FreeformTags[tagOwner] = "owner-b" },
		"other region":        func(b *oci.CloudVolumeBackup) { b.FreeformTags[tagRegion] = "fra" },
		"untagged":            func(b *oci.CloudVolumeBackup) { b.FreeformTags = nil },
		"missing key":         func(b *oci.CloudVolumeBackup) { delete(b.FreeformTags, tagBackupKey) },
		"tag volume mismatch": func(b *oci.CloudVolumeBackup) { b.FreeformTags[tagBackupVolume] = "ocid1.volume.b" },
	} {
		candidate := backup
		candidate.FreeformTags = maps.Clone(backup.FreeformTags)
		mutate(&candidate)
		if scope.Owns(candidate, volume) {
			t.Fatalf("%s: foreign backup is owned", name)
		}
	}
}

func TestPlanCreatesFirstFullThenIncrementalsOnInterval(t *testing.T) {
	policy := Policy{Enabled: true, FullEvery: 3}
	actions := Plan(policy, scope, volume, nil, now)
	if len(actions) != 1 || actions[0].Kind != ActionCreate || actions[0].Type != TypeFull || !entityid.Valid(actions[0].Key) {
		t.Fatalf("first plan = %+v", actions)
	}
	// Same slot replays the same idempotency key.
	if again := Plan(policy, scope, volume, nil, now.Add(time.Minute)); again[0].Key != actions[0].Key {
		t.Fatal("create key is not stable within its slot")
	}
	recent := []oci.CloudVolumeBackup{owned("b1", "AVAILABLE", TypeFull, time.Hour)}
	if actions := Plan(policy, scope, volume, recent, now); len(actions) != 0 {
		t.Fatalf("backup inside interval planned %+v", actions)
	}
	due := []oci.CloudVolumeBackup{owned("b1", "AVAILABLE", TypeFull, 25*time.Hour)}
	if actions := Plan(policy, scope, volume, due, now); len(actions) != 1 || actions[0].Type != TypeIncremental {
		t.Fatalf("due incremental = %+v", actions)
	}
	chain := []oci.CloudVolumeBackup{
		owned("b3", "AVAILABLE", TypeIncremental, 25*time.Hour),
		owned("b2", "AVAILABLE", TypeIncremental, 49*time.Hour),
		owned("b1", "AVAILABLE", TypeFull, 73*time.Hour),
	}
	if actions := Plan(policy, scope, volume, chain, now); len(actions) != 1 || actions[0].Type != TypeFull {
		t.Fatalf("FullEvery did not start a new full backup: %+v", actions)
	}
	inProgress := []oci.CloudVolumeBackup{owned("b2", "CREATING", TypeIncremental, 30*time.Hour), owned("b1", "AVAILABLE", TypeFull, 50*time.Hour)}
	if actions := Plan(policy, scope, volume, inProgress, now); len(actions) != 0 {
		t.Fatalf("plan created while a backup is in progress: %+v", actions)
	}
	queued := []oci.CloudVolumeBackup{owned("b2", "REQUEST_RECEIVED", TypeIncremental, 30*time.Hour), owned("b1", "AVAILABLE", TypeFull, 50*time.Hour)}
	if actions := Plan(policy, scope, volume, queued, now); len(actions) != 0 {
		t.Fatalf("plan created while a backup request is queued: %+v", actions)
	}
	foreign := owned("f1", "AVAILABLE", TypeFull, time.Hour)
	foreign.FreeformTags = nil
	if actions := Plan(policy, scope, volume, []oci.CloudVolumeBackup{foreign}, now); len(actions) != 1 || actions[0].Type != TypeFull {
		t.Fatalf("foreign backup satisfied the policy: %+v", actions)
	}
}

func TestPlanPrunesOnlyOwnedAvailableBeyondRetain(t *testing.T) {
	var backups []oci.CloudVolumeBackup
	for index := range 5 {
		backups = append(backups, owned(fmt.Sprintf("b%d", index), "AVAILABLE", TypeIncremental, time.Duration(index+1)*time.Hour))
	}
	backups = append(backups, owned("faulty", "FAULTY", TypeFull, 100*time.Hour))
	foreign := owned("foreign", "AVAILABLE", TypeFull, 200*time.Hour)
	foreign.FreeformTags = nil
	backups = append(backups, foreign)
	policy := Policy{Enabled: true, Retain: 2}
	if actions := Plan(policy, scope, volume, backups, now); len(actions) != 0 {
		t.Fatalf("prune ran while disabled: %+v", actions)
	}
	policy.Prune = true
	var deleted []string
	for _, action := range Plan(policy, scope, volume, backups, now) {
		if action.Kind == ActionDelete {
			deleted = append(deleted, action.BackupID)
		}
	}
	if fmt.Sprint(deleted) != "[b2 b3 b4]" {
		t.Fatalf("pruned %v, want the three oldest owned AVAILABLE backups", deleted)
	}
}

func TestPolicyValidation(t *testing.T) {
	if err := (Policy{}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Policy{{IntervalHours: -1}, {Retain: 1000}, {FullEvery: -2}, {RunIntervalSeconds: 5}} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %+v", bad)
		}
	}
}

type fakeFencer struct {
	snapshot authority.Snapshot
	guardErr error
	guards   int
}

func (f *fakeFencer) Current() authority.Snapshot { return f.snapshot }
func (f *fakeFencer) Guard(context.Context, uint64) error {
	f.guards++
	return f.guardErr
}

func leader() authority.Snapshot {
	return authority.Snapshot{Leader: true, Ready: true, Epoch: 3, Revision: 5, ExpiresAt: time.Now().Add(time.Minute)}
}

type fakeProvider struct {
	backups map[string]oci.CloudVolumeBackup
	tokens  map[string]string
	creates int
	deletes []string
	onGet   func(*oci.CloudVolumeBackup)
	gone    map[string]bool
}

func newFakeProvider(backups ...oci.CloudVolumeBackup) *fakeProvider {
	provider := &fakeProvider{backups: make(map[string]oci.CloudVolumeBackup), tokens: make(map[string]string)}
	for _, backup := range backups {
		provider.backups[backup.ID] = backup
	}
	return provider
}

func (p *fakeProvider) CreateVolumeBackup(_ context.Context, volumeID, name, kind string, tags map[string]string, token string) (oci.CloudVolumeBackup, error) {
	if id, ok := p.tokens[token]; ok {
		return p.backups[id], nil
	}
	p.creates++
	backup := oci.CloudVolumeBackup{ID: fmt.Sprintf("created-%d", p.creates), VolumeID: volumeID, DisplayName: name,
		Type: kind, LifecycleState: "CREATING", CreatedAt: now, FreeformTags: maps.Clone(tags), ETag: "e"}
	p.backups[backup.ID] = backup
	p.tokens[token] = backup.ID
	return backup, nil
}

func (p *fakeProvider) ListVolumeBackups(_ context.Context, volumeID string) ([]oci.CloudVolumeBackup, error) {
	var found []oci.CloudVolumeBackup
	for _, backup := range p.backups {
		if backup.VolumeID == volumeID {
			found = append(found, backup)
		}
	}
	return found, nil
}

func (p *fakeProvider) ListCompartmentVolumeBackups(context.Context) ([]oci.CloudVolumeBackup, error) {
	var found []oci.CloudVolumeBackup
	for _, backup := range p.backups {
		found = append(found, backup)
	}
	return found, nil
}

func (p *fakeProvider) VolumeGone(_ context.Context, volumeID string) (bool, error) {
	return p.gone[volumeID], nil
}

func (p *fakeProvider) GetVolumeBackup(_ context.Context, id string) (oci.CloudVolumeBackup, error) {
	backup, ok := p.backups[id]
	if !ok {
		return oci.CloudVolumeBackup{}, errors.New("not found")
	}
	if p.onGet != nil {
		p.onGet(&backup)
	}
	return backup, nil
}

func (p *fakeProvider) DeleteVolumeBackup(_ context.Context, id, etag string) error {
	if p.backups[id].ETag != etag {
		return oci.ErrStaleETag
	}
	delete(p.backups, id)
	p.deletes = append(p.deletes, id)
	return nil
}

func runner(provider *fakeProvider, fencer *fakeFencer, policy Policy) Runner {
	return Runner{Policy: policy, Scope: scope, Provider: provider, Fencer: fencer,
		Volumes: func(context.Context) ([]string, error) { return []string{volume}, nil },
		Now:     func() time.Time { return now }}
}

func TestRunnerCreatesIdempotentlyAndPrunesWithExactETag(t *testing.T) {
	var existing []oci.CloudVolumeBackup
	for index := range 4 {
		existing = append(existing, owned(fmt.Sprintf("old-%d", index), "AVAILABLE", TypeFull, time.Duration(index+25)*time.Hour))
	}
	provider := newFakeProvider(existing...)
	fencer := &fakeFencer{snapshot: leader()}
	report, err := runner(provider, fencer, Policy{Enabled: true, Retain: 2, FullEvery: 2, Prune: true}).RunOnce(t.Context())
	if err != nil || len(report.Created) != 1 || len(report.Deleted) != 2 {
		t.Fatalf("report = %+v, %v", report, err)
	}
	if provider.creates != 1 || fmt.Sprint(provider.deletes) != "[old-2 old-3]" {
		t.Fatalf("creates=%d deletes=%v", provider.creates, provider.deletes)
	}
	// The new backup is CREATING: a second pass creates nothing.
	if report, err := runner(provider, fencer, Policy{Enabled: true, Retain: 2, FullEvery: 2, Prune: true}).RunOnce(t.Context()); err != nil || len(report.Created) != 0 {
		t.Fatalf("second pass = %+v, %v", report, err)
	}
}

func TestRunnerSkipsBackupThatChangedOwnershipBeforeDelete(t *testing.T) {
	provider := newFakeProvider(
		owned("keep", "AVAILABLE", TypeFull, time.Hour),
		owned("old", "AVAILABLE", TypeFull, 2*time.Hour),
	)
	provider.onGet = func(backup *oci.CloudVolumeBackup) { backup.FreeformTags = nil }
	report, err := runner(provider, &fakeFencer{snapshot: leader()}, Policy{Enabled: true, Retain: 1, FullEvery: 1, Prune: true}).RunOnce(t.Context())
	if err != nil || len(provider.deletes) != 0 || len(report.Skipped) != 1 {
		t.Fatalf("re-read foreign backup was deleted: report=%+v deletes=%v err=%v", report, provider.deletes, err)
	}
}

func TestRunnerRefusesFollowersFencedAndDisabled(t *testing.T) {
	provider := newFakeProvider()
	follower := &fakeFencer{snapshot: authority.Snapshot{Ready: true, Epoch: 3, Revision: 5, ExpiresAt: time.Now().Add(time.Minute)}}
	if _, err := runner(provider, follower, Policy{Enabled: true}).RunOnce(t.Context()); !errors.Is(err, authority.ErrNotLeader) {
		t.Fatalf("follower ran: %v", err)
	}
	fenced := &fakeFencer{snapshot: leader(), guardErr: authority.ErrFenced}
	if _, err := runner(provider, fenced, Policy{Enabled: true}).RunOnce(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced runner did not stop: %v", err)
	}
	if _, err := runner(provider, &fakeFencer{snapshot: leader()}, Policy{}).RunOnce(t.Context()); !errors.Is(err, storage.ErrDisabled) {
		t.Fatalf("disabled policy ran: %v", err)
	}
	if provider.creates != 0 {
		t.Fatalf("refused runs created %d backups", provider.creates)
	}
}

func orphan(id, volumeID string, age time.Duration) oci.CloudVolumeBackup {
	return oci.CloudVolumeBackup{ID: id, VolumeID: volumeID, LifecycleState: "AVAILABLE", Type: TypeFull,
		CreatedAt: now.Add(-age), FreeformTags: scope.Tags(volumeID, entityid.Derive("test-backup", id)), ETag: "etag-" + id}
}

func TestRunnerPrunesOrphanedBackupsOfRemovedVolumesAfterRetention(t *testing.T) {
	const removed, retained = "ocid1.volume.removed", "ocid1.volume.retained"
	foreign := orphan("foreign", removed, 90*24*time.Hour)
	foreign.FreeformTags = nil
	provider := newFakeProvider(
		owned("live", "AVAILABLE", TypeFull, time.Hour),
		orphan("old", removed, 40*24*time.Hour),
		orphan("young", removed, 10*24*time.Hour),
		orphan("still-there", retained, 90*24*time.Hour),
		foreign,
	)
	provider.gone = map[string]bool{removed: true}
	fencer := &fakeFencer{snapshot: leader()}
	if _, err := runner(provider, fencer, Policy{Enabled: true}).RunOnce(t.Context()); err != nil || len(provider.deletes) != 0 {
		t.Fatalf("orphans pruned without Prune: deletes=%v err=%v", provider.deletes, err)
	}
	report, err := runner(provider, fencer, Policy{Enabled: true, Prune: true}).RunOnce(t.Context())
	if err != nil || fmt.Sprint(provider.deletes) != "[old]" || fmt.Sprint(report.Deleted) != "[old]" {
		t.Fatalf("orphan prune deletes=%v report=%+v err=%v; want only the expired owned backup of the removed volume", provider.deletes, report, err)
	}
}

func TestRunnerProtectsListedVolumesButSkipsOrphansOnPartialListing(t *testing.T) {
	const removed = "ocid1.volume.removed"
	provider := newFakeProvider(orphan("old", removed, 400*24*time.Hour))
	provider.gone = map[string]bool{removed: true}
	partial := runner(provider, &fakeFencer{snapshot: leader()}, Policy{Enabled: true, Prune: true})
	partial.Volumes = func(context.Context) ([]string, error) {
		return []string{volume}, fmt.Errorf("%w: partition unreadable", ErrPartialVolumes)
	}
	report, err := partial.RunOnce(t.Context())
	if !errors.Is(err, ErrPartialVolumes) || len(report.Created) != 1 || len(provider.deletes) != 0 {
		t.Fatalf("partial listing: report=%+v deletes=%v err=%v", report, provider.deletes, err)
	}
}
