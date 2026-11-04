package backup

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
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
	return authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Leader: true, Ready: true, Epoch: 3, Revision: 5, ExpiresAt: time.Now().Add(time.Minute)}
}

type fakeProvider struct {
	backups   map[string]oci.CloudVolumeBackup
	tokens    map[string]string
	creates   int
	deletes   []string
	onGet     func(*oci.CloudVolumeBackup)
	gone      map[string]bool
	goneErr   map[string]error
	goneReads map[string]int
}

func newFakeProvider(backups ...oci.CloudVolumeBackup) *fakeProvider {
	provider := &fakeProvider{backups: make(map[string]oci.CloudVolumeBackup), tokens: make(map[string]string), goneReads: make(map[string]int)}
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
	p.goneReads[volumeID]++
	return p.gone[volumeID], p.goneErr[volumeID]
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

func runner(provider *fakeProvider, fencer *fakeFencer) Runner {
	return Runner{Scope: scope, Provider: provider, Fencer: fencer,
		Volumes: func(context.Context) ([]string, error) { return []string{volume}, nil },
		Now:     func() time.Time { return now }}
}

func TestRunnerCreatesIdempotentlyAndPrunesWithExactETag(t *testing.T) {
	var existing []oci.CloudVolumeBackup
	for index := range 9 {
		existing = append(existing, owned(fmt.Sprintf("old-%d", index), "AVAILABLE", TypeFull, time.Duration(index+25)*time.Hour))
	}
	provider := newFakeProvider(existing...)
	fencer := &fakeFencer{snapshot: leader()}
	report, err := runner(provider, fencer).RunOnce(t.Context())
	if err != nil || len(report.Created) != 1 || len(report.Deleted) != 2 {
		t.Fatalf("report = %+v, %v", report, err)
	}
	if provider.creates != 1 || fmt.Sprint(provider.deletes) != "[old-7 old-8]" {
		t.Fatalf("creates=%d deletes=%v", provider.creates, provider.deletes)
	}
	// The new backup is CREATING: a second pass creates nothing.
	if report, err := runner(provider, fencer).RunOnce(t.Context()); err != nil || len(report.Created) != 0 {
		t.Fatalf("second pass = %+v, %v", report, err)
	}
}

func TestRunnerRefusesFollowersAndFencedAuthority(t *testing.T) {
	provider := newFakeProvider()
	follower := &fakeFencer{snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Epoch: 3, Revision: 5, ExpiresAt: time.Now().Add(time.Minute)}}
	if _, err := runner(provider, follower).RunOnce(t.Context()); !errors.Is(err, authority.ErrNotLeader) {
		t.Fatalf("follower ran: %v", err)
	}
	fenced := &fakeFencer{snapshot: leader(), guardErr: authority.ErrFenced}
	if _, err := runner(provider, fenced).RunOnce(t.Context()); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("fenced runner did not stop: %v", err)
	}

	if provider.creates != 0 {
		t.Fatalf("refused runs created %d backups", provider.creates)
	}
}
