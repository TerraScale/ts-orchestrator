package region_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

// The genuine original fixture has initial retention cooling, not fourteen
// days of elapsed production history. It must not mint recovery authority.
func TestOriginalNetBirdBackupRefusesPendingProtection(t *testing.T) {
	tier.Integration(t)
	region.WithOriginalNetBirdManagerFixture(t, func(factory *ociclient.Factory, resolver region.FoundationResolver, manager region.VerifiedNetBirdManager) {
		ctx := t.Context()
		if err := manager.Check(ctx); err != nil {
			t.Fatal(err)
		}
		// The original GRU foundation selects the exact source escrow Vault as its regional Vault.
		if manager.VaultTarget() != manager.CredentialTarget() {
			t.Fatal("original regional backup Vault differs from its selected credential escrow")
		}
		record, _, err := resolver.Store.Load(ctx, "GRU")
		if err != nil {
			t.Fatal(err)
		}
		journal := record.OriginalFoundationCompartments.Regions[0].NetBirdManager.Backup
		if journal == nil || journal.Complete {
			t.Fatal("fixture must retain genuine initial pending backup history")
		}
		if _, err := resolver.OriginalNetBirdBackup(ctx, manager); !errors.Is(err, region.ErrOriginalNetBirdBackupPending) {
			t.Fatalf("original authority before retention lock: %v", err)
		}
		if _, err := foundation.NewBackupTargets(ctx, factory, resolver, manager); !errors.Is(err, region.ErrOriginalNetBirdBackupPending) {
			t.Fatalf("public recovery constructor lost original pending refusal: %v", err)
		}
		if _, err := resolver.BootstrapMaterial(ctx, "GRU"); err == nil {
			t.Fatal("generic bootstrap material accepted original schema3")
		}
		for _, cell := range [2]string{"GRU", "SJC"} {
			if _, err := resolver.Resolve(ctx, cell); err == nil {
				t.Fatalf("generic resolver accepted original %s", cell)
			}
			if _, err := resolver.BackupDestination(ctx, cell); err == nil {
				t.Fatalf("generic backup destination accepted original %s", cell)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := foundation.NewBackupTargets(canceled, factory, resolver, manager); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled original recovery: %v", err)
		}
	})
}

func TestOriginalNetBirdBackupDoesNotFallBackAfterRefusal(t *testing.T) {
	tier.Integration(t)
	region.WithOriginalNetBirdManagerFixture(t, func(factory *ociclient.Factory, resolver region.FoundationResolver, manager region.VerifiedNetBirdManager) {
		refused := errors.New("current original store is unavailable")
		store := &originalBackupReadStore{FoundationStore: resolver.Store, refused: refused}
		resolver.Store = store
		if _, err := foundation.NewBackupTargets(t.Context(), factory, resolver, manager); !errors.Is(err, refused) || errors.Is(err, region.ErrNotOriginalNetBirdManager) {
			t.Fatalf("original store refusal was replaced by generic fallback: %v", err)
		}
		store.refused = region.ErrNotOriginalNetBirdManager
		if _, err := resolver.OriginalNetBirdBackup(t.Context(), manager); !errors.Is(err, region.ErrOriginalSourceProducerHold) || errors.Is(err, region.ErrNotOriginalNetBirdManager) {
			t.Fatalf("original reader error selected legacy lineage: %v", err)
		}
		store.refused = nil
		for _, test := range []struct {
			name   string
			change func(*region.OriginalNetBirdBackupJournal)
		}{
			{"unearned completion", func(j *region.OriginalNetBirdBackupJournal) { j.Complete = true }},
			{"foreign store", func(j *region.OriginalNetBirdBackupJournal) { j.StoreGeneration += "foreign" }},
			{"foreign namespace", func(j *region.OriginalNetBirdBackupJournal) { j.Namespace += "foreign" }},
			{"swapped regions", func(j *region.OriginalNetBirdBackupJournal) {
				j.Destinations[0], j.Destinations[1] = j.Destinations[1], j.Destinations[0]
			}},
			{"credential escrow", func(j *region.OriginalNetBirdBackupJournal) {
				j.Destinations[0].KMSKeyID = manager.CredentialTarget().KeyID
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				store.change = test.change
				t.Cleanup(func() { store.change = nil })
				if _, err := foundation.NewBackupTargets(t.Context(), factory, resolver, manager); err == nil || errors.Is(err, region.ErrNotOriginalNetBirdManager) {
					t.Fatalf("changed original producer history received recovery authority or generic fallback: %v", err)
				}
			})
		}
	})
}

func TestLegacyNetBirdManagerHasExplicitBackupLineageBoundary(t *testing.T) {
	region.WithNetBirdManagerFixture(t, func(_ *ociclient.Factory, resolver region.FoundationResolver, manager region.VerifiedNetBirdManager) {
		if _, err := resolver.OriginalNetBirdBackup(t.Context(), manager); !errors.Is(err, region.ErrNotOriginalNetBirdManager) {
			t.Fatalf("genuine legacy manager did not select its existing backup path: %v", err)
		}
		if _, err := resolver.OriginalNetBirdBackup(t.Context(), region.VerifiedNetBirdManager{}); err == nil || errors.Is(err, region.ErrNotOriginalNetBirdManager) {
			t.Fatalf("unadmitted manager reached the legacy lineage boundary: %v", err)
		}
	})
}

// This reader changes only the current response under test. The real signed
// fixture, manager admission and retained producer journal remain untouched.
type originalBackupReadStore struct {
	region.FoundationStore
	refused error
	change  func(*region.OriginalNetBirdBackupJournal)
}

func (s *originalBackupReadStore) Load(ctx context.Context, cell string) (region.FoundationRecord, string, error) {
	if s.refused != nil {
		return region.FoundationRecord{}, "", s.refused
	}
	record, etag, err := s.FoundationStore.Load(ctx, cell)
	if err != nil || s.change == nil || cell != "GRU" {
		return record, etag, err
	}
	wire, err := json.Marshal(record)
	if err != nil {
		return region.FoundationRecord{}, "", err
	}
	var changed region.FoundationRecord
	if err := json.Unmarshal(wire, &changed); err != nil {
		return region.FoundationRecord{}, "", err
	}
	s.change(changed.OriginalFoundationCompartments.Regions[0].NetBirdManager.Backup)
	return changed, etag, nil
}
