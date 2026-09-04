package vmqual

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func newOperationsContractForTest(t *testing.T) (*LocalProviderEndpoints, *LocalOperationsContract) {
	t.Helper()
	endpoints, err := NewLocalProviderEndpoints(LocalProviderConfig{StateRoot: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := endpoints.Close(); err != nil {
			t.Errorf("close local providers: %v", err)
		}
	})
	contract, err := NewLocalOperationsContract(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	contract.now = func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }
	return endpoints, contract
}

func TestLocalOperationsContractRequiresPersistentProviders(t *testing.T) {
	if _, err := NewLocalOperationsContract(nil); err == nil {
		t.Fatal("nil provider fixture was accepted")
	}
	_, contract := newOperationsContractForTest(t)
	if _, err := contract.QualifyKV(nil); err == nil {
		t.Fatal("nil context was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := contract.QualifyEstate(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}

func TestLocalOperationsContractQualifiesKVStateAndBudget(t *testing.T) {
	_, contract := newOperationsContractForTest(t)
	result, err := contract.QualifyKV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cloudflare.DefaultKVWriterHealthInterval != 10*time.Second || result.Interval != cloudflare.DefaultKVWriterHealthInterval {
		t.Fatalf("interval = %s", result.Interval)
	}
	if result.InitialWrites != 5 || result.RefreshWrites != 3 || result.TransitionWrites != 5 || result.TotalWrites != 13 {
		t.Fatalf("write accounting = %+v", result)
	}
	if !equalInts(result.BudgetObservations, []int{5, 5}) {
		t.Fatalf("budget observations = %v", result.BudgetObservations)
	}
	wantOrder := []string{
		"set-health:fra", "set-health:gru", "set-placement:qualification-live",
		"delete-health:sfo", "delete-placement:qualification-stale",
	}
	if !equalStrings(result.TransitionOrder, wantOrder) || !result.StaleHealthRemoved || !result.StalePlacementRemoved {
		t.Fatalf("KV transition result = %+v", result)
	}
	if !equalStrings(result.PlacementRegions, []string{"gru"}) || result.PlacementGeneration != 2 {
		t.Fatalf("placement readback = %+v", result)
	}
}

func TestLocalOperationsContractQualifiesEstateChangeAndSafety(t *testing.T) {
	_, contract := newOperationsContractForTest(t)
	result, err := contract.QualifyEstate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if estate.DefaultPublisherInterval != 10*time.Second || result.Interval != estate.DefaultPublisherInterval {
		t.Fatalf("interval = %s", result.Interval)
	}
	if result.InitialWrites != 6 || result.UnchangedWrites != 0 || result.OnChangeWrites != 1 {
		t.Fatalf("publish accounting = %+v", result)
	}
	if !equalStrings(result.Documents, estate.EstateDocIDs()) || !result.PersistentReadback {
		t.Fatalf("estate readback = %+v", result)
	}
	if !result.SecretRejected || !result.UnboundedLabelRejected {
		t.Fatalf("unsafe payload rejection = %+v", result)
	}
}

func TestLocalOperationsContractQualifiesRestoreAndRegionalMirrors(t *testing.T) {
	endpoints, contract := newOperationsContractForTest(t)
	result, err := contract.QualifyRestoreAndMirrors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.DailyInterval != 24*time.Hour || result.RunID != "restore-drill-2026-09-04" {
		t.Fatalf("daily drill result = %+v", result)
	}
	if !equalStrings(result.RestoredDatabases, []string{"control", "qualification"}) || !result.ScratchBranchesClean {
		t.Fatalf("restore proof = %+v", result)
	}
	wantRegions := []string{"fra", "gru", "sfo"}
	if !equalStrings(result.SnapshotRegions, wantRegions) || !equalStrings(result.ArtifactRegions, wantRegions) {
		t.Fatalf("mirror regions = snapshot %v artifact %v", result.SnapshotRegions, result.ArtifactRegions)
	}
	if result.SnapshotObject == "" || result.ArtifactObject == "" || !result.PersistentReadback {
		t.Fatalf("persistent result = %+v", result)
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if stats := endpoints.Object[region].Stats(); stats.Objects == 0 || stats.Bytes == 0 {
			t.Fatalf("%s persistent object store stats = %+v", region, stats)
		}
	}

	// Running the contract again on the same disk-backed endpoints reloads the
	// successful daily journal record rather than manufacturing a new run.
	reloaded, err := NewLocalOperationsContract(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.now = contract.now
	second, err := reloaded.QualifyRestoreAndMirrors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.RunID != result.RunID || !second.PersistentReadback || !second.ScratchBranchesClean {
		t.Fatalf("reloaded restore result = %+v", second)
	}
}

func TestLocalOperationsContractQualifiesPlacementLockTransitions(t *testing.T) {
	_, contract := newOperationsContractForTest(t)
	result, err := contract.QualifyPlacementLocks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "explicit" || result.Generation != 1 || !equalStrings(result.Regions, []string{"FRA", "GRU"}) {
		t.Fatalf("placement lock = %+v", result)
	}
	if !equalStrings(result.Transitions, placementTransitions) || !result.WideningRejected || !result.Persistent {
		t.Fatalf("placement transitions = %+v", result)
	}
}
