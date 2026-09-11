package vmqual

import (
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"testing"
	"time"
)

// Completion removes the claims directory before the journal file; a crash in
// that window leaves a complete journal without claims. Recovery must accept
// it (the run marker is already tolerated absent for complete journals),
// while an unfinished journal still requires its claims.
func TestCompletedJournalToleratesMissingClaimsAfterCrashWindow(t *testing.T) {
	root := t.TempDir()
	runID := "11111111-1111-4111-8111-111111111111"
	created := time.Now().UTC().Add(-time.Minute)
	resource := JournalVM{RunID: runID, ID: "gru-member-1", Region: string(vmnet.GRU), Phase: vmPhaseCleaned, Cleaned: true,
		ClaimPath: filepath.Join(root, ".vmqual-runs", runID+".claims", "gru-member-1.json")}
	for _, phase := range []string{journalPhaseActive, journalPhaseComplete} {
		journal := Journal{
			Version: cleanupJournalVersion, Marker: OwnershipMarker, RunID: runID, Revision: 1,
			CreatedAt: created, UpdatedAt: created.Add(time.Second), StateRoot: root,
			RunMarkerPath: filepath.Join(root, ".vmqual-runs", runID+".json"),
			Phase:         phase, NetworkPhase: networkPhasePlanned, VMs: []JournalVM{resource},
		}
		err := validateOwnershipGraph(journal, filepath.Join(root, "cleanup-journal.json"))
		if phase == journalPhaseComplete {
			if err != nil {
				t.Fatalf("complete journal without claims was rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatal("an unfinished journal without claims was accepted")
		}
	}
}
