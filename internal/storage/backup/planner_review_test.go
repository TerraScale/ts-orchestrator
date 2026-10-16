package backup

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// A create that OCI accepted and then marked FAULTY gets a new attempt key
// in the same slot, so the replacement is not a replay of the failed retry
// token; an ambiguous outcome keeps the key (#127 12048).
func TestPlanUsesANewAttemptKeyAfterAFaultyBackup(t *testing.T) {
	first := Plan(scope, volume, nil, now)
	if len(first) != 1 || first[0].Kind != ActionCreate {
		t.Fatalf("first plan = %+v", first)
	}
	faulty := oci.CloudVolumeBackup{ID: "f1", VolumeID: volume, LifecycleState: "FAULTY", Type: TypeFull,
		CreatedAt: now.Add(-time.Minute), FreeformTags: scope.Tags(volume, first[0].Key)}
	second := Plan(scope, volume, []oci.CloudVolumeBackup{faulty}, now.Add(15*time.Minute))
	if len(second) != 1 || second[0].Key == first[0].Key {
		t.Fatalf("replacement after FAULTY replays the failed key: %+v", second)
	}
	if again := Plan(scope, volume, []oci.CloudVolumeBackup{faulty}, now.Add(30*time.Minute)); again[0].Key != second[0].Key {
		t.Fatal("the replacement key is not stable while its outcome is ambiguous")
	}
	faulty2 := faulty
	faulty2.ID, faulty2.FreeformTags = "f2", scope.Tags(volume, second[0].Key)
	third := Plan(scope, volume, []oci.CloudVolumeBackup{faulty, faulty2}, now.Add(45*time.Minute))
	if third[0].Key == second[0].Key || third[0].Key == first[0].Key {
		t.Fatalf("a second failure did not advance the attempt: %+v", third)
	}
}

// Daily backup and retention use the same fixed seven-backup cadence.
func TestFixedRetentionKeepsTheFullBackupThroughoutItsCadence(t *testing.T) {
	var history []oci.CloudVolumeBackup
	for day := range 15 {
		at := now.Add(time.Duration(day) * 24 * time.Hour)
		actions := Plan(scope, volume, history, at)
		var created bool
		for _, action := range actions {
			switch action.Kind {
			case ActionCreate:
				created = true
				want := TypeIncremental
				if day%7 == 0 {
					want = TypeFull
				}
				if action.Type != want {
					t.Fatalf("day %d: backup type %s, want %s", day, action.Type, want)
				}
				history = append(history, oci.CloudVolumeBackup{ID: action.Key, VolumeID: volume,
					LifecycleState: "AVAILABLE", Type: action.Type, CreatedAt: at, FreeformTags: scope.Tags(volume, action.Key)})
			case ActionDelete:
				for i, backup := range history {
					if backup.ID == action.BackupID {
						history = append(history[:i], history[i+1:]...)
						break
					}
				}
			}
		}
		if !created {
			t.Fatalf("day %d: no daily backup", day)
		}
		full := false
		for _, backup := range history {
			if backup.Type == TypeFull {
				full = true
			}
		}
		if !full || len(history) > 8 {
			t.Fatalf("day %d: retained history has no FULL or exceeds retention plus the new backup: %+v", day, history)
		}
	}
}
