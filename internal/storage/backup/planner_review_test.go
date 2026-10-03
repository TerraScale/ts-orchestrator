package backup

import (
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// A create that OCI accepted and then marked FAULTY gets a new attempt key
// in the same slot, so the replacement is not a replay of the failed retry
// token; an ambiguous outcome keeps the key (#127 12048).
func TestPlanUsesANewAttemptKeyAfterAFaultyBackup(t *testing.T) {
	policy := Policy{Enabled: true}
	first := Plan(policy, scope, volume, nil, now)
	if len(first) != 1 || first[0].Kind != ActionCreate {
		t.Fatalf("first plan = %+v", first)
	}
	faulty := oci.CloudVolumeBackup{ID: "f1", VolumeID: volume, LifecycleState: "FAULTY", Type: TypeFull,
		CreatedAt: now.Add(-time.Minute), FreeformTags: scope.Tags(volume, first[0].Key)}
	second := Plan(policy, scope, volume, []oci.CloudVolumeBackup{faulty}, now.Add(15*time.Minute))
	if len(second) != 1 || second[0].Key == first[0].Key {
		t.Fatalf("replacement after FAULTY replays the failed key: %+v", second)
	}
	if again := Plan(policy, scope, volume, []oci.CloudVolumeBackup{faulty}, now.Add(30*time.Minute)); again[0].Key != second[0].Key {
		t.Fatal("the replacement key is not stable while its outcome is ambiguous")
	}
	faulty2 := faulty
	faulty2.ID, faulty2.FreeformTags = "f2", scope.Tags(volume, second[0].Key)
	third := Plan(policy, scope, volume, []oci.CloudVolumeBackup{faulty, faulty2}, now.Add(45*time.Minute))
	if third[0].Key == second[0].Key || third[0].Key == first[0].Key {
		t.Fatalf("a second failure did not advance the attempt: %+v", third)
	}
}

// Pruning below the full-backup cadence would delete the last FULL and force
// extra fulls, so such a policy is refused (#127 12049).
func TestPolicyRefusesPruningBelowTheFullCadence(t *testing.T) {
	if err := (Policy{Prune: true, Retain: 2, FullEvery: 7}).Validate(); err == nil {
		t.Fatal("retain 2 with full_every 7 accepted")
	}
	if err := (Policy{Prune: true, Retain: 7, FullEvery: 7}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Policy{Retain: 2, FullEvery: 7}).Validate(); err != nil {
		t.Fatalf("a non-pruning policy was refused: %v", err)
	}
}
