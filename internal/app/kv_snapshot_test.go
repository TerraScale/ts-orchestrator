package app

import (
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machines"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/volume"
)

// Renaming a configuration bucket must not silently drop it from snapshots.
func TestKVSnapshotsCoverConfigurationBuckets(t *testing.T) {
	for _, bucket := range []string{cellSpecBucket, rootChainBucket, hostenroll.GrantBucket, rollout.Bucket, machines.Bucket, volume.Bucket} {
		if !slices.Contains(kvsnapshot.Buckets, bucket) {
			t.Fatalf("kvsnapshot.Buckets lacks %s", bucket)
		}
	}
	// Observed machine states are relearned from hosts, never restored.
	if slices.Contains(kvsnapshot.Buckets, machines.StatusBucket) {
		t.Fatalf("kvsnapshot.Buckets holds %s", machines.StatusBucket)
	}
}
