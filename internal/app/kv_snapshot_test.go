package app

import (
	"slices"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// Renaming a configuration bucket must not silently drop it from snapshots.
func TestKVSnapshotsCoverConfigurationBuckets(t *testing.T) {
	for _, bucket := range []string{cellSpecBucket, hostenroll.GrantBucket, rollout.Bucket} {
		if !slices.Contains(kvsnapshot.Buckets, bucket) {
			t.Fatalf("kvsnapshot.Buckets lacks %s", bucket)
		}
	}
}
