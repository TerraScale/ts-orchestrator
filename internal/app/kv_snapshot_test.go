package app

import (
	"slices"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/kvsnapshot"
	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/volume"
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

func TestStartKVSnapshotsDisabledExposesStatusWithoutDependencies(t *testing.T) {
	stop, view, err := startKVSnapshots(t.Context(), Config{}, nil, nil, nil)
	if err != nil || stop == nil || view == nil {
		t.Fatalf("disabled snapshots = %v, %v, %v", stop != nil, view != nil, err)
	}
	stop()
	status := view()
	if status.State != "disabled" || status.IntervalSeconds != 0 || !status.LastCheckAt.IsZero() || len(status.Buckets) != 0 {
		t.Fatalf("disabled status = %+v", status)
	}
}
