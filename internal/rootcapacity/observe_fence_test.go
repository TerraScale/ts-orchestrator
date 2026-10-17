package rootcapacity

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func TestProtectedCapturePermanentlyFencesWorkerAdmission(t *testing.T) {
	const instanceID = "original-worker"
	for _, phase := range []string{drainwire.PoolCaptured, drainwire.PoolStopped} {
		record := region.FoundationRecord{PoolDrains: map[string]drainwire.PoolReceipt{"original-removal": {
			Child: drainwire.PoolChild{InstanceID: instanceID}, Phase: phase, ExpiresAt: time.Now().Add(-time.Hour),
		}}}
		if !protectedChildFenced(record, instanceID) || protectedChildFenced(record, "another-worker") {
			t.Fatal("expired capture lost its permanent exact-instance admission fence")
		}
	}
	record := region.FoundationRecord{PoolChildren: map[string]region.PoolChildRecord{"original-birth": {
		InstanceID: instanceID, Stage: region.PoolChildRetired, RetirementDrain: &drainwire.PoolReceipt{},
	}}}
	if !protectedChildFenced(record, instanceID) || protectedChildFenced(record, "another-worker") {
		t.Fatal("terminal receipt transfer lost its permanent exact-instance admission fence")
	}
	if protectedChildFenced(region.FoundationRecord{PoolChildren: map[string]region.PoolChildRecord{"original-birth": {
		InstanceID: instanceID, Stage: region.PoolChildReady,
	}}}, instanceID) {
		t.Fatal("ordinary ready worker was fenced without protected drain history")
	}
}
