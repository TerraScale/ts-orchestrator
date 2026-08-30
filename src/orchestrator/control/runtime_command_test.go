package control

import (
	"strings"
	"testing"
)

func TestNewRuntimeCommandRejectsNegativeAcceptedCounters(t *testing.T) {
	t.Parallel()

	checkpoint := &NativeGitOpsVerifiedConvergenceDispatchV1{}
	accepted := &NativeGitOpsAcceptedCellSpec{Generation: -1, WriterEpoch: 1}
	if _, err := NewRuntimeCommandV1(accepted, checkpoint, RuntimeHostAssignmentV1{}, RuntimeLifecycleOperationRequest{}); err == nil ||
		!strings.Contains(err.Error(), "accepted.Generation") {
		t.Fatalf("negative generation error = %v", err)
	}

	accepted.Generation = 1
	accepted.WriterEpoch = -1
	if _, err := NewRuntimeCommandV1(accepted, checkpoint, RuntimeHostAssignmentV1{}, RuntimeLifecycleOperationRequest{}); err == nil ||
		!strings.Contains(err.Error(), "accepted.WriterEpoch") {
		t.Fatalf("negative writer epoch error = %v", err)
	}
}
