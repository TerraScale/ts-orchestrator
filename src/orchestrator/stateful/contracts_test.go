package stateful

import (
	"errors"
	"strings"
	"testing"
)

// errorsAsParam reports whether err is one of the package argument errors
// naming the given parameter.
func errorsAsParam(err error, param string) bool {
	var argumentError *ArgumentError
	if errors.As(err, &argumentError) {
		return argumentError.Param == param
	}
	var outOfRange *ArgumentOutOfRangeError
	if errors.As(err, &outOfRange) {
		return outOfRange.Param == param
	}
	return false
}

func TestNewPersistentVolumeId(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expectValid bool
	}{
		{name: "canonical token", value: "terrabase-gru-1", expectValid: true},
		{name: "single character", value: "v", expectValid: true},
		{name: "leading dash", value: "-volume", expectValid: false},
		{name: "trailing dash", value: "volume-", expectValid: false},
		{name: "uppercase", value: "Volume1", expectValid: false},
		{name: "underscore", value: "vol_1", expectValid: false},
		{name: "empty", value: "", expectValid: false},
		{name: "too long", value: strings.Repeat("a", 64), expectValid: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := NewPersistentVolumeId(test.value)
			if test.expectValid {
				if err != nil {
					t.Fatalf("id: %v", err)
				}
				if id.String() != test.value {
					t.Fatalf("id = %q, want %q", id.String(), test.value)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got a valid id")
			}
			if !errorsAsParam(err, "value") {
				t.Fatalf("error %v does not reference param value", err)
			}
		})
	}
}

func TestNewVolumeBinding(t *testing.T) {
	validId := PersistentVolumeId{Value: "terrabase-gru-1"}

	tests := []struct {
		name         string
		volumeId     PersistentVolumeId
		roleKind     string
		allocationId string
		destination  string
		readOnly     bool
		expectParam  string
	}{
		{
			name:         "valid binding",
			volumeId:     validId,
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "/var/lib/terrabase",
			readOnly:     true,
		},
		{
			name:         "zero volume id",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "/var/lib/terrabase",
			expectParam:  "value",
		},
		{
			name:         "uppercase role kind",
			volumeId:     validId,
			roleKind:     "TerraBase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "/var/lib/terrabase",
			expectParam:  "roleKind",
		},
		{
			name:        "empty allocation id",
			volumeId:    validId,
			roleKind:    "terrabase",
			destination: "/var/lib/terrabase",
			expectParam: "allocationId",
		},
		{
			name:         "relative destination",
			volumeId:     validId,
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "var/lib/terrabase",
			expectParam:  "destination",
		},
		{
			name:         "traversal destination",
			volumeId:     validId,
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "/var/lib/../terrabase",
			expectParam:  "destination",
		},
		{
			name:         "root destination",
			volumeId:     validId,
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			destination:  "/",
			expectParam:  "destination",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding, err := NewVolumeBinding(
				test.volumeId, test.roleKind, test.allocationId, test.destination, test.readOnly)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid binding")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("binding: %v", err)
			}
			if binding.VolumeId.Value != test.volumeId.Value || binding.RoleKind != test.roleKind ||
				binding.AllocationId != test.allocationId || binding.Destination != test.destination ||
				binding.ReadOnly != test.readOnly {
				t.Fatalf("binding = %+v", binding)
			}
		})
	}
}

func TestNewReplicaHealth(t *testing.T) {
	tests := []struct {
		name         string
		roleKind     string
		allocationId string
		up           bool
		peerAcks     int
		minReplicas  int
		lagBytes     int64
		expectParam  string
	}{
		{
			name:         "healthy replica",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			up:           true,
			peerAcks:     2,
			minReplicas:  3,
			lagBytes:     1024,
		},
		{
			name:         "down replica",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			up:           false,
			peerAcks:     0,
			minReplicas:  3,
			lagBytes:     0,
		},
		{
			name:         "negative peer acks",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			peerAcks:     -1,
			minReplicas:  3,
			expectParam:  "peerAckCount",
		},
		{
			name:         "zero min replicas",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			minReplicas:  0,
			expectParam:  "minReplicas",
		},
		{
			name:         "negative lag",
			roleKind:     "terrabase",
			allocationId: "terrascale-gru-terrabase-1",
			minReplicas:  3,
			lagBytes:     -1,
			expectParam:  "lagBytes",
		},
		{
			name:         "uppercase role kind",
			roleKind:     "TerraBase",
			allocationId: "terrascale-gru-terrabase-1",
			minReplicas:  3,
			expectParam:  "roleKind",
		},
		{
			name:         "uppercase allocation id",
			roleKind:     "terrabase",
			allocationId: "TerraBase-1",
			minReplicas:  3,
			expectParam:  "allocationId",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replica, err := NewReplicaHealth(
				test.roleKind, test.allocationId, test.up, test.peerAcks,
				test.minReplicas, test.lagBytes)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid replica")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("replica: %v", err)
			}
			if replica.Up != test.up || replica.PeerAckCount != test.peerAcks ||
				replica.MinReplicas != test.minReplicas || replica.LagBytes != test.lagBytes {
				t.Fatalf("replica = %+v", replica)
			}
		})
	}
}

func TestNewNodeDrainCandidateSnapshotsAndRejectsDuplicates(t *testing.T) {
	replicas := []ReplicaHealth{
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", MinReplicas: 3},
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-2", MinReplicas: 3},
	}

	candidate, err := NewNodeDrainCandidate("gru-node-1", replicas)
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	if candidate.NodeId != "gru-node-1" || len(candidate.Replicas) != 2 {
		t.Fatalf("candidate = %+v", candidate)
	}

	replicas[0].AllocationId = "terrascale-gru-terrabase-2"
	if candidate.Replicas[0].AllocationId != "terrascale-gru-terrabase-1" {
		t.Fatal("the replica list must be a snapshot, not an alias")
	}

	duplicate := []ReplicaHealth{
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", MinReplicas: 3},
		{RoleKind: "terrabase", AllocationId: "terrascale-gru-terrabase-1", MinReplicas: 3},
	}
	if _, err := NewNodeDrainCandidate("gru-node-1", duplicate); !errorsAsParam(err, "replicas") {
		t.Fatalf("duplicate replicas must be rejected with param replicas, got %v", err)
	}

	if _, err := NewNodeDrainCandidate("GRU-NODE-1", nil); !errorsAsParam(err, "nodeId") {
		t.Fatalf("invalid node id must be rejected with param nodeId, got %v", err)
	}

	invalidReplica := []ReplicaHealth{{RoleKind: "terrabase", AllocationId: "ok-1", MinReplicas: 0}}
	if _, err := NewNodeDrainCandidate("gru-node-1", invalidReplica); !errorsAsParam(err, "minReplicas") {
		t.Fatalf("invalid replica must surface its own validation error, got %v", err)
	}
}

func TestNewDrainDecision(t *testing.T) {
	tests := []struct {
		name        string
		allowed     bool
		reason      string
		blocking    []string
		expectParam string
	}{
		{
			name:    "allowed drain",
			allowed: true,
			reason:  "all replicas have healthy peer sets on other nodes",
		},
		{
			name:     "blocked drain naming allocations",
			allowed:  false,
			reason:   "terrabase replica would fall below min replicas",
			blocking: []string{"terrascale-gru-terrabase-1"},
		},
		{
			name:        "empty reason",
			reason:      "",
			expectParam: "reason",
		},
		{
			name:        "control character reason",
			reason:      "bad\x00reason",
			expectParam: "reason",
		},
		{
			name:        "oversized reason",
			reason:      strings.Repeat("r", 257),
			expectParam: "reason",
		},
		{
			name:        "allowed drain naming blockers",
			allowed:     true,
			reason:      "allowed",
			blocking:    []string{"terrascale-gru-terrabase-1"},
			expectParam: "blockingAllocationIds",
		},
		{
			name:        "invalid blocking allocation id",
			allowed:     false,
			reason:      "blocked",
			blocking:    []string{"Not A Token"},
			expectParam: "blockingAllocationIds",
		},
		{
			name:        "duplicate blocking allocation ids",
			allowed:     false,
			reason:      "blocked",
			blocking:    []string{"terrascale-gru-terrabase-1", "terrascale-gru-terrabase-1"},
			expectParam: "blockingAllocationIds",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := NewDrainDecision(test.allowed, test.reason, test.blocking)
			if test.expectParam != "" {
				if err == nil {
					t.Fatal("expected an error, got a valid decision")
				}
				if !errorsAsParam(err, test.expectParam) {
					t.Fatalf("error %v does not reference param %q", err, test.expectParam)
				}
				return
			}
			if err != nil {
				t.Fatalf("decision: %v", err)
			}
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %v", decision.Allowed)
			}
			if len(decision.BlockingAllocationIds) != len(test.blocking) {
				t.Fatalf("blocking ids = %v", decision.BlockingAllocationIds)
			}
		})
	}
}
