package placement

import (
	"reflect"
	"testing"
)

var testRequest = Resources{CPU: 2, MemoryBytes: 2 << 30, DiskBytes: 10 << 30}

func TestPlanWorkloadSpreadsDeterministicallyAndBalancesCapacity(t *testing.T) {
	hosts := []WorkloadHost{
		workloadHost("node-d", "fd-c", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-c", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{CPU: 4}),
		workloadHost("node-b", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
	}
	request := WorkloadRequest{Cell: "gru", Role: "ts-auth", Replicas: 3, Request: testRequest, Hosts: hosts}

	first, err := PlanWorkload(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PlanWorkload(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("plan changed between identical snapshots: %#v != %#v", first, second)
	}
	wantNodes := []string{"node-a", "node-b", "node-d"}
	for index, assignment := range first {
		if assignment.Node != wantNodes[index] || assignment.Ordinal != index || assignment.Withdrawn {
			t.Fatalf("assignment %d = %#v, want node %q at ordinal %d", index, assignment, wantNodes[index], index)
		}
	}
}

func workloadHost(node, domain string, capacity, allocated Resources) WorkloadHost {
	return WorkloadHost{
		Cell:           "gru",
		Node:           node,
		FailureDomain:  domain,
		Roles:          []string{"ts-auth"},
		Capacity:       capacity,
		Allocated:      allocated,
		CurrentSession: true,
		Admitted:       true,
		Healthy:        true,
	}
}
