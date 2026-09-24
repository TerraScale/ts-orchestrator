package placement

import (
	"errors"
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

func TestPlanWorkloadKeepsHealthyAndPendingAssignmentsAndWithdrawsFailedOnes(t *testing.T) {
	hosts := []WorkloadHost{
		workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-b", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-c", "fd-c", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
	}
	previous := []Assignment{
		{Node: "node-b", Role: "ts-auth", Ordinal: 1, Pending: true},
		{Node: "node-a", Role: "ts-auth", Ordinal: 0, Ready: true},
		{Node: "node-c", Role: "ts-auth", Ordinal: 2},
	}

	plan, err := PlanReplicas("gru", "ts-auth", 2, testRequest, hosts, previous)
	if err != nil {
		t.Fatal(err)
	}
	want := []Assignment{
		{Node: "node-a", Role: "ts-auth", Ordinal: 0, Ready: true},
		{Node: "node-b", Role: "ts-auth", Ordinal: 1, Pending: true},
		{Node: "node-c", Role: "ts-auth", Ordinal: 2, Withdrawn: true},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %#v, want %#v", plan, want)
	}
}

func TestPlanWorkloadReplacesFailedAssignmentOnAnotherNode(t *testing.T) {
	hosts := []WorkloadHost{
		workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-b", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
	}
	previous := []Assignment{{Node: "node-a", Role: "ts-auth", Ordinal: 0}}

	plan, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest, Hosts: hosts, Previous: previous,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Node != "node-b" || !plan[0].Pending || !plan[1].Withdrawn || plan[1].Node != "node-a" {
		t.Fatalf("failed assignment was not replaced and withdrawn: %#v", plan)
	}
}

func TestPlanWorkloadExcludesStaleCordonedAndUnderCapacityHosts(t *testing.T) {
	stale := workloadHost("stale", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})
	stale.CurrentSession = false
	cordoned := workloadHost("cordoned", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})
	cordoned.Cordoned = true
	tooSmall := workloadHost("small", "fd-c", Resources{CPU: 8, MemoryBytes: 1 << 30, DiskBytes: 100 << 30}, Resources{})
	healthy := workloadHost("healthy", "fd-d", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})

	plan, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest,
		Hosts: []WorkloadHost{stale, cordoned, tooSmall, healthy},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Node != "healthy" {
		t.Fatalf("plan = %#v, want only healthy eligible host", plan)
	}
}

func TestPlanWorkloadAccountsForOtherExistingWorkloads(t *testing.T) {
	busyCPU := workloadHost("busy-cpu", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{CPU: 7})
	busyMemory := workloadHost("busy-memory", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{MemoryBytes: 15 << 30})
	busyDisk := workloadHost("busy-disk", "fd-c", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{DiskBytes: 95 << 30})
	free := workloadHost("free", "fd-d", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})

	plan, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest,
		Hosts: []WorkloadHost{busyCPU, busyMemory, busyDisk, free},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0].Node != "free" {
		t.Fatalf("plan = %#v, want free host after resource accounting", plan)
	}
}

func TestPlanWorkloadRejectsOvercapacityWithoutPartialAssignments(t *testing.T) {
	hosts := []WorkloadHost{
		workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
		workloadHost("node-b", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{}),
	}

	plan, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 3, Request: testRequest, Hosts: hosts,
	})
	if !errors.Is(err, ErrInsufficientCapacity) {
		t.Fatalf("error = %v, want ErrInsufficientCapacity", err)
	}
	if len(plan) != 0 {
		t.Fatalf("partial plan escaped capacity failure: %#v", plan)
	}
}

func TestPlanWorkloadWithdrawsAllAssignmentsWhenTargetIsZero(t *testing.T) {
	previous := []Assignment{
		{Node: "node-a", Role: "ts-auth", Ordinal: 0, Ready: true},
		{Node: "node-b", Role: "ts-auth", Ordinal: 1, Pending: true},
	}
	plan, err := PlanReplicas("gru", "ts-auth", 0, testRequest, nil, previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Node != "node-a" || !plan[0].Withdrawn || plan[1].Node != "node-b" || !plan[1].Withdrawn {
		t.Fatalf("plan = %#v, want sorted withdrawals", plan)
	}
}

func TestPlanWorkloadRejectsInvalidResourceRequestAndDuplicateAssignments(t *testing.T) {
	validHost := workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})
	_, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: Resources{CPU: 1}, Hosts: []WorkloadHost{validHost},
	})
	if !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("invalid resource request error = %v, want ErrInvalidWorkload", err)
	}

	_, err = PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest,
		Hosts: []WorkloadHost{validHost, validHost},
	})
	if !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("duplicate host error = %v, want ErrInvalidWorkload", err)
	}

	_, err = PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest,
		Hosts: []WorkloadHost{validHost},
		Previous: []Assignment{
			{Node: "node-a", Role: "ts-auth", Ordinal: 0, Ready: true},
			{Node: "node-a", Role: "ts-auth", Ordinal: 1, Ready: true},
		},
	})
	if !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("duplicate assignment error = %v, want ErrInvalidWorkload", err)
	}
}

func TestPlanWorkloadDoesNotKeepReadyAssignmentAfterCapacityShrinks(t *testing.T) {
	host := workloadHost("node-a", "fd-a", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{CPU: 7})
	previous := []Assignment{{Node: "node-a", Role: "ts-auth", Ordinal: 0, Ready: true}}

	plan, err := PlanWorkload(WorkloadRequest{
		Cell: "gru", Role: "ts-auth", Replicas: 1, Request: testRequest,
		Hosts:    []WorkloadHost{host, workloadHost("node-b", "fd-b", Resources{CPU: 8, MemoryBytes: 16 << 30, DiskBytes: 100 << 30}, Resources{})},
		Previous: previous,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 || plan[0].Node != "node-b" || !plan[1].Withdrawn || plan[1].Node != "node-a" {
		t.Fatalf("capacity-shrunk assignment was retained: %#v", plan)
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
