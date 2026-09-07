package hostagent

import (
	"encoding/json"
	"testing"
)

func TestHeadroomFactsRoundTripAndFailClosed(t *testing.T) {
	report, err := NewNodeStatusReport("status-1", "gru-1", NodeStateServing, false, HostFacts{
		Metrics: HostMetrics{
			CapacityMeasured:      true,
			CPUCount:              4,
			CPUBudgetMilli:        3500,
			AvailableMemoryBytes:  2 << 30,
			AvailableStorageBytes: 8 << 30,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded NodeStatusReport
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Facts.Metrics.HeadroomValid() {
		t.Fatalf("decoded measured headroom is invalid: %+v", decoded.Facts.Metrics)
	}

	decoded.Facts.Metrics.AvailableStorageBytes = 0
	if decoded.Facts.Metrics.HeadroomValid() {
		t.Fatal("tampered storage margin remained admissible")
	}
	var absent NodeStatusReport
	if err := json.Unmarshal([]byte(`{"commandId":"status-1","nodeId":"gru-1","state":"serving","facts":{}}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.Facts.Metrics.HeadroomValid() {
		t.Fatal("absent headroom remained admissible")
	}
}

func TestReadCPUCapacityUsesCgroupProbe(t *testing.T) {
	count, budget, err := readCPUCapacity()
	if err != nil {
		t.Skipf("test host has no readable cgroup v2 cpu budget: %v", err)
	}
	if count <= 0 || budget <= 0 {
		t.Fatalf("invalid measured cpu capacity: count=%d budget=%d", count, budget)
	}
}
