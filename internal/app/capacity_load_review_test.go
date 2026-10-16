package app

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

func TestCapacityLimitDoesNotRejectAutoscalerReports(t *testing.T) {
	now := time.Now()
	load := hostload.NewAggregator(hostload.AggregatorConfig{Now: func() time.Time { return now }})
	telemetry := &runtimeObservability{usage: capacity.NewStore("gru")}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192}}
	for node := range 257 {
		origin := hostload.Origin{Cell: "gru", Node: fmt.Sprintf("node-%d", node)}
		if err := telemetry.recordHostLoad(load.Record, origin, report, nil); err != nil {
			t.Fatalf("optional history rejected autoscaler node %d: %v", node, err)
		}
	}
	now = now.Add(10 * time.Second)
	origin := hostload.Origin{Cell: "gru", Node: "node-256"}
	if err := telemetry.recordHostLoad(load.Record, origin, report, nil); err != nil {
		t.Fatal(err)
	}
	if len(load.Nodes()) != 257 {
		t.Fatal("autoscaler lost nodes beyond capacity history's limit")
	}
	found := false
	for _, node := range load.Nodes() {
		if node.Origin.Node == origin.Node {
			found = node.At.Equal(now)
		}
	}
	if !found {
		t.Fatal("overflowing host stopped refreshing autoscaler telemetry")
	}
	if err := telemetry.recordHostLoad(nil, origin, report, nil); err == nil {
		t.Fatal("standalone capacity rejection was hidden")
	}
}

func TestCapacityStillRecordsWhenAutoscalerRejects(t *testing.T) {
	load := hostload.NewAggregator(hostload.AggregatorConfig{})
	telemetry := &runtimeObservability{usage: capacity.NewStore("gru")}
	origin := hostload.Origin{Cell: "gru", Node: "node"}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192}}
	if err := load.Record(origin, report); err != nil {
		t.Fatal(err)
	}
	if err := telemetry.recordHostLoad(load.Record, origin, report, nil); !errors.Is(err, hostload.ErrTooFrequent) {
		t.Fatalf("autoscaler rejection was hidden: %v", err)
	}
	if telemetry.usage.History.Stats().Series == 0 {
		t.Fatal("autoscaler rejection gated capacity history")
	}
}

func TestFencedTelemetryCannotEnterCapacityHistory(t *testing.T) {
	telemetry := &runtimeObservability{usage: capacity.NewStore("gru")}
	load := &hostTelemetry{load: hostload.NewAggregator(hostload.AggregatorConfig{}), fencer: &fenceLease{lost: true}}
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192}}
	if err := telemetry.recordHostLoad(load.record, hostload.Origin{Cell: "gru", Node: "node"}, report, nil); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("demoted collector report was accepted: %v", err)
	}
	if telemetry.usage.History.Stats().Series != 0 {
		t.Fatal("demoted collector fed capacity history")
	}
}
