package capacity

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

func TestCommittedUsageReplayPreservesHistoricalResourcesAndUnknownGaps(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Second)
	first := end.Add(-40 * time.Second).Add(500 * time.Microsecond)
	second := first.Add(10 * time.Second)
	origin := hostload.Origin{Cell: "gru", Node: "host-a", Environment: "production"}
	cpu, memory := 0.5, int64(512)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPUCores: 4, MemoryBytes: 8192},
		Roles: []hostload.RoleUsage{{Role: "api", CPUCores: &cpu, MemoryBytes: &memory}}}
	for restart := range 2 {
		store := NewStore("gru")
		for index, at := range []time.Time{first, second} {
			requests := map[string]hostload.Request{"api": {CPUCores: float64(index + 1), MemoryBytes: int64(index+1) * 1024}}
			if err := store.RecordCommitted(at, origin, report, requests); err != nil {
				t.Fatal(err)
			}
		}
		from, to := first.Truncate(time.Millisecond), second.Add(time.Second)
		unknown := []hostload.UsageInterval{{Node: origin.Node, Environment: origin.Environment, From: from, To: to, Unknown: "retained manager history was truncated", Truncated: true}}
		result, err := store.Query(from, to, unknown)
		if err != nil || result.Complete || !result.Truncated || len(result.Gaps) != 1 || len(result.Replicas) != 1 {
			t.Fatalf("restart%d erased unknown coverage or samples: %+v %v", restart, result, err)
		}
		request := result.Replicas[0].CPU.Request
		if request == nil || request.Complete || request.Samples != 2 || request.Min != 1 || request.Max != 2 || request.Mean != 1.5 || !request.From.Equal(first.Truncate(time.Millisecond)) || !request.To.Equal(second.Truncate(time.Millisecond)) {
			t.Fatalf("restart%d rewrote journal receive times or old requests: %+v", restart, request)
		}
		if len(result.Services) != 1 || result.Services[0].CPU.Request != nil {
			t.Fatalf("unknown allocation span became a service total: %+v", result.Services)
		}
		if err := store.RecordCommitted(first, origin, report, nil); err == nil {
			t.Fatal("out-of-order committed sample replaced retained resources")
		}
	}
}
