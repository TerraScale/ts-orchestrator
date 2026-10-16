package capacity

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestServiceCoverageRequiresAnOverlappingRange(t *testing.T) {
	from := time.Now().UTC().Add(-time.Minute)
	to := from.Add(15 * time.Second)
	a := []observability.Point{{Time: from, Value: 1, Min: 1, Max: 1}, {Time: from.Add(5 * time.Second), Value: 1, Min: 1, Max: 1}}
	for _, offset := range []time.Duration{4, 5, 6} {
		b := []observability.Point{{Time: from.Add(offset * time.Second), Value: 2, Min: 2, Max: 2}, {Time: from.Add((offset + 5) * time.Second), Value: 2, Min: 2, Max: 2}}
		replicas := []*replicaSeries{
			{active: []hostload.UsageInterval{{From: from, To: to}}, metrics: map[string][]observability.Point{"cpu_usage": a}},
			{active: []hostload.UsageInterval{{From: from, To: to}}, metrics: map[string][]observability.Point{"cpu_usage": b}},
		}
		total := aggregateMetric(replicas, "cpu_usage", from, to)
		if total == nil || total.Complete != (offset == 4) || total.Mean != 3 {
			t.Fatalf("offset %s: aggregate coverage = %+v", offset*time.Second, total)
		}
	}
}

func TestIncompleteServiceCoverageMakesUsageIncomplete(t *testing.T) {
	s := NewStore("gru")
	from := time.Now().UTC().Truncate(5 * time.Second).Add(-time.Minute)
	to := from.Add(15 * time.Second)
	for _, node := range []string{"a", "b"} {
		offset := 0
		if node == "b" {
			offset = 6
		}
		for _, second := range []int{offset, offset + 5} {
			appendResourceSample(s, from.Add(time.Duration(second)*time.Second), node, 3)
		}
	}
	usage, err := s.Query(from, to, fullWindowInventory(from, to, "", "a", "b", "a/api", "b/api"))
	if err != nil || len(usage.Services) != 1 || usage.Complete || rowComplete(usage.Services[0]) {
		t.Fatalf("non-overlapping service coverage claimed complete: %+v %v", usage, err)
	}
	for _, replica := range usage.Replicas {
		if !rowComplete(replica) {
			t.Fatalf("individual replica should cover the short window: %+v", replica)
		}
	}
}

func TestMeasurementQueryExcludesBoundarySampleSpikes(t *testing.T) {
	s := NewStore("gru")
	base := time.Now().UTC().Truncate(5 * time.Second).Add(-time.Minute)
	appendResourceSample(s, base.Add(500*time.Millisecond), "a", 0.01)
	appendResourceSample(s, base.Add(2*time.Second), "a", 3)
	for second := 5; second <= 30; second += 5 {
		appendResourceSample(s, base.Add(time.Duration(second)*time.Second), "a", 3)
	}
	appendResourceSample(s, base.Add(32*time.Second), "a", 0.01)
	usage, err := s.Query(base.Add(time.Second), base.Add(31*time.Second), fullWindowInventory(base.Add(time.Second), base.Add(31*time.Second), "", "a", "a/api"))
	if err != nil || !usage.Complete || len(usage.Nodes) != 1 || usage.Nodes[0].CPU.Headroom.Min != 3 || usage.Replicas[0].CPU.Headroom.Min != 3 {
		t.Fatalf("warmup/cleanup samples contaminated measurement headroom: %+v %v", usage, err)
	}
}

func appendResourceSample(s *Store, at time.Time, node string, headroom float64) {
	var samples []observability.Sample
	for _, service := range []string{"", "api"} {
		for metric, value := range map[string]float64{"cpu_usage": 1, "cpu_request": 2, "cpu_limit": 4, "cpu_headroom": headroom, "memory_usage": 100, "memory_request": 200, "memory_limit": 400, "memory_headroom": 300} {
			samples = append(samples, observability.Sample{Metric: "capacity_" + metric, Labels: observability.L("node", node, "service", service), Value: value})
		}
	}
	s.History.Append(at, samples)
}
