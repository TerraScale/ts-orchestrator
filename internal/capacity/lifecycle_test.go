package capacity

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestServiceTotalsFollowReplicaLifetimes(t *testing.T) {
	for _, test := range []struct {
		name                string
		lifetimes           [][3]int // node index, start, end seconds
		mean, minimum, peak float64
		bound               float64
	}{
		{"replacement", [][3]int{{0, 0, 30}, {1, 30, 60}}, 1, 1, 1, 2},
		{"staggered start", [][3]int{{0, 0, 60}, {1, 30, 60}}, 1.5, 1, 2, 2},
		{"inactive gap", [][3]int{{0, 0, 20}, {1, 40, 60}}, 2.0 / 3, 0, 1, 2},
		{"reactivation", [][3]int{{0, 0, 20}, {0, 40, 60}}, 2.0 / 3, 0, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := NewStore("gru")
			from := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
			to := from.Add(time.Minute)
			var expected []hostload.UsageInterval
			for _, lifetime := range test.lifetimes {
				node := []string{"a", "b"}[lifetime[0]]
				start, end := from.Add(time.Duration(lifetime[1])*time.Second), from.Add(time.Duration(lifetime[2])*time.Second)
				expected = append(expected, fullWindowInventory(start, end, "", node, node+"/api")...)
			}
			// Delayed reports from outside an identity's active lifetime must be ignored.
			for _, node := range []string{"a", "b"} {
				for at := from; at.Before(to); at = at.Add(5 * time.Second) {
					value := 100.0
					for _, interval := range expected {
						if interval.Node == node && !at.Before(interval.From) && at.Before(interval.To) {
							value = 1
						}
					}
					appendUsageSample(s, at, node, value)
				}
			}
			usage, err := s.Query(from, to, expected)
			if err != nil || !usage.Complete || len(usage.Services) != 1 {
				t.Fatalf("active lifetimes were not covered: %+v %v", usage, err)
			}
			row := usage.Services[0]
			for _, check := range []struct {
				stat       *Stats
				multiplier float64
			}{
				{row.CPU.Usage, 1}, {row.CPU.Request, 2}, {row.CPU.Limit, 4}, {row.CPU.Headroom, 3},
				{row.Memory.Usage, 100}, {row.Memory.Request, 200}, {row.Memory.Limit, 400}, {row.Memory.Headroom, 300},
			} {
				stat, scale := check.stat, check.multiplier
				if stat == nil || math.Abs(stat.Mean-test.mean*scale) > 1e-9 || stat.Min != test.minimum*scale || stat.Max != test.peak*scale || stat.MaxUpperBound == nil || *stat.MaxUpperBound != test.bound*scale {
					t.Fatalf("misaligned service statistics: %+v, scale %g", stat, scale)
				}
			}
			if test.name == "replacement" {
				var table bytes.Buffer
				if err := WriteTable(&table, usage); err != nil || !strings.Contains(table.String(), "1.00 / 2.00 / 4.00 / 3.00") {
					t.Fatalf("table doubled replacement capacity: %s %v", table.String(), err)
				}
			}
		})
	}
}

func TestServiceStatisticsAlignUnequalCadencesAndSeparatePeakBounds(t *testing.T) {
	s := NewStore("gru")
	from := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	to := from.Add(30 * time.Second)
	for _, node := range []string{"a", "b"} {
		seconds := []int{0, 5, 10, 20, 25}
		if node == "b" {
			seconds = []int{0, 5, 10, 15, 20, 25}
		}
		for _, second := range seconds {
			value := 1.0
			if second >= 10 && second < 20 {
				value = 3
			}
			if node == "b" {
				value = 4 - value
			}
			appendUsageSample(s, from.Add(time.Duration(second)*time.Second), node, value)
		}
	}
	usage, err := s.Query(from, to, fullWindowInventory(from, to, "", "a", "a/api", "b", "b/api"))
	if err != nil || !usage.Complete {
		t.Fatalf("cadence fixture incomplete: %+v %v", usage, err)
	}
	row := usage.Services[0]
	if row.CPU.Usage.Mean != 4 || row.CPU.Usage.Min != 4 || row.CPU.Usage.Max != 4 || *row.CPU.Usage.MaxUpperBound != 6 || row.CPU.Headroom.Min != 4 {
		t.Fatalf("replica peaks were treated as simultaneous: %+v", row.CPU)
	}
}

func TestMissingActiveServiceMeasurementsRemainUnknown(t *testing.T) {
	for _, missing := range []string{"replica", "interior gap"} {
		t.Run(missing, func(t *testing.T) {
			s := NewStore("gru")
			from := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Minute)
			to := from.Add(time.Minute)
			for _, node := range []string{"a", "b"} {
				for second := 0; second < 60; second += 5 {
					if node == "b" && (missing == "replica" || (second >= 20 && second < 45)) {
						continue
					}
					appendUsageSample(s, from.Add(time.Duration(second)*time.Second), node, 1)
				}
			}
			usage, err := s.Query(from, to, fullWindowInventory(from, to, "", "a", "a/api", "b", "b/api"))
			if err != nil || usage.Complete || len(usage.Services) != 1 || usage.Services[0].CPU.Usage != nil || usage.Services[0].CPU.Headroom != nil {
				t.Fatalf("unknown active telemetry became a numeric total: %+v %v", usage, err)
			}
			var table bytes.Buffer
			if err := WriteTable(&table, usage); err != nil || !strings.Contains(table.String(), "? / ? / ? / ?") {
				t.Fatalf("unknown totals disappeared from table: %s %v", table.String(), err)
			}
		})
	}
}

func appendUsageSample(s *Store, at time.Time, node string, usage float64) {
	var samples []observability.Sample
	for _, service := range []string{"", "api"} {
		for metric, value := range map[string]float64{"cpu_usage": usage, "cpu_request": 2, "cpu_limit": 4, "cpu_headroom": max(0, 4-usage), "memory_usage": 100 * usage, "memory_request": 200, "memory_limit": 400, "memory_headroom": max(0, 400-100*usage)} {
			samples = append(samples, observability.Sample{Metric: "capacity_" + metric, Labels: observability.L("node", node, "service", service), Value: value})
		}
	}
	s.History.Append(at, samples)
}
