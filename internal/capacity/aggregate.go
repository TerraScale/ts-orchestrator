package capacity

import (
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostload"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

var resourceMetrics = [...]string{"cpu_usage", "cpu_request", "cpu_limit", "cpu_headroom", "memory_usage", "memory_request", "memory_limit", "memory_headroom"}

type replicaSeries struct {
	Row
	active  []hostload.UsageInterval
	metrics map[string][]observability.Point
}

func windowPoints(points []observability.Point, from, to time.Time) []observability.Point {
	compare := func(a, b observability.Point) int { return a.Time.Compare(b.Time) }
	start, _ := slices.BinarySearchFunc(points, observability.Point{Time: from}, compare)
	end, _ := slices.BinarySearchFunc(points, observability.Point{Time: to}, compare)
	return points[start:end]
}

func summarizeReplica(points []observability.Point, active []hostload.UsageInterval) *Stats {
	var measured []observability.Point
	complete := true
	for _, interval := range active {
		part := windowPoints(points, interval.From.Truncate(time.Millisecond), interval.To.Truncate(time.Millisecond))
		stat := summarize(part, interval.From, interval.To)
		complete = complete && stat != nil && stat.Complete
		measured = append(measured, part...)
	}
	if len(measured) == 0 {
		return nil
	}
	stat := summarize(measured, measured[0].Time, measured[len(measured)-1].Time)
	stat.Complete = complete
	return stat
}

type usageEvent struct {
	at                      time.Time
	value                   float64
	active, known, observed int
	lifecycle               bool
}

// Samples hold until the next sample, for at most the coverage gap. Lifecycle
// boundaries reset that hold; inactive time is zero, unknown active time is null.
func aggregateMetric(replicas []*replicaSeries, metric string, from, to time.Time) *Stats {
	var events []usageEvent
	stat := &Stats{From: from, To: to, Complete: true}
	upperBound := 0.0
	for _, replica := range replicas {
		replicaMax := 0.0
		for _, interval := range replica.active {
			points := windowPoints(replica.metrics[metric], interval.From.Truncate(time.Millisecond), interval.To.Truncate(time.Millisecond))
			if len(points) == 0 {
				return nil
			}
			part := summarize(points, interval.From, interval.To)
			stat.Complete = stat.Complete && part.Complete
			stat.Samples += len(points)
			replicaMax = max(replicaMax, part.Max)
			events = append(events, usageEvent{at: interval.From, active: 1, lifecycle: true}, usageEvent{at: interval.To, active: -1, lifecycle: true})
			if len(points) >= 2 {
				events = append(events, usageEvent{at: points[0].Time, observed: 1}, usageEvent{at: points[len(points)-1].Time, observed: -1})
			}
			gap := min(MaxGap, max(10*time.Second, interval.To.Sub(interval.From)/4))
			for i, point := range points {
				start := point.Time
				if i == 0 && start.Sub(interval.From) <= gap {
					start = interval.From
				}
				end := point.Time.Add(gap)
				if interval.To.Before(end) {
					end = interval.To
				}
				if i+1 < len(points) && points[i+1].Time.Before(end) {
					end = points[i+1].Time
				}
				events = append(events, usageEvent{at: start, value: point.Value, known: 1}, usageEvent{at: end, value: -point.Value, known: -1})
			}
		}
		upperBound += replicaMax
	}
	slices.SortFunc(events, func(a, b usageEvent) int { return a.at.Compare(b.at) })
	active, known, observed := 0, 0, 0
	total, integral := 0.0, 0.0
	previous := from
	together, initialized := false, false
	for i := 0; i < len(events); {
		at := events[i].at
		if previous.Before(at) {
			if known != active {
				return nil
			}
			integral += total * at.Sub(previous).Seconds()
			if !initialized {
				stat.Min, stat.Max, initialized = total, total, true
			} else {
				stat.Min, stat.Max = min(stat.Min, total), max(stat.Max, total)
			}
			together = together || (active > 0 && observed == active)
		}
		end, lifecycle := i, false
		for end < len(events) && events[end].at.Equal(at) {
			lifecycle = lifecycle || events[end].lifecycle
			end++
		}
		if lifecycle {
			// Each concurrently active group needs a positive observed intersection.
			stat.Complete = stat.Complete && (active == 0 || together)
			together = false
		}
		for ; i < end; i++ {
			event := events[i]
			active, known, observed = active+event.active, known+event.known, observed+event.observed
			total += event.value
		}
		if active == 0 {
			total = 0
		}
		previous = at
	}
	if previous.Before(to) {
		stat.Min = min(stat.Min, 0)
	}
	stat.Mean = integral / to.Sub(from).Seconds()
	stat.MaxUpperBound = &upperBound
	return stat
}

func setStats(row *Row, metric string, stat *Stats) {
	switch metric {
	case "cpu_usage":
		row.CPU.Usage = stat
	case "cpu_request":
		row.CPU.Request = stat
	case "cpu_limit":
		row.CPU.Limit = stat
	case "cpu_headroom":
		row.CPU.Headroom = stat
	case "memory_usage":
		row.Memory.Usage = stat
	case "memory_request":
		row.Memory.Request = stat
	case "memory_limit":
		row.Memory.Limit = stat
	case "memory_headroom":
		row.Memory.Headroom = stat
	}
}
