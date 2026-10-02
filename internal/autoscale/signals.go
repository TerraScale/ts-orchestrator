package autoscale

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"
)

// Target names the service a signal describes.
type Target struct {
	Cell        string
	Environment string
	Role        string
}

// Source produces one aggregated reading for a signal at now. A source that
// has no data returns a zero-sample reading rather than an error; errors are
// reserved for transport or authorization failures.
type Source interface {
	Read(ctx context.Context, target Target, signal Signal, now time.Time) (Reading, error)
}

// Collect reads every policy signal. Failed reads become unavailable signals,
// which can block a scale-down but never force a scale-up.
func Collect(ctx context.Context, source Source, target Target, policy Policy, now time.Time) []Reading {
	if source == nil {
		return nil
	}
	readings := make([]Reading, 0, len(policy.Signals))
	for _, signal := range policy.Signals {
		reading, err := source.Read(ctx, target, signal, now)
		if err != nil {
			continue
		}
		reading.Signal = signal.Name
		readings = append(readings, reading)
	}
	return readings
}

// Sample is one per-replica measurement.
type Sample struct {
	At    time.Time
	Value float64
}

type seriesKey struct {
	target Target
	signal SignalName
}

// WindowStore is an in-memory bounded sample store implementing Source. A
// telemetry consumer records samples and the autoscaler reads windowed
// aggregates. Samples older than retention are discarded on write.
type WindowStore struct {
	mu        sync.Mutex
	retention time.Duration
	maxPoints int
	series    map[seriesKey][]Sample
}

// NewWindowStore bounds every series by age and by point count.
func NewWindowStore(retention time.Duration, maxPoints int) *WindowStore {
	if retention <= 0 {
		retention = 15 * time.Minute
	}
	if maxPoints <= 0 {
		maxPoints = 4096
	}
	return &WindowStore{retention: retention, maxPoints: maxPoints, series: make(map[seriesKey][]Sample)}
}

// Record appends one sample. Non-finite or negative values are dropped.
func (s *WindowStore) Record(target Target, signal SignalName, sample Sample) {
	if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 || sample.At.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := seriesKey{target: target, signal: signal}
	points := append(s.series[key], sample)
	points = slices.DeleteFunc(points, func(p Sample) bool { return sample.At.Sub(p.At) > s.retention })
	if len(points) > s.maxPoints {
		points = slices.Clone(points[len(points)-s.maxPoints:])
	}
	s.series[key] = points
}

// Read aggregates the samples inside the signal window ending at now.
func (s *WindowStore) Read(_ context.Context, target Target, signal Signal, now time.Time) (Reading, error) {
	s.mu.Lock()
	var values []float64
	for _, point := range s.series[seriesKey{target: target, signal: signal.Name}] {
		if !point.At.After(now) && now.Sub(point.At) <= signal.Window() {
			values = append(values, point.Value)
		}
	}
	s.mu.Unlock()
	return Reading{Signal: signal.Name, Value: Aggregate(signal.AggregationOrDefault(), values), Samples: len(values)}, nil
}

// Aggregate reduces values; an empty input yields zero.
func Aggregate(aggregation Aggregation, values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	switch aggregation {
	case AggregateMax:
		return slices.Max(values)
	case AggregateP95:
		sorted := slices.Clone(values)
		slices.Sort(sorted)
		index := int(math.Ceil(0.95*float64(len(sorted)))) - 1
		return sorted[max(index, 0)]
	default:
		sum := 0.0
		for _, value := range values {
			sum += value
		}
		return sum / float64(len(values))
	}
}
