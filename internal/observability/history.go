package observability

import (
	"cmp"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

// History tiers. Raw samples are kept for an hour, one-minute rollups for
// six hours, five-minute rollups for a day and hourly rollups for 14 days.
// A range query reads the finest tier that still covers its start.
const (
	TierRaw = "raw"
	Tier1m  = "1m"
	Tier5m  = "5m"
	Tier1h  = "1h"

	DefaultHistoryInterval = 10 * time.Second
	DefaultHistorySeries   = 4096
	rawRetention           = time.Hour
	oneMinuteRetention     = 6 * time.Hour
	fiveMinuteRetention    = 24 * time.Hour
	// HistoryRetention is the oldest metric data retained for queries.
	HistoryRetention = 14 * 24 * time.Hour
)

// Label is one metric label pair.
type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Sample is one observation of one series.
type Sample struct {
	Metric string
	Labels []Label
	Value  float64
	// Counter marks a cumulative value; range queries may then ask for
	// its per-second rate.
	Counter bool
}

// L builds a label list from name, value pairs.
func L(pairs ...string) []Label {
	labels := make([]Label, 0, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		labels = append(labels, Label{Name: pairs[index], Value: pairs[index+1]})
	}
	return labels
}

// Point is one value of a series at a time. Min and Max are the range of the
// raw samples a rollup covers; for a raw point they equal Value.
type Point struct {
	Time  time.Time `json:"t"`
	Value float64   `json:"v"`
	Min   float64   `json:"min"`
	Max   float64   `json:"max"`
	// Samples lets in-process charts detect omitted observations within a bucket.
	Samples uint32 `json:"-"`
}

// bucket accumulates the samples of one tier step.
type bucket struct {
	Start int64   `json:"t"` // unix milliseconds of the step start
	Sum   float64 `json:"s"`
	Min   float64 `json:"n"`
	Max   float64 `json:"x"`
	Last  float64 `json:"l"`
	Count uint32  `json:"c"`
	// LastAt is when Last was sampled (unix milliseconds); rates divide by
	// the time between the samples that supplied Last, not by the bucket
	// starts. Zero in snapshots taken before it existed.
	LastAt int64 `json:"a,omitempty"`
	// Increase is a counter's reset-correct growth from the series' sample
	// before this bucket to Last, accumulated per raw sample when it is
	// ingested; Increased marks it as tracked. Downsampling keeps only the
	// bucket's Last, so a reset and recovery inside one bucket would
	// otherwise look like less growth than happened.
	Increase  float64 `json:"i,omitempty"`
	Increased bool    `json:"ii,omitempty"`
}

func (b *bucket) add(at int64, value float64, increase float64, counted bool) {
	if b.Count == 0 {
		b.Min, b.Max = value, value
	} else {
		b.Min, b.Max = min(b.Min, value), max(b.Max, value)
	}
	b.Sum += value
	b.Last, b.LastAt = value, at
	b.Count++
	if counted {
		b.Increase += increase
		b.Increased = true
	}
}

// lastAt is when the bucket's Last was sampled, or its start when unknown.
func (b bucket) lastAt() int64 {
	if b.LastAt != 0 {
		return b.LastAt
	}
	return b.Start
}

// tier is a ring of closed buckets and the bucket being filled.
type tier struct {
	step   time.Duration // zero keeps every sample
	ring   []bucket
	start  int
	size   int
	open   bucket
	opened bool
}

func newTier(step, retention, interval time.Duration) *tier {
	capacity := int(retention / interval)
	if step > 0 {
		capacity = int(retention / step)
	}
	return &tier{step: step, ring: make([]bucket, max(capacity, 1))}
}

func (t *tier) push(b bucket) {
	index := (t.start + t.size) % len(t.ring)
	if t.size == len(t.ring) {
		t.start = (t.start + 1) % len(t.ring)
	} else {
		t.size++
	}
	t.ring[index] = b
}

func (t *tier) add(at int64, value float64, increase float64, counted bool) {
	if t.step == 0 {
		b := bucket{Start: at}
		b.add(at, value, increase, counted)
		t.push(b)
		return
	}
	stepMillis := t.step.Milliseconds()
	aligned := at - at%stepMillis
	if t.opened && aligned != t.open.Start {
		if aligned < t.open.Start {
			return // out of order; ignore
		}
		t.push(t.open)
		t.opened = false
	}
	if !t.opened {
		t.open = bucket{Start: aligned}
		t.opened = true
	}
	t.open.add(at, value, increase, counted)
}

// oldest returns the last sample time in the tier's oldest bucket.
func (t *tier) oldest() (int64, bool) {
	switch {
	case t.size > 0:
		return t.ring[t.start].lastAt(), true
	case t.opened:
		return t.open.lastAt(), true
	default:
		return 0, false
	}
}

// buckets returns closed buckets plus the open one, oldest first.
func (t *tier) buckets() []bucket {
	out := make([]bucket, 0, t.size+1)
	for offset := range t.size {
		out = append(out, t.ring[(t.start+offset)%len(t.ring)])
	}
	if t.opened {
		out = append(out, t.open)
	}
	return out
}

type series struct {
	metric  string
	labels  []Label
	counter bool
	last    int64
	// lastValue is the newest raw sample, the baseline of a counter's next
	// increase; sampled reports that there is one.
	lastValue float64
	sampled   bool
	tiers     map[string]*tier
}

// HistoryConfig sizes a History.
type HistoryConfig struct {
	// Interval is the expected sampling interval; it sizes the raw tier.
	Interval time.Duration
	// MaxSeries bounds distinct series; new series beyond it are dropped
	// and counted.
	MaxSeries int
	// StaleAfter releases slots for series that stopped reporting.
	// Zero uses the full history retention.
	StaleAfter time.Duration
}

// History is a bounded in-memory time-series store of key metrics with
// raw -> 1m -> 5m -> 1h downsampling over 14 days. It is safe for concurrent
// use; Append and Range never perform I/O.
type History struct {
	config       HistoryConfig
	mu           sync.RWMutex
	series       map[string]*series
	dropped      uint64
	dropMinutes  map[int64]bool
	newestMinute int64
}

// NewHistory returns an empty store.
func NewHistory(config HistoryConfig) *History {
	if config.Interval <= 0 {
		config.Interval = DefaultHistoryInterval
	}
	if config.MaxSeries <= 0 {
		config.MaxSeries = DefaultHistorySeries
	}
	if config.StaleAfter <= 0 {
		config.StaleAfter = HistoryRetention
	}
	return &History{config: config, series: map[string]*series{}, dropMinutes: map[int64]bool{}}
}

// HistoryMetrics is the history store's metric set.
var HistoryMetrics = metrics.NewSet()

var (
	historyDropped = HistoryMetrics.NewCounter(MetricPrefix + "history_series_dropped_total")
	historySamples = HistoryMetrics.NewCounter(MetricPrefix + "history_samples_total")
)

func seriesKey(metric string, labels []Label) string {
	pairs := make([]string, 0, len(labels)*2)
	for _, label := range labels {
		pairs = append(pairs, label.Name, label.Value)
	}
	return Series(metric, pairs...)
}

func sortedLabels(labels []Label) []Label {
	labels = slices.Clone(labels)
	slices.SortFunc(labels, func(left, right Label) int { return cmp.Compare(left.Name, right.Name) })
	return labels
}

func (history *History) newSeries(metric string, labels []Label, counter bool) *series {
	interval := history.config.Interval
	return &series{metric: metric, labels: labels, counter: counter, tiers: map[string]*tier{
		TierRaw: newTier(0, rawRetention, interval),
		Tier1m:  newTier(time.Minute, oneMinuteRetention, interval),
		Tier5m:  newTier(5*time.Minute, fiveMinuteRetention, interval),
		Tier1h:  newTier(time.Hour, HistoryRetention, interval),
	}}
}

// Append stores one batch of samples taken at the same time. NaN and
// infinite values are skipped.
func (history *History) Append(at time.Time, samples []Sample) {
	millis := at.UnixMilli()
	history.mu.Lock()
	defer history.mu.Unlock()
	minute := millis / time.Minute.Milliseconds()
	history.newestMinute = max(history.newestMinute, minute)
	oldestMinute := history.newestMinute - int64(rawRetention/time.Minute)
	for at := range history.dropMinutes {
		if at < oldestMinute {
			delete(history.dropMinutes, at)
		}
	}
	// Prune first, so series that stopped reporting free their slots.
	stale := millis - history.config.StaleAfter.Milliseconds()
	for key, current := range history.series {
		if current.last < stale {
			delete(history.series, key)
		}
	}
	for _, sample := range samples {
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Metric == "" {
			continue
		}
		labels := sortedLabels(sample.Labels)
		key := seriesKey(sample.Metric, labels)
		current, ok := history.series[key]
		if !ok {
			if len(history.series) >= history.config.MaxSeries {
				history.dropped++
				if minute >= oldestMinute {
					history.dropMinutes[minute] = true
				}
				historyDropped.Inc()
				continue
			}
			current = history.newSeries(sample.Metric, labels, sample.Counter)
			history.series[key] = current
		}
		if millis < current.last {
			continue
		}
		// A counter's growth since its previous raw sample, reset-correct:
		// a decrease is a restart that counted again from zero.
		increase, counted := 0.0, false
		if current.counter && current.sampled {
			increase, counted = sample.Value-current.lastValue, true
			if increase < 0 {
				increase = sample.Value
			}
		}
		current.last, current.lastValue, current.sampled = millis, sample.Value, true
		for _, name := range []string{TierRaw, Tier1m, Tier5m, Tier1h} {
			current.tiers[name].add(millis, sample.Value, increase, counted)
		}
		historySamples.Inc()
	}
}

// HistoryQuery selects series and a time range.
type HistoryQuery struct {
	Metric string
	// Labels must all match; an empty value matches any value of the
	// label as long as the series has it.
	Labels map[string]string
	Start  time.Time
	End    time.Time
	// Tier forces a tier; empty picks the finest tier covering Start.
	Tier string
	// Rate turns a counter into its per-second rate between points.
	Rate bool
	// MaxSeries bounds the result; zero means 64.
	MaxSeries int
}

// HistorySeries is one matching series in a range.
type HistorySeries struct {
	Metric         string            `json:"metric"`
	Labels         map[string]string `json:"labels,omitempty"`
	Tier           string            `json:"tier"`
	Points         []Point           `json:"points"`
	LastObservedAt time.Time         `json:"last_observed_at"`
	Stale          bool              `json:"stale,omitzero"`
	Gaps           bool              `json:"gaps,omitzero"`
}

// HistoryResult is a range query's answer.
type HistoryResult struct {
	RetentionStart  time.Time `json:"retention_start"`
	IntervalSeconds float64   `json:"interval_seconds"`
	// DroppedSeries counts rejected new series over this store's lifetime.
	DroppedSeries     uint64          `json:"dropped_series,omitzero"`
	Series            []HistorySeries `json:"series"`
	UnsupportedReason string          `json:"unsupported_reason,omitempty"`
	// Truncated reports that more series matched than MaxSeries.
	Truncated bool `json:"truncated,omitzero"`
	// Pending marks regional history that has not completed archive replay.
	Pending bool `json:"pending,omitzero"`
	// Incomplete marks retained samples omitted or rejected during regional replay.
	Incomplete bool `json:"incomplete,omitzero"`
}

// HistorySource is the range-query interface the dashboard charts and the
// insight rules depend on. History implements it.
type HistorySource interface {
	Range(query HistoryQuery) HistoryResult
	Metrics() []string
}

// TierFor returns the finest tier whose retention covers start, given now.
func TierFor(start, now time.Time) string {
	age := now.Sub(start)
	switch {
	case age <= rawRetention:
		return TierRaw
	case age <= oneMinuteRetention:
		return Tier1m
	case age <= fiveMinuteRetention:
		return Tier5m
	default:
		return Tier1h
	}
}

// Range returns matching series' points in [Start, End], oldest first.
func (history *History) Range(query HistoryQuery) HistoryResult {
	if query.End.IsZero() {
		query.End = time.Now()
	}
	if query.Start.IsZero() {
		query.Start = query.End.Add(-time.Hour)
	}
	chosen := query.Tier
	if chosen == "" {
		chosen = TierFor(query.Start, time.Now())
	}
	if query.MaxSeries <= 0 {
		query.MaxSeries = 64
	}
	query.MaxSeries = min(query.MaxSeries, 512)
	start, end := query.Start.UnixMilli(), query.End.UnixMilli()
	cutoff := time.Now().Add(-HistoryRetention).UnixMilli()
	history.mu.RLock()
	defer history.mu.RUnlock()
	result := HistoryResult{RetentionStart: time.UnixMilli(cutoff).UTC(),
		IntervalSeconds: history.config.Interval.Seconds(), DroppedSeries: history.dropped}
	for minute := range history.dropMinutes {
		if minute >= start/time.Minute.Milliseconds() && minute <= end/time.Minute.Milliseconds() {
			result.Incomplete = true
			break
		}
	}
	keys := slices.Sorted(maps.Keys(history.series))
	for _, key := range keys {
		current := history.series[key]
		if current.metric != query.Metric || !labelsMatch(current.labels, query.Labels) {
			continue
		}
		if query.Rate && !current.counter {
			result.UnsupportedReason = "rate_requires_counter"
			continue
		}
		tierName := chosen
		if query.Tier == "" {
			tierName = current.coveringTier(chosen, start, end, cutoff)
		}
		t, ok := current.tiers[tierName]
		if !ok {
			continue
		}
		out := HistorySeries{Metric: current.metric, Tier: tierName, Labels: labelMap(current.labels)}
		var previous *bucket
		var lastAt int64
		expected := max(history.config.Interval, t.step).Milliseconds()
		for _, b := range t.buckets() {
			if b.lastAt() < cutoff {
				continue
			}
			if b.Start > end {
				break
			}
			if b.Start < start-t.step.Milliseconds() {
				copied := b
				previous = &copied
				continue
			}
			if lastAt != 0 && b.lastAt()-lastAt > 2*expected {
				out.Gaps = true
			}
			lastAt = b.lastAt()
			if query.Rate {
				if previous != nil && b.lastAt() > previous.lastAt() {
					delta := b.Last - previous.Last
					if delta < 0 { // counter reset
						delta = b.Last
					}
					if b.Increased {
						// Growth accumulated per raw sample also counts a
						// reset and recovery inside the bucket.
						delta = b.Increase
					}
					rate := delta / (float64(b.lastAt()-previous.lastAt()) / 1000)
					out.Points = append(out.Points, Point{Time: time.UnixMilli(b.Start).UTC(), Value: rate,
						Min: rate, Max: rate})
				}
				copied := b
				previous = &copied
				continue
			}
			value := b.Sum / float64(b.Count)
			if current.counter {
				value = b.Last
			}
			out.Points = append(out.Points, Point{Time: time.UnixMilli(b.Start).UTC(), Value: value,
				Min: b.Min, Max: b.Max, Samples: b.Count})
		}
		out.LastObservedAt = time.UnixMilli(lastAt).UTC()
		out.Stale = end-lastAt > 2*expected
		// A stored series without points in the range does not take one
		// of the result's slots.
		if len(out.Points) == 0 {
			continue
		}
		if len(result.Series) == query.MaxSeries {
			result.Truncated = true
			break
		}
		result.Series = append(result.Series, out)
	}
	return result
}

// coveringTier picks, for an automatic query, the finest tier from chosen
// on whose data reaches back to start; restored history has no raw tier and
// may lack the 1m one, so a fresh tier must not hide older restored data.
// Without full coverage it takes the tier reaching furthest back.
func (current *series) coveringTier(chosen string, start, end, cutoff int64) string {
	order := []string{TierRaw, Tier1m, Tier5m, Tier1h}
	best, bestOldest := chosen, int64(math.MaxInt64)
	for _, name := range order[max(slices.Index(order, chosen), 0):] {
		t := current.tiers[name]
		if t == nil {
			continue
		}
		oldest, ok := t.oldest()
		if !ok {
			continue
		}
		// Rounded bucket starts can predate ingestion; compare known sample
		// times so coarser tiers do not manufacture earlier coverage.
		if oldest <= start {
			best = name
			break
		}
		if oldest < bestOldest {
			best, bestOldest = name, oldest
		}
	}
	// Coarser buckets may retain samples lost from finer tiers across restarts.
	for _, name := range order[max(slices.Index(order, best)+1, 0):] {
		coarser := current.tiers[name]
		if coarser == nil {
			continue
		}
		step := coarser.step.Milliseconds()
		oldest, _ := current.tiers[best].oldest()
		counts := map[int64]uint64{}
		for _, b := range current.tiers[best].buckets() {
			counts[b.Start-b.Start%step] += uint64(b.Count)
		}
		for _, b := range coarser.buckets() {
			// Missing samples before a covering fine tier are outside the requested range.
			if (b.Start >= start || oldest > start) && b.lastAt() >= cutoff &&
				b.Start >= start-step && b.Start <= end && uint64(b.Count) > counts[b.Start] {
				best = name
				break
			}
		}
	}
	return best
}

// Metrics lists the metric names currently stored.
func (history *History) Metrics() []string {
	history.mu.RLock()
	defer history.mu.RUnlock()
	names := map[string]struct{}{}
	cutoff := time.Now().Add(-HistoryRetention).UnixMilli()
	for _, current := range history.series {
		if current.last >= cutoff {
			names[current.metric] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(names))
}

// HistoryStats reports the store's size.
type HistoryStats struct {
	Series  int    `json:"series"`
	Dropped uint64 `json:"dropped"`
}

// Stats returns the series count and dropped new series.
func (history *History) Stats() HistoryStats {
	history.mu.RLock()
	defer history.mu.RUnlock()
	return HistoryStats{Series: len(history.series), Dropped: history.dropped}
}

// DroppedBetween reports lost raw coverage, conservatively rounded to minutes.
// Only the raw retention window is tracked; the lifetime counter is unchanged.
func (history *History) DroppedBetween(start, end time.Time) bool {
	history.mu.RLock()
	defer history.mu.RUnlock()
	first, last := start.UnixMilli()/time.Minute.Milliseconds(), end.UnixMilli()/time.Minute.Milliseconds()
	for minute := range history.dropMinutes {
		if minute >= first && minute <= last {
			return true
		}
	}
	return false
}

func labelsMatch(labels []Label, want map[string]string) bool {
	for name, value := range want {
		index := slices.IndexFunc(labels, func(label Label) bool { return label.Name == name })
		if index < 0 || value != "" && labels[index].Value != value {
			return false
		}
	}
	return true
}

func labelMap(labels []Label) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for _, label := range labels {
		out[label.Name] = label.Value
	}
	return out
}

// Latest returns the newest raw value of each matching series, keyed by
// the series' label set rendered as name=value pairs joined by commas.
func (history *History) Latest(metric string, labels map[string]string) map[string]float64 {
	history.mu.RLock()
	defer history.mu.RUnlock()
	out := map[string]float64{}
	for _, current := range history.series {
		if current.metric != metric || !labelsMatch(current.labels, labels) {
			continue
		}
		raw := current.tiers[TierRaw]
		if raw.size == 0 {
			continue
		}
		last := raw.ring[(raw.start+raw.size-1)%len(raw.ring)]
		parts := make([]string, 0, len(current.labels))
		for _, label := range current.labels {
			parts = append(parts, label.Name+"="+label.Value)
		}
		out[strings.Join(parts, ",")] = last.Last
	}
	return out
}

var _ HistorySource = (*History)(nil)
