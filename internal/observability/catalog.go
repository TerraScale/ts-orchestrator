package observability

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	catalogVersion          = 1
	catalogMaxBytes         = 1 << 20
	catalogMaxMetrics       = 2048
	catalogMaxSamples       = 4096
	catalogSamplesPerMetric = 64
	catalogMaxLabels        = 32
	catalogMaxHistoryPoints = 8192
)

// CatalogSource is the shared read-only metric service for CLI and dashboard.
type CatalogSource interface {
	Catalog(context.Context) (CatalogResult, error)
	History(context.Context, HistoryQuery) (CatalogHistory, error)
}

// CatalogResult discovers the actual registered exposition and retained names.
type CatalogResult struct {
	Version    int             `json:"version"`
	ObservedAt time.Time       `json:"observed_at"`
	State      string          `json:"state"`
	Truncated  bool            `json:"truncated,omitzero"`
	Metrics    []CatalogMetric `json:"metrics"`
}

// CatalogMetric describes supplied metadata; Unsupported lists absent facts.
// Labels and Samples contain dimension names only, never dimension values.
type CatalogMetric struct {
	Name                    string          `json:"name"`
	Description             string          `json:"description,omitempty"`
	Unit                    string          `json:"unit,omitempty"`
	Type                    string          `json:"type,omitempty"`
	Source                  string          `json:"source"`
	State                   string          `json:"state"`
	ObservedAt              time.Time       `json:"observed_at,omitzero"`
	Unsupported             []string        `json:"unsupported,omitempty"`
	Labels                  []string        `json:"labels"`
	Samples                 []CatalogSample `json:"samples"`
	HistoryState            string          `json:"history_state"`
	HistoryTiers            []string        `json:"history_tiers,omitempty"`
	HistoryRetentionSeconds int64           `json:"history_retention_seconds,omitzero"`
}

// CatalogSample is a current sample with its numeric text and safe dimensions.
type CatalogSample struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Labels []string `json:"labels"`
}

// CatalogHistory adds explicit coverage state to the existing range response.
type CatalogHistory struct {
	Version    int       `json:"version"`
	ObservedAt time.Time `json:"observed_at"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	HistoryResult
}

type metricCatalog struct {
	registry *Registry
	history  atomic.Pointer[HistorySource]
}

// catalogBuffer retains a bounded prefix without making exporters retry writes.
type catalogBuffer struct {
	bytes.Buffer
	truncated bool
}

func (buffer *catalogBuffer) Write(data []byte) (int, error) {
	remaining := catalogMaxBytes - buffer.Len()
	if len(data) > remaining {
		buffer.truncated = true
	}
	_, _ = buffer.Buffer.Write(data[:min(len(data), remaining)])
	return len(data), nil
}

func (buffer *catalogBuffer) WriteString(value string) (int, error) {
	remaining := catalogMaxBytes - buffer.Len()
	if len(value) > remaining {
		buffer.truncated = true
	}
	_, _ = buffer.Buffer.WriteString(value[:min(len(value), remaining)])
	return len(value), nil
}

func (catalog *metricCatalog) Catalog(ctx context.Context) (CatalogResult, error) {
	if err := ctx.Err(); err != nil {
		return CatalogResult{}, err
	}
	buffer := new(catalogBuffer)
	catalog.registry.WritePrometheus(buffer)
	result := CatalogResult{Version: catalogVersion, ObservedAt: time.Now().UTC(), State: "available", Metrics: []CatalogMetric{}}
	result.Truncated = buffer.truncated
	data := buffer.String()
	if buffer.truncated {
		data, _, _ = strings.CutLast(data, "\n")
	}
	entries := map[string]*CatalogMetric{}
	entry := func(name string) *CatalogMetric {
		if current := entries[name]; current != nil {
			return current
		}
		if len(entries) >= catalogMaxMetrics {
			result.Truncated = true
			return nil
		}
		current := &CatalogMetric{Name: name, Source: "registry", State: "missing", HistoryState: "unsupported", Labels: []string{}, Samples: []CatalogSample{}}
		entries[name] = current
		return current
	}
	// Metadata is optional in Prometheus exposition; never infer type or units
	// from a name suffix when the exporter supplied no metadata.
	for line := range strings.SplitSeq(data, "\n") {
		if len(line) > 65536 {
			result.Truncated = true
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		kind, rest, ok := strings.Cut(line[2:], " ")
		if !ok || kind != "HELP" && kind != "TYPE" && kind != "UNIT" {
			continue
		}
		name, value, ok := strings.Cut(rest, " ")
		if !ok || !catalogName(name, true) {
			continue
		}
		current := entry(name)
		if current == nil {
			continue
		}
		value = RedactText(strings.TrimSpace(value), 512)
		switch kind {
		case "HELP":
			current.Description = value
		case "UNIT":
			current.Unit = value
		case "TYPE":
			if slices.Contains([]string{"counter", "gauge", "histogram", "summary", "untyped", "info", "stateset"}, value) {
				current.Type = value
			}
		}
	}
	sampleCount := 0
	for line := range strings.SplitSeq(data, "\n") {
		if err := ctx.Err(); err != nil {
			return CatalogResult{}, err
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 65536 {
			result.Truncated = true
			continue
		}
		sample, ok := catalogParseSample(line)
		if !ok {
			result.State = "incomplete"
			continue
		}
		name := sample.Name
		for _, suffix := range []string{"_bucket", "_sum", "_count", "_created"} {
			base, matched := strings.CutSuffix(name, suffix)
			if current := entries[base]; matched && current != nil && (current.Type == "histogram" || current.Type == "summary" || current.Type == "counter") {
				name = base
				break
			}
		}
		current := entry(name)
		if current == nil {
			continue
		}
		current.State, current.ObservedAt = "available", result.ObservedAt
		current.Labels = append(current.Labels, sample.Labels...)
		slices.Sort(current.Labels)
		current.Labels = slices.Compact(current.Labels)
		if len(current.Labels) > catalogMaxLabels {
			current.Labels = current.Labels[:catalogMaxLabels]
			current.State = "truncated"
			result.Truncated = true
		}
		if sampleCount >= catalogMaxSamples || len(current.Samples) >= catalogSamplesPerMetric {
			current.State = "truncated"
			result.Truncated = true
			continue
		}
		current.Samples = append(current.Samples, sample)
		sampleCount++
	}
	if source := catalog.history.Load(); source != nil {
		for _, name := range (*source).Metrics() {
			if !catalogName(name, true) {
				result.State = "incomplete"
				continue
			}
			current := entry(name)
			if current == nil {
				continue
			}
			if current.ObservedAt.IsZero() {
				current.Source, current.State = "history", "missing"
			} else {
				current.Source = "registry,history"
			}
			current.HistoryState = "available"
			current.HistoryTiers = []string{TierRaw, Tier1m, Tier5m, Tier1h}
			current.HistoryRetentionSeconds = int64(HistoryRetention / time.Second)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		current := entries[name]
		if current.Description == "" {
			current.Unsupported = append(current.Unsupported, "description")
		}
		if current.Unit == "" {
			current.Unsupported = append(current.Unsupported, "unit")
		}
		if current.Type == "" {
			current.Unsupported = append(current.Unsupported, "type")
		}
		if current.ObservedAt.IsZero() {
			current.Unsupported = append(current.Unsupported, "collection_time")
		}
		result.Metrics = append(result.Metrics, *current)
	}
	if result.Truncated {
		result.State = "truncated"
	} else if len(result.Metrics) == 0 {
		result.State = "missing"
	}
	return result, nil
}

func catalogName(name string, metric bool) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for index, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character == '_' || metric && character == ':' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func catalogParseSample(line string) (CatalogSample, bool) {
	end := strings.IndexAny(line, "{ \t")
	if end < 0 || !catalogName(line[:end], true) {
		return CatalogSample{}, false
	}
	sample := CatalogSample{Name: line[:end], Labels: []string{}}
	rest := line[end:]
	if rest[0] == '{' {
		rest = rest[1:]
		for {
			rest = strings.TrimLeft(rest, " \t")
			if strings.HasPrefix(rest, "}") {
				rest = rest[1:]
				break
			}
			name, value, ok := strings.Cut(rest, "=")
			name = strings.TrimSpace(name)
			if !ok || !catalogName(name, false) || len(sample.Labels) >= catalogMaxLabels {
				return CatalogSample{}, false
			}
			value = strings.TrimLeft(value, " \t")
			if !strings.HasPrefix(value, `"`) {
				return CatalogSample{}, false
			}
			index := 1
			for ; index < len(value); index++ {
				if value[index] == '\\' {
					index++
					if index >= len(value) || !strings.ContainsRune("\\\"n", rune(value[index])) {
						return CatalogSample{}, false
					}
				} else if value[index] == '"' {
					break
				}
			}
			if index >= len(value) {
				return CatalogSample{}, false
			}
			sample.Labels = append(sample.Labels, name)
			rest = strings.TrimLeft(value[index+1:], " \t")
			if strings.HasPrefix(rest, ",") {
				rest = rest[1:]
				continue
			}
			if !strings.HasPrefix(rest, "}") {
				return CatalogSample{}, false
			}
			rest = rest[1:]
			break
		}
	}
	fields := strings.Fields(rest)
	if len(fields) < 1 || len(fields) > 2 {
		return CatalogSample{}, false
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return CatalogSample{}, false
	}
	sample.Value = strconv.FormatFloat(value, 'g', -1, 64)
	slices.Sort(sample.Labels)
	return sample, true
}

func (catalog *metricCatalog) History(ctx context.Context, query HistoryQuery) (CatalogHistory, error) {
	if err := ctx.Err(); err != nil {
		return CatalogHistory{}, err
	}
	result := CatalogHistory{Version: catalogVersion, ObservedAt: time.Now().UTC(), State: "unsupported", Reason: "history source is not available"}
	if !catalogName(query.Metric, true) {
		return CatalogHistory{}, errors.New("invalid metric name")
	}
	if query.End.IsZero() {
		query.End = result.ObservedAt
	}
	if query.Start.IsZero() {
		query.Start = query.End.Add(-time.Hour)
	}
	if !query.Start.Before(query.End) || query.End.Sub(query.Start) > HistoryRetention {
		return CatalogHistory{}, errors.New("history range must be positive and at most 14 days")
	}
	if !slices.Contains([]string{"", TierRaw, Tier1m, Tier5m, Tier1h}, query.Tier) {
		return CatalogHistory{}, errors.New("invalid history tier")
	}
	if query.MaxSeries <= 0 {
		query.MaxSeries = 64
	}
	query.MaxSeries = min(query.MaxSeries, 512)
	source := catalog.history.Load()
	if source == nil {
		return result, nil
	}
	if !slices.Contains((*source).Metrics(), query.Metric) {
		result.Reason = "metric is not retained by the history source"
		return result, nil
	}
	result.HistoryResult = (*source).Range(query)
	result.State, result.Reason = "missing", "no retained samples in the requested range"
	points := 0
	var newest time.Time
	if len(result.Series) > query.MaxSeries {
		result.Series = result.Series[:query.MaxSeries]
		result.Truncated = true
	}
	for index := range result.Series {
		series := &result.Series[index]
		if len(series.Points) > catalogMaxHistoryPoints-points {
			series.Points = series.Points[:catalogMaxHistoryPoints-points]
			result.Truncated = true
		}
		points += len(series.Points)
		for _, point := range series.Points {
			if point.Time.After(newest) {
				newest = point.Time
			}
		}
	}
	if !newest.IsZero() {
		result.State, result.Reason = "available", ""
		step := DefaultHistoryInterval
		if result.IntervalSeconds > 0 {
			step = time.Duration(result.IntervalSeconds * float64(time.Second))
		}
		for _, series := range result.Series {
			switch series.Tier {
			case Tier1m:
				step = max(step, time.Minute)
			case Tier5m:
				step = max(step, 5*time.Minute)
			case Tier1h:
				step = max(step, time.Hour)
			}
		}
		if query.End.Sub(newest) > 2*step {
			result.State, result.Reason = "stale", "latest retained sample predates the requested range end"
		}
	}
	if result.Incomplete {
		result.State, result.Reason = "incomplete", "retained samples were omitted or rejected"
	}
	if result.Pending {
		result.State, result.Reason = "pending", "regional history replay is pending"
	}
	if result.Truncated {
		result.State, result.Reason = "truncated", "history result exceeded the response budget"
	}
	if result.UnsupportedReason != "" {
		result.State, result.Reason = "unsupported", "rates require a retained counter series"
	}
	return result, ctx.Err()
}
