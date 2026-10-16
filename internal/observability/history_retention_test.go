package observability

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestHistoryRetainsFourteenDaysAndRestoresHourlyRollups(t *testing.T) {
	base := time.Now().Truncate(time.Hour).Add(-16 * 24 * time.Hour)
	history := NewHistory(HistoryConfig{})
	for hour := range 16 * 24 {
		at := base.Add(time.Duration(hour) * time.Hour)
		history.Append(at.Add(10*time.Minute), []Sample{{Metric: "g", Value: float64(hour)}})
		history.Append(at.Add(40*time.Minute), []Sample{{Metric: "g", Value: float64(hour + 2)}})
	}
	end := time.Now()
	query := HistoryQuery{Metric: "g", Start: end.Add(-HistoryRetention), End: end}
	check := func(t *testing.T, store *History) {
		t.Helper()
		result := historyHTTPRange(t, store, query)
		if len(result.Series) != 1 || result.Series[0].Tier != Tier1h {
			t.Fatalf("14-day query = %+v", result)
		}
		points := result.Series[0].Points
		if len(points) < 335 || len(points) > 337 {
			t.Fatalf("14-day hourly points = %d", len(points))
		}
		last := points[len(points)-1]
		if last.Value != 384 || last.Min != 383 || last.Max != 385 {
			t.Fatalf("hourly average and extrema = %+v", last)
		}
		for _, point := range points {
			// A rollup can start up to one hour before the cutoff.
			if point.Time.Before(query.Start.Add(-time.Hour)) {
				t.Fatalf("expired hourly point = %+v", point)
			}
		}
	}
	check(t, history)
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	check(t, restored)
}

func TestHistorySnapshotPrefersHourlyCoverageWhenSizeLimited(t *testing.T) {
	history := NewHistory(HistoryConfig{})
	base := time.Now().Truncate(time.Hour).Add(-HistoryRetention)
	for step := range 14 * 24 * 12 {
		history.Append(base.Add(time.Duration(step)*5*time.Minute),
			[]Sample{{Metric: "g", Value: math.Sin(float64(step))}})
	}
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var snapshot historySnapshot
	if err := json.NewDecoder(reader).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	for index := range snapshot.Series {
		delete(snapshot.Series[index].Tiers, Tier1m)
		delete(snapshot.Series[index].Tiers, Tier5m)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if err := json.NewEncoder(writer).Encode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	limit := buffer.Len() + 64
	data, err = history.Export(limit)
	if err != nil || len(data) > limit {
		t.Fatalf("limited export = %d bytes, limit %d, error %v", len(data), limit, err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	end := time.Now()
	result := historyHTTPRange(t, restored, HistoryQuery{Metric: "g", Start: end.Add(-HistoryRetention), End: end})
	if len(result.Series) != 1 || result.Series[0].Tier != Tier1h || len(result.Series[0].Points) < 335 {
		t.Fatalf("hourly coverage after limited restore = %+v", result)
	}
}

func TestHistoryExpiredSeriesAreNotQueriedOrSnapshotted(t *testing.T) {
	history := NewHistory(HistoryConfig{})
	old := time.Now().Add(-15 * 24 * time.Hour)
	history.Append(old, []Sample{{Metric: "g", Value: 1}})
	if result := historyHTTPRange(t, history, HistoryQuery{Metric: "g", Start: old.Add(-time.Hour), End: old.Add(time.Hour), Tier: Tier1h}); len(result.Series) != 0 {
		t.Fatalf("expired series returned = %+v", result)
	}
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	if stats := restored.Stats(); stats.Series != 0 {
		t.Fatalf("expired series restored = %+v", stats)
	}
	// An inactive member's two-day-old series must survive new samples.
	history.Append(time.Now().Add(-2*24*time.Hour), []Sample{{Metric: "g", Value: 2}})
	history.Append(time.Now(), []Sample{{Metric: "other", Value: 3}})
	if stats := history.Stats(); stats.Series != 2 {
		t.Fatalf("series expired before 14 days = %+v", stats)
	}
}

func TestHourlyCounterRollupKeepsResetGrowthAfterRestore(t *testing.T) {
	base := time.Now().Truncate(time.Hour).Add(-3 * time.Hour)
	history := NewHistory(HistoryConfig{})
	for _, sample := range []struct {
		offset time.Duration
		value  float64
	}{{0, 100}, {time.Hour + 10*time.Minute, 150}, {time.Hour + 20*time.Minute, 0}, {time.Hour + 30*time.Minute, 200}} {
		history.Append(base.Add(sample.offset), []Sample{{Metric: "c", Value: sample.value, Counter: true}})
	}
	data, err := history.Export(0)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewHistory(HistoryConfig{})
	if err := restored.Import(data); err != nil {
		t.Fatal(err)
	}
	// Resume inside the restored open hour: the new increase joins it.
	restored.Append(base.Add(time.Hour+40*time.Minute), []Sample{{Metric: "c", Value: 250, Counter: true}})
	result := historyHTTPRange(t, restored, HistoryQuery{Metric: "c", Start: base, End: base.Add(2 * time.Hour), Tier: Tier1h, Rate: true})
	if len(result.Series) != 1 || len(result.Series[0].Points) != 1 {
		t.Fatalf("hourly rate = %+v", result)
	}
	// 100 -> 150 (+50), reset -> 200 (+200), -> 250 (+50), over 100 min.
	if rate := result.Series[0].Points[0].Value; math.Abs(rate-300.0/6000) > 1e-9 {
		t.Fatalf("restored hourly counter rate = %v", rate)
	}
}
