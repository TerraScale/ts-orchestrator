package observability

import (
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
