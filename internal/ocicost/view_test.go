package ocicost

import (
	"fmt"
	"testing"
	"time"
)

// viewReport is October 2026 through the 9th, with October 9th partial.
func viewReport() Report {
	report := Report{Version: Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "USD",
		ObservedAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		Services:   []Line{{Name: "compute", Cents: 500}, {Name: "storage", Cents: 300}},
		Components: []Line{{Name: "controller", Cents: 300}, {Name: "terrabase", Cents: 200}}}
	for day := 1; day <= 8; day++ {
		report.Days = append(report.Days, Day{Day: time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC), Cents: 100})
	}
	report.Days = append(report.Days, Day{Day: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Cents: 40})
	return report
}

var viewNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func TestSummarizeCarriesForecast(t *testing.T) {
	t.Parallel()
	view := Summarize(viewReport(), viewNow, nil)
	if view.Cell != "gru" || view.OCIRegion != "sa-saopaulo-1" {
		t.Fatalf("view identity = %q %q", view.Cell, view.OCIRegion)
	}
	// 840 this month; the 7 complete days before the 9th average 100 a day,
	// so the month ends at 800 + 100 × 23 days left.
	if view.Forecast.MonthToDateCents != 840 || view.Forecast.RateCents != 100 || view.Forecast.MonthEndCents != 3100 {
		t.Fatalf("forecast = %+v", view.Forecast)
	}
	if len(view.Services) != 2 || view.Services[0].Name != "compute" || len(view.Components) != 2 {
		t.Fatalf("lines = %+v %+v", view.Services, view.Components)
	}
	if view.UntaggedCents != 340 {
		t.Fatalf("untagged = %d, want 840 - 500", view.UntaggedCents)
	}
}

func TestSummarizeFoldsLinesPastTheBound(t *testing.T) {
	t.Parallel()
	report := viewReport()
	report.Services = nil
	for index := 1; index <= 20; index++ {
		report.Services = append(report.Services, Line{Name: fmt.Sprintf("svc-%02d", index), Cents: uint64(index)})
	}
	services := Summarize(report, viewNow, nil).Services
	if len(services) != maxViewLines {
		t.Fatalf("services = %d lines, want %d", len(services), maxViewLines)
	}
	if last := services[maxViewLines-1]; last.Name != "Other" || last.Cents != 16+17+18+19+20 {
		t.Fatalf("folded line = %+v, want Other 90", last)
	}
	if services[maxViewLines-2].Name != "svc-15" {
		t.Fatalf("kept lines = ..., %q, want svc-15 last", services[maxViewLines-2].Name)
	}
}

func TestSummarizeUntaggedFloorsAtZero(t *testing.T) {
	t.Parallel()
	report := viewReport()
	report.Components = []Line{{Name: "controller", Cents: 1000}}
	if untagged := Summarize(report, viewNow, nil).UntaggedCents; untagged != 0 {
		t.Fatalf("untagged = %d, want 0 when tags exceed the month", untagged)
	}
}
