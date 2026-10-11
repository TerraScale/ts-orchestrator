package ocicost

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// validReport has one day of usage, one service and one tagged component.
func validReport() Report {
	return Report{
		Version:    Version,
		Cell:       "gru",
		OCIRegion:  "sa-saopaulo-1",
		Currency:   "BRL",
		ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC),
		Days:       []Day{{Day: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC), Cents: 267}},
		Services:   []Line{{Name: "Block Storage", Cents: 807}},
		Components: []Line{{Name: "terrabase", Cents: 437}},
	}
}

func TestReportValidate(t *testing.T) {
	utc := func(day int) time.Time { return time.Date(2026, time.October, day, 0, 0, 0, 0, time.UTC) }

	t.Run("valid", func(t *testing.T) {
		report := validReport()
		if err := report.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if report.Empty() {
			t.Error("Empty() = true for a report with usage days")
		}
	})

	t.Run("valid prices", func(t *testing.T) {
		report := validReport()
		report.Prices = []Price{{SKU: "B91961", PerUnit: 0.1335}, {SKU: "B93297", PerUnit: 0}}
		if err := report.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	t.Run("empty without currency passes", func(t *testing.T) {
		report := Report{
			Version:    Version,
			Cell:       "gru",
			OCIRegion:  "sa-saopaulo-1",
			ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
			Through:    utc(8),
		}
		if err := report.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if !report.Empty() {
			t.Error("Empty() = false for a report without days")
		}
	})

	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "wrong version", mutate: func(r *Report) { r.Version = Version + 1 }},
		{name: "empty cell", mutate: func(r *Report) { r.Cell = "" }},
		{name: "upper-case cell", mutate: func(r *Report) { r.Cell = "GRU" }},
		{name: "empty OCI region", mutate: func(r *Report) { r.OCIRegion = "" }},
		{name: "lower-case currency", mutate: func(r *Report) { r.Currency = "usd" }},
		{name: "zero observed time", mutate: func(r *Report) { r.ObservedAt = time.Time{} }},
		{name: "through not midnight", mutate: func(r *Report) { r.Through = utc(8).Add(time.Hour) }},
		{name: "through after observed", mutate: func(r *Report) { r.Through = utc(11) }},
		{name: "through not in UTC", mutate: func(r *Report) { r.Through = utc(8).In(time.FixedZone("UTC+0", 0)) }},
		{name: "unsorted days", mutate: func(r *Report) {
			r.Days = []Day{{Day: utc(3)}, {Day: utc(2)}}
		}},
		{name: "duplicate day", mutate: func(r *Report) {
			r.Days = []Day{{Day: utc(2)}, {Day: utc(2)}}
		}},
		{name: "day cents over bound", mutate: func(r *Report) { r.Days[0].Cents = maxCents + 1 }},
		{name: "65 days", mutate: func(r *Report) {
			r.Days = nil
			for index := range 65 {
				r.Days = append(r.Days, Day{Day: time.Date(2026, time.January, 1+index, 0, 0, 0, 0, time.UTC)})
			}
		}},
		{name: "empty line name", mutate: func(r *Report) { r.Services[0].Name = "" }},
		{name: "duplicate service", mutate: func(r *Report) {
			r.Services = append(r.Services, Line{Name: "Block Storage", Cents: 1})
		}},
		{name: "unknown component", mutate: func(r *Report) {
			r.Components = []Line{{Name: "db", Cents: 1}}
		}},
		{name: "cost without currency", mutate: func(r *Report) { r.Currency = "" }},
		{name: "65 prices", mutate: func(r *Report) {
			r.Prices = nil
			for index := range 65 {
				r.Prices = append(r.Prices, Price{SKU: fmt.Sprintf("B%05d", index)})
			}
		}},
		{name: "empty SKU", mutate: func(r *Report) { r.Prices = []Price{{SKU: "", PerUnit: 1}} }},
		{name: "SKU over bound", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: strings.Repeat("x", maxNameBytes+1), PerUnit: 1}}
		}},
		{name: "unsorted prices", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93298", PerUnit: 1}, {SKU: "B93297", PerUnit: 1}}
		}},
		{name: "duplicate price SKU", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: 1}, {SKU: "B93297", PerUnit: 2}}
		}},
		{name: "NaN price", mutate: func(r *Report) { r.Prices = []Price{{SKU: "B93297", PerUnit: math.NaN()}} }},
		{name: "infinite price", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: math.Inf(1)}}
		}},
		{name: "negative price", mutate: func(r *Report) { r.Prices = []Price{{SKU: "B93297", PerUnit: -0.01}} }},
		{name: "price over bound", mutate: func(r *Report) {
			r.Prices = []Price{{SKU: "B93297", PerUnit: maxUnitPrice + 1}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := validReport()
			tc.mutate(&report)
			if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
				t.Errorf("Validate() = %v, want ErrInvalidReport", err)
			}
		})
	}
}
