package dashboard

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/budget"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalview"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ocicost"
)

// costRow is one region's line on the cost page.
type costRow struct {
	Region   string
	Answered bool
	// Rollup marks numbers from another region's rollup: month to date, the
	// rate with pending and month end only, no next month or lines.
	Rollup bool
	// View is nil when the region did not answer or predates the cost view.
	View *ocicost.View
}

// costRows lists this region's full view first, then every other region of
// the global view from its rollup's cost section (TS-805).
func (current view) costRows() []costRow {
	local := current.localRegion()
	var rows []costRow
	if current.LocalSummary != nil {
		rows = append(rows, costRow{Region: local, Answered: true, View: current.LocalSummary.Cost})
	}
	for _, region := range current.Global {
		if strings.EqualFold(region.Cell, local) {
			continue
		}
		row := costRow{Region: region.Cell, Rollup: true, Answered: region.Rollup != nil && !region.Stale}
		if region.Rollup != nil && region.Rollup.Cost != nil {
			row.View = rollupCost(region.Cell, *region.Rollup.Cost)
		}
		rows = append(rows, row)
	}
	return rows
}

// rollupCost is a rollup's cost section as a view; its per hour already
// holds the pending hosts.
func rollupCost(cell string, cost globalview.Cost) *ocicost.View {
	cents := func(value float64) uint64 { return uint64(math.Round(max(value, 0) * 100)) }
	return &ocicost.View{Cell: cell, Forecast: ocicost.Forecast{Currency: cost.Currency, ObservedAt: cost.ObservedAt,
		MonthToDateCents: cents(cost.MonthToDate), RateCents: cents(cost.PerHour * 24),
		MonthEndCents: cents(cost.MonthForecast)}}
}

// fullRows are the reported rows with every number, this region's.
func fullRows(rows []costRow) []costRow {
	return slices.DeleteFunc(slices.Clone(rows), func(row costRow) bool { return row.Rollup })
}

// reportedRows are the rows the totals sum: those with a report, in the
// first currency seen. A row in another currency is left out and marks the
// totals mixed.
func reportedRows(rows []costRow) (reported []costRow, currency string, mixed bool) {
	for _, row := range rows {
		if row.View == nil || row.View.Missing != "" {
			continue
		}
		rowCurrency := row.View.Forecast.Currency
		if rowCurrency != "" {
			if currency == "" {
				currency = rowCurrency
			} else if rowCurrency != currency {
				mixed = true
				continue
			}
		}
		reported = append(reported, row)
	}
	return reported, currency, mixed
}

// costTotal sums the reported regions.
type costTotal struct {
	Currency                                        string
	Mixed                                           bool
	MonthToDate, Rate, Pending, MonthEnd, NextMonth uint64
	// Reported of Expected regions have a report to sum; Rollups of them
	// come from rollups, which carry no pending or next month.
	Reported, Expected, Rollups int
}

// show formats one total, unknown until a region reports.
func (total costTotal) show(cents uint64) string {
	if total.Reported == 0 {
		return "unknown"
	}
	return money(cents, total.Currency)
}

// showFull formats a total only rows with every number have, unknown once a
// rollup is part of the sum.
func (total costTotal) showFull(cents uint64) string {
	if total.Rollups > 0 {
		return "—"
	}
	return total.show(cents)
}

func (current view) costTotals() costTotal {
	rows := current.costRows()
	reported, currency, mixed := reportedRows(rows)
	total := costTotal{Currency: currency, Mixed: mixed, Reported: len(reported), Expected: len(rows)}
	for _, row := range reported {
		forecast := row.View.Forecast
		total.MonthToDate += forecast.MonthToDateCents
		total.Rate += forecast.RateCents
		total.Pending += forecast.PendingDailyCents
		total.MonthEnd += forecast.MonthEndCents
		total.NextMonth += forecast.NextMonthCents
		if row.Rollup {
			total.Rollups++
		}
	}
	return total
}

// costLines merges the reported regions' services or components, costliest
// first. Components end with the untagged cost, once any is tagged, so an
// empty list means no tags yet.
func (current view) costLines(kind string) []ocicost.Line {
	reported, _, _ := reportedRows(fullRows(current.costRows()))
	sums := map[string]uint64{}
	var untagged uint64
	for _, row := range reported {
		lines := row.View.Services
		if kind == "components" {
			lines = row.View.Components
			untagged += row.View.UntaggedCents
		}
		for _, line := range lines {
			sums[line.Name] += line.Cents
		}
	}
	lines := make([]ocicost.Line, 0, len(sums))
	for name, cents := range sums {
		lines = append(lines, ocicost.Line{Name: name, Cents: cents})
	}
	slices.SortFunc(lines, func(a, b ocicost.Line) int {
		return cmp.Or(cmp.Compare(b.Cents, a.Cents), strings.Compare(a.Name, b.Name))
	})
	if kind == "components" && len(lines) > 0 {
		lines = append(lines, ocicost.Line{Name: "untagged", Cents: untagged})
	}
	return lines
}

// costMethodLines walks each reported region's own numbers through the
// method the page explains.
func (current view) costMethodLines() []string {
	reported, _, _ := reportedRows(fullRows(current.costRows()))
	lines := make([]string, 0, len(reported))
	for _, row := range reported {
		forecast := row.View.Forecast
		line := fmt.Sprintf("%s: %s (complete days) + (%s + %s) × %d days = %s", upper(row.Region),
			amount(forecast.CompleteCents), amount(forecast.RateCents), amount(forecast.PendingDailyCents),
			forecast.DaysLeft, amount(forecast.MonthEndCents))
		if forecast.Currency != "" {
			line += " " + forecast.Currency
		}
		lines = append(lines, line)
	}
	return lines
}

// globalCapacity is TS-804's global cap, or nil when none is set.
func (current view) globalCapacity() *budget.Capacity {
	capacity := current.capacityData().Capacity
	if capacity == nil || capacity.State == budget.StateNone {
		return nil
	}
	return capacity
}

// costCapKPI is the global budget cap tile: TS-804's cap against its projection.
func (current view) costCapKPI() kpi {
	href := current.State.link("/cost")
	capacity := current.globalCapacity()
	if capacity == nil {
		return kpi{Label: "Budget cap", Value: "not set", Sub: "TS-804 global budget", Href: href}
	}
	sub := "projected " + money(capacity.ProjectedCents, capacity.Currency)
	if capacity.CapCents > 0 {
		sub += " (" + itoa(int(math.Round(float64(capacity.ProjectedCents)*100/float64(capacity.CapCents)))) + "%)"
	}
	status := costStatus(capacity.State)
	if current.Now.Sub(capacity.At) > budget.AllowanceMaxAge {
		sub += " · stale"
		status = "warn"
	}
	return kpi{Label: "Budget cap", Value: money(capacity.CapCents, capacity.Currency), Sub: sub, Status: status,
		Href: href}
}

// costKPIs are the cost page's tiles.
func (current view) costKPIs() []kpi {
	total := current.costTotals()
	var notes []string
	if total.Reported < total.Expected {
		notes = append(notes, "across "+itoa(total.Reported)+" of "+itoa(total.Expected)+" regions")
	}
	if total.Mixed {
		notes = append(notes, "other currencies left out")
	}
	sub := strings.Join(notes, "; ")
	return []kpi{
		{Label: "Month to date", Value: total.show(total.MonthToDate), Sub: sub, Status: "info",
			Href: current.State.link("/cost")},
		{Label: "Forecast month end", Value: total.show(total.MonthEnd), Sub: sub, Status: "info",
			Href: current.State.link("/cost")},
		{Label: "Forecast next month", Value: total.showFull(total.NextMonth), Sub: sub, Status: "info",
			Href: current.State.link("/cost")},
		current.costCapKPI(),
	}
}

// money formats cents with their currency code, when there is one.
func money(cents uint64, currency string) string {
	if currency == "" {
		return amount(cents)
	}
	return currency + " " + amount(cents)
}

// amount formats cents as a plain decimal.
func amount(cents uint64) string {
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

// costStatus colors the global cap state. Unknown warns; no cap has no pill.
func costStatus(state budget.State) string {
	switch state {
	case budget.StateOK:
		return "ok"
	case budget.StateWarn, budget.StateUnknown:
		return "warn"
	case budget.StateOver:
		return "bad"
	default:
		return ""
	}
}
