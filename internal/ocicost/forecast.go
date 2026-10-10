package ocicost

import "time"

// Host is a host whose full cost the forecast must include although the
// daily rate may not show all of it yet: an autoscaled host and its
// monthly list price.
type Host struct {
	Created      time.Time
	MonthlyCents uint64
}

// Forecast is Project's answer, in whole cents of Currency.
type Forecast struct {
	Currency   string    `json:"currency,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Through    time.Time `json:"through"`
	// MonthToDateCents sums this month's days, the partial ones included.
	MonthToDateCents uint64 `json:"month_to_date_cents"`
	// CompleteCents sums this month's complete days, those before Through.
	CompleteCents uint64 `json:"complete_cents"`
	// RateCents is the average day of the AveragedDays complete days from
	// RateFrom to Through.
	RateFrom     time.Time `json:"rate_from"`
	AveragedDays int       `json:"averaged_days"`
	RateCents    uint64    `json:"rate_cents"`
	// PendingDailyCents is what the hosts add a day beyond the rate.
	PendingDailyCents uint64 `json:"pending_daily_cents"`
	// DaysLeft counts the days from Through, or from the month's first day
	// when Through is earlier, to the month's end.
	DaysLeft       int    `json:"days_left"`
	MonthEndCents  uint64 `json:"month_end_cents"`
	NextMonthCents uint64 `json:"next_month_cents"`
}

// Project forecasts the month of now from the report. Hosts add the cost
// the daily rate has not averaged yet, so the forecast errs high, never low.
func Project(report Report, now time.Time, hosts []Host) Forecast {
	monthStart, monthEnd := monthBounds(now)
	nextEnd := monthEnd.AddDate(0, 1, 0)
	through := report.Through
	forecast := Forecast{Currency: report.Currency, ObservedAt: report.ObservedAt, Through: through}

	for _, entry := range report.Days {
		inMonth := !entry.Day.Before(monthStart)
		if inMonth && entry.Day.Before(monthEnd) {
			forecast.MonthToDateCents += entry.Cents
		}
		if inMonth && entry.Day.Before(through) {
			forecast.CompleteCents += entry.Cents
		}
	}

	// A new region averages only the days it has, so its rate is not diluted
	// by days before it existed.
	from := through.Add(-RateDays * day)
	if len(report.Days) > 0 && report.Days[0].Day.After(from) {
		from = report.Days[0].Day
	}
	if from.After(through) {
		from = through
	}
	n := int(through.Sub(from) / day)
	var window uint64
	for _, entry := range report.Days {
		if !entry.Day.Before(from) && entry.Day.Before(through) {
			window += entry.Cents
		}
	}
	forecast.RateFrom = from
	forecast.AveragedDays = n
	if n > 0 {
		forecast.RateCents = ceilDiv(window, uint64(n))
	}

	var pending uint64
	for _, host := range hosts {
		daily := ceilDiv(host.MonthlyCents*12, 365)
		if n == 0 {
			pending += daily
			continue
		}
		var covered int
		switch {
		case !host.Created.IsZero() && !host.Created.After(from):
			covered = n
		case host.Created.IsZero() || !host.Created.Before(through):
			covered = 0
		default:
			covered = min(n, int(through.Sub(host.Created)/day))
		}
		missed := n - covered
		pending += ceilDiv(daily*uint64(missed), uint64(n))
	}
	forecast.PendingDailyCents = pending

	start := through
	if start.Before(monthStart) {
		start = monthStart
	}
	forecast.DaysLeft = int(monthEnd.Sub(start) / day)
	perDay := forecast.RateCents + pending
	forecast.MonthEndCents = forecast.CompleteCents + perDay*uint64(forecast.DaysLeft)
	forecast.NextMonthCents = perDay * uint64(nextEnd.Sub(monthEnd)/day)
	return forecast
}

// ceilDiv rounds up, so every division in a projection errs high.
func ceilDiv(a, b uint64) uint64 {
	return (a + b - 1) / b
}
