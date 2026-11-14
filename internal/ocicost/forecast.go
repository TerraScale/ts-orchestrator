package ocicost

import "time"

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
