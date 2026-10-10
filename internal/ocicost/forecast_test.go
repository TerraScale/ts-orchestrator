package ocicost

import (
	"testing"
	"time"
)

// fcAt is a 2026 UTC time at hour o'clock.
func fcAt(month time.Month, d, hour int) time.Time {
	return time.Date(2026, month, d, hour, 0, 0, 0, time.UTC)
}

// fcDays is one day of cents for each day from first to last of month.
func fcDays(month time.Month, first, last int, cents uint64) []Day {
	var days []Day
	for d := first; d <= last; d++ {
		days = append(days, Day{Day: fcAt(month, d, 0), Cents: cents})
	}
	return days
}

func fcReport(observed, through time.Time, days ...Day) Report {
	return Report{Version: Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "USD",
		ObservedAt: observed, Through: through, Days: days}
}

// midMonthReport is 16 October at noon with complete days to 13 October.
// Days 1 to 13 cost 1000 each, 14 and 15 are partial at 500 each.
func midMonthReport() Report {
	days := append(fcDays(time.October, 1, 13, 1000),
		Day{Day: fcAt(time.October, 14, 0), Cents: 500},
		Day{Day: fcAt(time.October, 15, 0), Cents: 500})
	return fcReport(fcAt(time.October, 16, 11), fcAt(time.October, 14, 0), days...)
}

func midMonthForecast() Forecast {
	return Forecast{
		Currency:         "USD",
		ObservedAt:       fcAt(time.October, 16, 11),
		Through:          fcAt(time.October, 14, 0),
		MonthToDateCents: 14000,
		CompleteCents:    13000,
		RateFrom:         fcAt(time.October, 7, 0),
		AveragedDays:     7,
		RateCents:        1000,
		DaysLeft:         18,
		MonthEndCents:    31000,
		NextMonthCents:   30000,
	}
}

func TestProject(t *testing.T) {
	midNow := fcAt(time.October, 16, 12)
	tests := []struct {
		name   string
		report Report
		now    time.Time
		hosts  []Host
		want   Forecast
	}{
		{
			name:   "mid-month",
			report: midMonthReport(),
			now:    midNow,
			want:   midMonthForecast(),
		},
		{
			// Rate: 23 to 29 October at 700 each, 4900 / 7 = 700.
			// Month end: 0 + 700 * 30 = 21000. Next: 700 * 31 = 21700.
			name: "first of month",
			report: fcReport(fcAt(time.November, 1, 4), fcAt(time.October, 30, 0),
				append(fcDays(time.October, 20, 31, 700), Day{Day: fcAt(time.November, 1, 0), Cents: 100})...),
			now: fcAt(time.November, 1, 6),
			want: Forecast{
				Currency:         "USD",
				ObservedAt:       fcAt(time.November, 1, 4),
				Through:          fcAt(time.October, 30, 0),
				MonthToDateCents: 100,
				RateFrom:         fcAt(time.October, 23, 0),
				AveragedDays:     7,
				RateCents:        700,
				DaysLeft:         30,
				MonthEndCents:    21000,
				NextMonthCents:   21700,
			},
		},
		{
			// Rate: 12 and 13 October at 900 each, 1800 / 2 = 900.
			// Month to date: 900 + 900 + 100 = 1900. Complete: 1800.
			// Month end: 1800 + 900 * 18 = 18000. Next: 900 * 30 = 27000.
			name: "new region",
			report: fcReport(fcAt(time.October, 16, 11), fcAt(time.October, 14, 0),
				Day{Day: fcAt(time.October, 12, 0), Cents: 900},
				Day{Day: fcAt(time.October, 13, 0), Cents: 900},
				Day{Day: fcAt(time.October, 14, 0), Cents: 100}),
			now: midNow,
			want: Forecast{
				Currency:         "USD",
				ObservedAt:       fcAt(time.October, 16, 11),
				Through:          fcAt(time.October, 14, 0),
				MonthToDateCents: 1900,
				CompleteCents:    1800,
				RateFrom:         fcAt(time.October, 12, 0),
				AveragedDays:     2,
				RateCents:        900,
				DaysLeft:         18,
				MonthEndCents:    18000,
				NextMonthCents:   27000,
			},
		},
		{
			// No complete day: the rate is 0, and the host's daily price
			// 36500 * 12 / 365 = 1200 is all pending.
			// Month end: 0 + 1200 * 18 = 21600. Next: 1200 * 30 = 36000.
			name: "no complete day",
			report: fcReport(fcAt(time.October, 16, 11), fcAt(time.October, 14, 0),
				Day{Day: fcAt(time.October, 14, 0), Cents: 500},
				Day{Day: fcAt(time.October, 15, 0), Cents: 500}),
			now:   midNow,
			hosts: []Host{{MonthlyCents: 36500}},
			want: Forecast{
				Currency:          "USD",
				ObservedAt:        fcAt(time.October, 16, 11),
				Through:           fcAt(time.October, 14, 0),
				MonthToDateCents:  1000,
				RateFrom:          fcAt(time.October, 14, 0),
				PendingDailyCents: 1200,
				DaysLeft:          18,
				MonthEndCents:     21600,
				NextMonthCents:    36000,
			},
		},
		{
			// Pending: 686 (created 11 October) + 0 (created 1 October)
			// + 1200 (no creation time) + 1200 (created 15 October) = 3086.
			// Month end: 13000 + (1000 + 3086) * 18 = 86548.
			// Next: 4086 * 30 = 122580.
			name:   "hosts in window",
			report: midMonthReport(),
			now:    midNow,
			hosts: []Host{
				{Created: fcAt(time.October, 11, 0), MonthlyCents: 36500},
				{Created: fcAt(time.October, 1, 0), MonthlyCents: 36500},
				{MonthlyCents: 36500},
				{Created: fcAt(time.October, 15, 0), MonthlyCents: 36500},
			},
			want: Forecast{
				Currency:          "USD",
				ObservedAt:        fcAt(time.October, 16, 11),
				Through:           fcAt(time.October, 14, 0),
				MonthToDateCents:  14000,
				CompleteCents:     13000,
				RateFrom:          fcAt(time.October, 7, 0),
				AveragedDays:      7,
				RateCents:         1000,
				PendingDailyCents: 3086,
				DaysLeft:          18,
				MonthEndCents:     86548,
				NextMonthCents:    122580,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(tc.report, tc.now, tc.hosts)
			if got != tc.want {
				t.Errorf("Project() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestProjectPending(t *testing.T) {
	// The window is 7 October to 14 October, seven days.
	// Daily price of a 36500 host is 1200; missed days of 7 cost 1200 * missed / 7.
	tests := []struct {
		name string
		host Host
		want uint64
	}{
		{name: "created inside window: 4 missed days", host: Host{Created: fcAt(time.October, 11, 0), MonthlyCents: 36500}, want: 686},
		{name: "created on window start: nothing missed", host: Host{Created: fcAt(time.October, 7, 0), MonthlyCents: 36500}, want: 0},
		{name: "created before window: nothing missed", host: Host{Created: fcAt(time.October, 1, 0), MonthlyCents: 36500}, want: 0},
		{name: "created on through: all missed", host: Host{Created: fcAt(time.October, 14, 0), MonthlyCents: 36500}, want: 1200},
		{name: "created after through: all missed", host: Host{Created: fcAt(time.October, 15, 0), MonthlyCents: 36500}, want: 1200},
		{name: "no creation time: all missed", host: Host{MonthlyCents: 36500}, want: 1200},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Project(midMonthReport(), fcAt(time.October, 16, 12), []Host{tc.host})
			if got.PendingDailyCents != tc.want {
				t.Errorf("PendingDailyCents = %d, want %d", got.PendingDailyCents, tc.want)
			}
		})
	}
}

func TestAssess(t *testing.T) {
	midNow := fcAt(time.October, 16, 12)
	// withForecast is the mid-month forecast with one field changed.
	withForecast := func(change func(*Forecast)) *Forecast {
		forecast := midMonthForecast()
		change(&forecast)
		return &forecast
	}
	tests := []struct {
		name     string
		capCents uint64
		now      time.Time
		forecast *Forecast
		want     Budget
	}{
		{
			name:     "no cap",
			capCents: 0,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateNone},
		},
		{
			name:     "no report",
			capCents: 40000,
			now:      midNow,
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "no cost report"},
		},
		{
			name:     "stale report",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.ObservedAt = midNow.Add(-MaxReportAge - time.Minute) }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "cost report is stale"},
		},
		{
			name:     "report from the future",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.ObservedAt = midNow.Add(time.Minute) }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "cost report is from the future"},
		},
		{
			name:     "report from last month",
			capCents: 40000,
			now:      fcAt(time.November, 1, 2),
			forecast: withForecast(func(f *Forecast) { f.ObservedAt = fcAt(time.October, 31, 23) }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "cost report is from last month"},
		},
		{
			name:     "data ends after now",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.Through = fcAt(time.October, 17, 0) }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "cost data ends after now"},
		},
		{
			name:     "out of range",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.MonthEndCents = maxCents + 1 }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: "cost report is out of range"},
		},
		{
			name:     "other currency",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.Currency = "EUR" }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: `cost is in "EUR", the budget in "USD"`},
		},
		{
			name:     "cost without currency",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.Currency = "" }),
			want:     Budget{State: StateUnknown, CapCents: 40000, Currency: "USD", Reason: `cost is in "", the budget in "USD"`},
		},
		{
			name:     "no cost and no currency matches any budget",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) {
				f.Currency = ""
				f.MonthToDateCents = 0
				f.MonthEndCents = 0
				f.NextMonthCents = 0
			}),
			want: Budget{State: StateOK, CapCents: 40000, Currency: "USD", HeadroomCents: 40000},
		},
		{
			// Projected 31000: 3100000 < 40000 * 80.
			name:     "ok",
			capCents: 40000,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateOK, CapCents: 40000, Currency: "USD", ProjectedCents: 31000, HeadroomCents: 9000},
		},
		{
			// 3100000 >= 38000 * 80 = 3040000.
			name:     "warn",
			capCents: 38000,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateWarn, CapCents: 38000, Currency: "USD", ProjectedCents: 31000, HeadroomCents: 7000},
		},
		{
			// 38750 * 80 = 3100000, exactly 80 percent.
			name:     "warn exactly at 80 percent",
			capCents: 38750,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateWarn, CapCents: 38750, Currency: "USD", ProjectedCents: 31000, HeadroomCents: 7750},
		},
		{
			// 38751 * 80 = 3100080 > 3100000, just under 80 percent.
			name:     "ok just under 80 percent",
			capCents: 38751,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateOK, CapCents: 38751, Currency: "USD", ProjectedCents: 31000, HeadroomCents: 7751},
		},
		{
			name:     "over exactly at cap",
			capCents: 31000,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateOver, CapCents: 31000, Currency: "USD", ProjectedCents: 31000, HeadroomCents: 0},
		},
		{
			name:     "over",
			capCents: 30000,
			now:      midNow,
			forecast: withForecast(func(*Forecast) {}),
			want:     Budget{State: StateOver, CapCents: 30000, Currency: "USD", ProjectedCents: 31000, HeadroomCents: -1000},
		},
		{
			// Next month 40000 is the larger projection: 4000000 < 60000 * 80.
			name:     "projection is the larger of month end and next month",
			capCents: 60000,
			now:      midNow,
			forecast: withForecast(func(f *Forecast) { f.NextMonthCents = 40000 }),
			want:     Budget{State: StateOK, CapCents: 60000, Currency: "USD", ProjectedCents: 40000, HeadroomCents: 20000},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.capCents, "USD", tc.forecast, tc.now)
			if got != tc.want {
				t.Errorf("Assess() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
