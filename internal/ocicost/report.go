// Package ocicost reports a region's OCI spend. The regional authority
// leader reads its OCI region's cost from the Usage API every hour into one
// report in the region's NATS KV; Project forecasts the month from it. The
// dashboard and the region's node scaler read the same report
// (docs/oci-cost.md).
package ocicost

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

const (
	// Version is the report's wire version.
	Version = 1
	// UsageLag is how long OCI usage data may take to arrive: a day counts
	// as complete once it ended at least this long ago.
	UsageLag = 48 * time.Hour
	// RateDays is how many complete days the daily rate averages.
	RateDays = 7
	// MaxReportAge is how long a report may stand in for failed reads.
	MaxReportAge = 6 * time.Hour

	// ComponentTag is the freeform tag the component lines group by.
	ComponentTag = "terrascale-component"
	// RegionTag is the freeform tag holding the resource's region.
	RegionTag = "terrascale-region"

	maxDays  = 64
	maxLines = 64
	// maxCents bounds an amount; more is a corrupt answer, not a bill.
	maxCents     = 1 << 40
	maxNameBytes = 64
	day          = 24 * time.Hour
)

// Components are the values of ComponentTag. Cost under any other value
// counts as untagged.
var Components = []string{"controller", "terrabase", "node-pool", "apps", "network", "releases", "images",
	"disaster-recovery", "storage"}

var (
	cellPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	// ErrInvalidReport marks a report that fails Validate.
	ErrInvalidReport = errors.New("invalid OCI cost report")
)

// Day is one UTC day's cost.
type Day struct {
	Day   time.Time `json:"day"`
	Cents uint64    `json:"cents"`
}

// Line is one service's or component's month-to-date cost.
type Line struct {
	Name  string `json:"name"`
	Cents uint64 `json:"cents"`
}

// Report is one OCI region's cost as the Usage API last answered it.
// Amounts are whole cents of Currency, rounded up; credits count as zero.
type Report struct {
	Version   int    `json:"version"`
	Cell      string `json:"cell"`
	OCIRegion string `json:"oci_region"`
	// Currency is empty when OCI reported no cost at all.
	Currency   string    `json:"currency,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	// Through ends the last complete day.
	Through time.Time `json:"through"`
	// Days are the days with usage, oldest first, from the rate window or
	// the month's first day, whichever is earlier; the newest are partial.
	Days []Day `json:"days,omitempty"`
	// Services and Components are this month's lines, costliest first.
	// Components hold only tagged cost; the rest is untagged.
	Services   []Line `json:"services,omitempty"`
	Components []Line `json:"components,omitempty"`
}

// Empty reports whether OCI answered without a single day of usage.
func (r Report) Empty() bool { return len(r.Days) == 0 }

// Validate bounds the report and checks its order, so a reader can trust
// any report it decodes.
func (r Report) Validate() error {
	switch {
	case r.Version != Version:
		return fmt.Errorf("%w: version %d", ErrInvalidReport, r.Version)
	case !cellPattern.MatchString(r.Cell) || r.OCIRegion == "" || len(r.OCIRegion) > maxNameBytes:
		return fmt.Errorf("%w: cell and OCI region are required", ErrInvalidReport)
	case r.Currency != "" && !currencyPattern.MatchString(r.Currency):
		return fmt.Errorf("%w: currency %q", ErrInvalidReport, r.Currency)
	case r.ObservedAt.IsZero() || !midnight(r.Through) || r.Through.After(r.ObservedAt):
		return fmt.Errorf("%w: needs an observation time after a UTC-midnight through", ErrInvalidReport)
	case len(r.Days) > maxDays || len(r.Services) > maxLines || len(r.Components) > maxLines:
		return fmt.Errorf("%w: more than %d days or %d lines", ErrInvalidReport, maxDays, maxLines)
	}
	var total uint64
	for index, entry := range r.Days {
		if !midnight(entry.Day) || index > 0 && !r.Days[index-1].Day.Before(entry.Day) || entry.Cents > maxCents {
			return fmt.Errorf("%w: days must be sorted unique UTC midnights within bounds", ErrInvalidReport)
		}
		total += entry.Cents
	}
	for _, lines := range [][]Line{r.Services, r.Components} {
		for index, line := range lines {
			if line.Name == "" || len(line.Name) > maxNameBytes || line.Cents > maxCents ||
				slices.ContainsFunc(lines[:index], func(other Line) bool { return other.Name == line.Name }) {
				return fmt.Errorf("%w: lines need unique bounded names", ErrInvalidReport)
			}
			total += line.Cents
		}
	}
	for _, line := range r.Components {
		if !slices.Contains(Components, line.Name) {
			return fmt.Errorf("%w: unknown component %q", ErrInvalidReport, line.Name)
		}
	}
	if r.Currency == "" && total != 0 {
		return fmt.Errorf("%w: cost without a currency", ErrInvalidReport)
	}
	return nil
}

func midnight(at time.Time) bool {
	return !at.IsZero() && at.Location() == time.UTC && at.Equal(at.Truncate(day))
}

// monthBounds returns the UTC month holding at and the next month's start.
func monthBounds(at time.Time) (time.Time, time.Time) {
	at = at.UTC()
	start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}
