package hostpool

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// MaxMonthlyCents bounds a budget cap and a pool host's monthly price.
const MaxMonthlyCents = 100_000_000

const (
	// UsageLag is how long OCI usage data may take to arrive: a day counts
	// as complete once it ended at least this long ago.
	UsageLag = 48 * time.Hour
	// PeakDays is how many complete days the projection takes its daily
	// rate from.
	PeakDays = 3
	// DefaultSpendInterval is how often the scaler reads the spend.
	DefaultSpendInterval = time.Hour
	// MaxSpendAge is how long a reading may stand in for failed reads.
	MaxSpendAge = 6 * time.Hour
	// maxSpendCents bounds a reading; more is a corrupt answer.
	maxSpendCents = 1 << 40
	day           = 24 * time.Hour
)

var currencyRE = regexp.MustCompile(`^[A-Z]{3}$`)

// Budget is a cell's signed monthly spending cap, in cents of an ISO 4217
// currency. Pool hosts launch only while the cell's projected spend stays
// within it.
type Budget struct {
	MonthlyCapCents uint64 `json:"monthly_cap_cents"`
	Currency        string `json:"currency"`
}

// Validate requires a positive bounded cap and a currency code.
func (b Budget) Validate() error {
	if b.MonthlyCapCents == 0 || b.MonthlyCapCents > MaxMonthlyCents || !currencyRE.MatchString(b.Currency) {
		return fmt.Errorf("%w: budget needs a cap within 1..%d cents and a currency code", ErrInvalidPool, MaxMonthlyCents)
	}
	return nil
}

// Spend is a cell's billed cost from the OCI usage API. Usage data lags, so
// it covers only complete days, which end at Through.
type Spend struct {
	// Currency is empty when OCI reported no cost at all.
	Currency string
	// MonthCents is the cost of the month's complete days.
	MonthCents uint64
	// PeakDayCents is the highest cost of the PeakDays days before Through.
	PeakDayCents uint64
	// Empty is set when OCI answered without a single row.
	Empty      bool
	Through    time.Time
	ObservedAt time.Time
}

// SpendSource reads a cell's spend at now.
type SpendSource interface {
	Spend(ctx context.Context, now time.Time) (Spend, error)
}

func monthBounds(at time.Time) (time.Time, time.Time) {
	at = at.UTC()
	start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
	return start, start.AddDate(0, 1, 0)
}

// Budget hold reasons.
const (
	reasonBudgetCapped  = "budget-capped"
	reasonBudgetUnknown = "budget-unknown"
)

// budgetGate is one tick's budget headroom, shared by every pool in order.
// A zero gate admits everything: the cell has no budget.
type budgetGate struct {
	limited bool
	// unknown holds every launch: the spend cannot be trusted.
	unknown bool
	// headroom is what launches may still add, in cents a month.
	headroom int64
}

// newBudgetGate projects the spend from a usable reading: the larger of
// this month's (its complete days, then the peak day until the month ends)
// and a whole month at the peak day, so the cap holds next month too. Each
// unbilled host, a pool host the reading may not show yet, is charged its
// full monthly price on top.
func newBudgetGate(budget *Budget, spend *Spend, unbilled []NodePool, now time.Time) budgetGate {
	if budget == nil {
		return budgetGate{}
	}
	start, end := monthBounds(now)
	if spend == nil || now.Sub(spend.ObservedAt) > MaxSpendAge || now.Before(spend.ObservedAt) ||
		spend.ObservedAt.Before(start) || spend.Through.After(now) ||
		spend.MonthCents > maxSpendCents || spend.PeakDayCents > maxSpendCents ||
		spend.Currency != budget.Currency && (spend.Currency != "" || spend.MonthCents+spend.PeakDayCents != 0) {
		return budgetGate{limited: true, unknown: true}
	}
	// Early in a month no complete day of it exists yet.
	from, month := spend.Through, int64(spend.MonthCents)
	if from.Before(start) {
		from, month = start, 0
	}
	peak := int64(spend.PeakDayCents)
	remaining, whole := int64((end.Sub(from)+day-1)/day), int64(end.Sub(start)/day)
	gate := budgetGate{limited: true, headroom: int64(budget.MonthlyCapCents) - max(month+peak*remaining, peak*whole)}
	for _, pool := range unbilled {
		if pool.HostMonthlyCents == 0 {
			return budgetGate{limited: true, unknown: true}
		}
		gate.headroom -= int64(pool.HostMonthlyCents)
	}
	return gate
}

// admit lets a pool's launches through whole, charging each host its full
// monthly price, or holds them all: part of a plan may place nothing.
func (g *budgetGate) admit(pool NodePool, plan Plan) Plan {
	if !g.limited || len(plan.Launch) == 0 {
		return plan
	}
	cost := int64(pool.HostMonthlyCents) * int64(len(plan.Launch))
	switch {
	case g.unknown || pool.HostMonthlyCents == 0:
		plan.Hold = reasonBudgetUnknown
	case cost > g.headroom:
		plan.Hold = reasonBudgetCapped
	default:
		g.headroom -= cost
		return plan
	}
	plan.Withheld, plan.Launch = len(plan.Launch), nil
	return plan
}
