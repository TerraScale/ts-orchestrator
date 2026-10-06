package hostpool

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/decisionlog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

var midMonth = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// midSpend projects 14000 for Oct 1..14 plus 17 days at 1000 = 31000; a
// host is charged 17/31 of its monthly price.
func midSpend() *Spend {
	return &Spend{Currency: "USD", MonthCents: 14000, PeakDayCents: 1000,
		Through: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), ObservedAt: midMonth.Add(-time.Hour)}
}

func pricedPool(name string, cents uint64) NodePool {
	pool := generalPool()
	pool.Name, pool.HostMonthlyCents = name, cents
	return pool
}

func launchPlan(pool NodePool, count int) Plan {
	plan := Plan{Reason: "insufficient-capacity", Reclaim: []string{"x"}}
	for ordinal := range count {
		plan.Launch = append(plan.Launch, Launch{Node: pool.NodeName("gru", ordinal), FailureDomain: "fd-1"})
	}
	return plan
}

func TestBudgetValidate(t *testing.T) {
	if err := (Budget{MonthlyCapCents: 1, Currency: "USD"}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, budget := range []Budget{{Currency: "USD"}, {MonthlyCapCents: MaxMonthlyCents + 1, Currency: "USD"},
		{MonthlyCapCents: 1, Currency: "usd"}, {MonthlyCapCents: 1}} {
		if err := budget.Validate(); !errors.Is(err, ErrInvalidPool) {
			t.Errorf("Validate(%+v) = %v", budget, err)
		}
	}
	pool := generalPool()
	pool.HostMonthlyCents = MaxMonthlyCents + 1
	if err := pool.Validate(); !errors.Is(err, ErrInvalidPool) {
		t.Fatalf("overpriced pool accepted: %v", err)
	}
}

func TestBudgetGateAdmitsWholePlansInOrder(t *testing.T) {
	// 31000 projected under a 35000 cap leaves 4000.
	gate := newBudgetGate(&Budget{MonthlyCapCents: 35000, Currency: "USD"}, midSpend(), nil, midMonth)
	first, second, third := pricedPool("first", 1500), pricedPool("second", 1000), pricedPool("third", 1000)
	if plan := gate.admit(first, launchPlan(first, 2)); len(plan.Launch) != 2 || plan.Withheld != 0 {
		t.Fatalf("first pool %+v", plan)
	}
	// 1000 is left: a plan costing more is held whole, reclaims kept.
	if plan := gate.admit(second, launchPlan(second, 2)); len(plan.Launch) != 0 || plan.Withheld != 2 ||
		plan.Hold != reasonBudgetCapped || plan.Reason != "insufficient-capacity" || len(plan.Reclaim) != 1 {
		t.Fatalf("second pool %+v", plan)
	}
	if plan := gate.admit(third, launchPlan(third, 1)); len(plan.Launch) != 1 || plan.Withheld != 0 {
		t.Fatalf("third pool %+v", plan)
	}
	// Without a budget nothing is withheld.
	gate = newBudgetGate(nil, nil, nil, midMonth)
	if plan := gate.admit(first, launchPlan(first, 3)); len(plan.Launch) != 3 || plan.Withheld != 0 {
		t.Fatalf("unbudgeted plan %+v", plan)
	}
}

func TestBudgetGateProjection(t *testing.T) {
	early := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	for name, test := range map[string]struct {
		spend    Spend
		now      time.Time
		headroom int64
	}{
		// 14000 for Oct 1..14 and 17 days at the 1000 peak.
		"this month": {spend: *midSpend(), now: midMonth, headroom: 100000 - 31000},
		// A whole month at the 2000 peak exceeds 1000 + 17 days at it.
		"next month at the peak": {now: midMonth, headroom: 100000 - 62000,
			spend: Spend{Currency: "USD", MonthCents: 1000, PeakDayCents: 2000, Through: october(15), ObservedAt: midMonth}},
		// Before October's first complete day, its cost so far is unknown
		// and the whole month runs at the peak.
		"first day": {now: early, headroom: 100000 - 31000,
			spend: Spend{Currency: "USD", MonthCents: 999999, PeakDayCents: 1000,
				Through: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), ObservedAt: early}},
		"no cost": {now: midMonth, headroom: 100000, spend: Spend{Through: october(15), ObservedAt: midMonth}},
	} {
		gate := newBudgetGate(&Budget{MonthlyCapCents: 100000, Currency: "USD"}, &test.spend, nil, test.now)
		if gate.hold != "" || !gate.limited || gate.headroom != test.headroom {
			t.Errorf("%s: gate = %+v, want headroom %d", name, gate, test.headroom)
		}
	}
}

func TestBudgetGateFailsClosed(t *testing.T) {
	budget := &Budget{MonthlyCapCents: MaxMonthlyCents, Currency: "USD"}
	pool := pricedPool("general", 1)
	cases := map[string]struct {
		spend func(*Spend) *Spend
		now   time.Time
	}{
		"no reading":        {spend: func(*Spend) *Spend { return nil }},
		"stale reading":     {spend: func(s *Spend) *Spend { s.ObservedAt = midMonth.Add(-MaxSpendAge - time.Second); return s }},
		"future reading":    {spend: func(s *Spend) *Spend { s.ObservedAt = midMonth.Add(time.Second); return s }},
		"data past now":     {spend: func(s *Spend) *Spend { s.Through = midMonth.Add(time.Hour); return s }},
		"another currency":  {spend: func(s *Spend) *Spend { s.Currency = "EUR"; return s }},
		"cost, no currency": {spend: func(s *Spend) *Spend { s.Currency = ""; return s }},
		"absurd reading":    {spend: func(s *Spend) *Spend { s.PeakDayCents = maxSpendCents + 1; return s }},
		"last month's reading": {now: time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC),
			spend: func(s *Spend) *Spend { s.ObservedAt = time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC); return s }},
	}
	for name, test := range cases {
		now := test.now
		if now.IsZero() {
			now = midMonth
		}
		gate := newBudgetGate(budget, test.spend(midSpend()), nil, now)
		if plan := gate.admit(pool, launchPlan(pool, 2)); len(plan.Launch) != 0 || plan.Withheld != 2 ||
			plan.Hold != reasonBudgetUnknown || len(plan.Reclaim) != 1 {
			t.Errorf("%s: admitted %+v", name, plan)
		}
	}
	// A pool without a price launches nothing under a budget.
	gate := newBudgetGate(budget, midSpend(), nil, midMonth)
	if plan := gate.admit(pricedPool("general", 0), launchPlan(generalPool(), 1)); plan.Withheld != 1 || plan.Hold != reasonBudgetUnknown {
		t.Fatalf("unpriced pool admitted %+v", plan)
	}
}

type fakeSpend struct {
	calls int
	err   error
	spend Spend
}

func (f *fakeSpend) Spend(ctx context.Context, now time.Time) (Spend, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return Spend{}, errors.New("unbounded spend read")
	}
	f.calls++
	spend := f.spend
	spend.ObservedAt = now
	return spend, f.err
}

// TestScalerHoldsLaunchesOverBudget is not parallel: it installs the
// process-wide decision recorder.
func TestScalerHoldsLaunchesOverBudget(t *testing.T) {
	recorder := &captureRecorder{}
	t.Cleanup(decisionlog.SetDefault(recorder))
	pool := pricedPool("general", 1500)
	view := &fakeView{hosts: []host.HostStatus{registered("gru-1-pool-general-1", "fd-1")},
		desired: []host.Desired{{Cell: "gru", Node: "gru-1-pool-general-1", Role: "api"}}}
	clock := midMonth
	spend := &fakeSpend{spend: *midSpend()}
	// 31000 projected under 35000 leaves 4000: three hosts at 1500 do not
	// fit, and the scaler only recommends.
	budget := &Budget{MonthlyCapCents: 35000, Currency: "USD"}
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{pool}, Hosts: view, Fencer: fencer{leader: true},
		Budget: func() *Budget { return budget }, Spend: spend, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	full := pool.virtualHost("gru", "gru-1-pool-general-1", "fd-1")
	full.Allocated = full.Capacity
	tick := func(step time.Duration, wantReads int, wantHold string) {
		t.Helper()
		clock = clock.Add(step)
		scaler.RequestCapacity(workload.ServiceSpec{Role: "api", Environment: "prod"}, apiDemand(6, full))
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if last := scaler.Last()[pool.Name]; spend.calls != wantReads || last.Hold != wantHold ||
			(last.Withheld == 0) != (wantHold == "") {
			t.Fatalf("after %s: %d spend reads, last plan %+v", clock.Sub(midMonth), spend.calls, last)
		}
	}
	tick(0, 1, reasonBudgetCapped)
	tick(time.Minute, 1, reasonBudgetCapped)
	// A failed read keeps the last reading, and is retried within minutes.
	spend.err = errors.New("usage API down")
	tick(DefaultSpendInterval, 2, reasonBudgetCapped)
	tick(time.Minute, 2, reasonBudgetCapped)
	tick(spendRetry, 3, reasonBudgetCapped)
	// Once the reading is MaxSpendAge old, every launch holds.
	tick(MaxSpendAge, 4, reasonBudgetUnknown)
	// Removing the budget lifts the hold.
	budget = nil
	tick(time.Minute, 4, "")
	if got := recorder.kinds(); !slices.Equal(got, []decisionlog.Kind{decisionlog.KindHeld, decisionlog.KindHeld,
		decisionlog.KindScaleUp, decisionlog.KindHoldCleared}) {
		t.Fatalf("journaled %v", got)
	}
}

func TestScalerLaunchesWithinBudgetAndRereadsInANewMonth(t *testing.T) {
	pool := pricedPool("general", 1500)
	clock := time.Date(2026, 10, 31, 23, 58, 0, 0, time.UTC)
	spend := &fakeSpend{spend: Spend{Currency: "USD", PeakDayCents: 100, Through: october(29)}}
	prov := &provisioner{}
	budget := &Budget{MonthlyCapCents: 10000, Currency: "USD"}
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{pool}, Hosts: &fakeView{}, Fencer: fencer{leader: true},
		Provisioner: prov, Budget: func() *Budget { return budget }, Spend: spend, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prov.launched, []string{"gru-1-pool-general-1"}) || spend.calls != 1 {
		t.Fatalf("launched %v after %d reads", prov.launched, spend.calls)
	}
	// October's reading cannot stand for November: it is read again at
	// once, not after spendRetry.
	clock = time.Date(2026, 11, 1, 0, 1, 0, 0, time.UTC)
	spend.spend.Through = october(30)
	if err := scaler.Tick(context.Background()); err != nil || spend.calls != 2 {
		t.Fatalf("new month: %d reads, %v", spend.calls, err)
	}
}

// Launched hosts are charged until a complete day after their launch is in
// the usage data, so launches add up across ticks while the data lags.
func TestScalerChargesLaunchesUntilTheUsageDataShowsThem(t *testing.T) {
	pool := pricedPool("general", 1500)
	pool.Min = 2
	view := &fakeView{}
	clock := midMonth
	spend := &fakeSpend{spend: *midSpend()}
	prov := &provisioner{clock: &clock}
	// 31000 projected under 34000 leaves 3000: two hosts.
	scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{pool}, Hosts: view, Fencer: fencer{leader: true},
		Provisioner: prov, Budget: func() *Budget { return &Budget{MonthlyCapCents: 34000, Currency: "USD"} },
		Spend: spend, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	// Placement found general-0 and general-1 full and needs one host more.
	var full []placement.WorkloadHost
	for index, domain := range []string{"fd-1", "fd-2"} {
		candidate := pool.virtualHost("gru", pool.NodeName("gru", index), domain)
		candidate.Allocated = candidate.Capacity
		full = append(full, candidate)
	}
	tick := func(demand bool) Plan {
		t.Helper()
		if demand {
			scaler.RequestCapacity(workload.ServiceSpec{Role: "api", Environment: "prod"}, apiDemand(1, full...))
		}
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		return scaler.Last()[pool.Name]
	}
	if plan := tick(false); !slices.Equal(prov.launched, []string{"gru-1-pool-general-1", "gru-1-pool-general-2"}) {
		t.Fatalf("launched %v, plan %+v", prov.launched, plan)
	}
	// The next tick charges both launches: a third host does not fit.
	clock = clock.Add(time.Minute)
	if plan := tick(true); len(prov.launched) != 2 || plan.Hold != reasonBudgetCapped {
		t.Fatalf("launched %v, plan %+v", prov.launched, plan)
	}
	// Registered, they stay charged while the usage data predates them.
	view.hosts = []host.HostStatus{registered("gru-1-pool-general-1", "fd-1"), registered("gru-1-pool-general-2", "fd-2")}
	clock = clock.Add(time.Hour)
	if plan := tick(true); len(prov.launched) != 2 || plan.Hold != reasonBudgetCapped {
		t.Fatalf("registered: launched %v, plan %+v", prov.launched, plan)
	}
	// Once a complete day after their launch is in the data, the reading
	// carries their cost and the third host fits again.
	clock = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	spend.spend = Spend{Currency: "USD", MonthCents: 17000, PeakDayCents: 1000, Through: october(18)}
	if plan := tick(true); !slices.Equal(prov.launched, []string{"gru-1-pool-general-1", "gru-1-pool-general-2", "gru-1-pool-general-3"}) || plan.Withheld != 0 {
		t.Fatalf("caught up: launched %v, plan %+v", prov.launched, plan)
	}
}

func TestBudgetGateChargesUnbilledHosts(t *testing.T) {
	budget := &Budget{MonthlyCapCents: 35000, Currency: "USD"}
	pool := pricedPool("general", 1500)
	if gate := newBudgetGate(budget, midSpend(), []NodePool{pool, pool}, midMonth); gate.hold != "" || gate.headroom != 1000 {
		t.Fatalf("gate = %+v", gate)
	}
	if gate := newBudgetGate(budget, midSpend(), []NodePool{pricedPool("general", 0)}, midMonth); gate.hold != reasonBudgetUnknown {
		t.Fatalf("an unpriced unbilled host was not refused: %+v", gate)
	}
}

// A new cell has no usage yet, so an empty answer is no cost; once the data
// covers a whole day after the cell was created, it is a broken query and
// every launch holds. The cell's age survives restarts: a restarted
// controller of an old cell, or one that cannot date its cell, never
// trusts an empty answer.
func TestScalerTrustsAnEmptyAnswerOnlyInANewCell(t *testing.T) {
	newScaler := func(cellSince time.Time, clock *time.Time, spend *fakeSpend, prov *provisioner) *Scaler {
		t.Helper()
		scaler, err := NewScaler(Config{Cell: "gru", Pools: []NodePool{pricedPool("general", 1500)}, Hosts: &fakeView{},
			Fencer: fencer{leader: true}, Provisioner: prov, CellSince: cellSince,
			Budget: func() *Budget { return &Budget{MonthlyCapCents: 10000, Currency: "BRL"} },
			Spend:  spend, Now: func() time.Time { return *clock }})
		if err != nil {
			t.Fatal(err)
		}
		return scaler
	}
	clock := midMonth
	spend := &fakeSpend{spend: Spend{Empty: true, Through: october(14)}}
	prov := &provisioner{}
	scaler := newScaler(midMonth.Add(-time.Hour), &clock, spend, prov)
	if err := scaler.Tick(context.Background()); err != nil || !slices.Equal(prov.launched, []string{"gru-1-pool-general-1"}) {
		t.Fatalf("new cell: launched %v, %v", prov.launched, err)
	}
	// Through Oct 18 covers Oct 16 11:00 to Oct 17 11:00, a whole day
	// after the cell was created.
	clock = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	spend.spend.Through = october(18)
	if err := scaler.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := scaler.Last()["general"]; last.Hold != reasonBudgetUnknown || len(prov.launched) != 1 {
		t.Fatalf("broken query: launched %v, plan %+v", prov.launched, last)
	}

	for name, cellSince := range map[string]time.Time{"restart of an old cell": october(1).AddDate(0, -6, 0),
		"unknown cell age": {}} {
		clock, prov := midMonth, &provisioner{}
		scaler := newScaler(cellSince, &clock, &fakeSpend{spend: Spend{Empty: true, Through: october(14)}}, prov)
		if err := scaler.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if last := scaler.Last()["general"]; last.Hold != reasonBudgetUnknown || len(prov.launched) != 0 {
			t.Errorf("%s: launched %v, plan %+v", name, prov.launched, last)
		}
	}
}
