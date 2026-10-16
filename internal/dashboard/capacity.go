package dashboard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/regionsuggest"
)

const (
	// capacityTimeout bounds the reads behind one render of the capacity page.
	capacityTimeout = 3 * time.Second
	// budgetSetTimeout bounds one budget change, including the leader's write.
	budgetSetTimeout   = 5 * time.Second
	maxBudgetFormBytes = 4 << 10
	// maxBudgetMajorUnits is the largest budget a form may name: 1e10 units of the currency.
	maxBudgetMajorUnits = 10_000_000_000
)

// ErrBudgetNotHome means the budget can only be set on the home region's dashboard.
var ErrBudgetNotHome = errors.New("set the budget on the home region's dashboard")

// CapacitySource supplies the capacity page and the budget form. Capacity is
// read once per render under capacityTimeout; SetBudget writes the budget
// through the home's global leader.
type CapacitySource interface {
	Capacity(ctx context.Context) CapacityView
	SetBudget(ctx context.Context, next budget.Budget) error
}

// CapacityView is everything the capacity page shows. A nil part is unknown
// or not set; Unavailable names reads that failed.
type CapacityView struct {
	// Home reports that this controller is in the home region, where the
	// budget is set and the region suggestion is computed.
	Home     bool
	Budget   *budget.Budget
	Capacity *budget.Capacity
	// Scale is this region's node scaling status.
	Scale *nodescale.Status
	// Suggestion is the region suggestion's latest result; nil before it is computed.
	Suggestion  *regionsuggest.Suggestion
	Unavailable []string
}

// loadCapacity reads the capacity page's provider once, under its own timeout.
func (current *view) loadCapacity(ctx context.Context, source CapacitySource) {
	ctx, cancel := context.WithTimeout(ctx, capacityTimeout)
	defer cancel()
	capacity := source.Capacity(ctx)
	current.Capacity = &capacity
	current.Unavailable = append(current.Unavailable, capacity.Unavailable...)
}

// capacityData is the loaded capacity view, or an empty one when no provider is attached.
func (current view) capacityData() CapacityView {
	if current.Capacity == nil {
		return CapacityView{}
	}
	return *current.Capacity
}

// budgetForm is the budget form's prefill: the current budget, else the
// capacity document's currency, else BRL.
func (data CapacityView) budgetForm() (amount, currency string) {
	currency = "BRL"
	if data.Capacity != nil && data.Capacity.Currency != "" {
		currency = data.Capacity.Currency
	}
	if data.Budget != nil {
		return majorUnits(data.Budget.MonthlyCapCents), data.Budget.Currency
	}
	return "", currency
}

// signalRow is one node scaling signal for display.
type signalRow struct{ Name, Value string }

// signalRows lists the scaling signals by name.
func (data CapacityView) signalRows() []signalRow {
	if data.Scale == nil {
		return nil
	}
	var rows []signalRow
	for _, name := range slices.Sorted(maps.Keys(data.Scale.Signals)) {
		rows = append(rows, signalRow{Name: string(name), Value: strconv.FormatFloat(data.Scale.Signals[name], 'f', 2, 64)})
	}
	return rows
}

// capacityStatus colors a capacity state.
func capacityStatus(state budget.State) string {
	switch state {
	case budget.StateOK:
		return "ok"
	case budget.StateWarn:
		return "warn"
	case budget.StateOver:
		return "bad"
	default:
		return "idle"
	}
}

// actionStatus colors a scale or suggested action: growth runs, shrinking warns, none is idle.
func actionStatus(action string) string {
	switch action {
	case string(nodescale.Up), "add":
		return "run"
	case string(nodescale.Down), "remove":
		return "warn"
	default:
		return "idle"
	}
}

// majorUnits writes cents as the currency's major unit, for example 500.00.
func majorUnits(cents uint64) string { return fmt.Sprintf("%d.%02d", cents/100, cents%100) }

// budgetAmount is a positive count of the major unit with at most two decimals.
var budgetAmount = regexp.MustCompile(`^[0-9]{1,11}(\.[0-9]{1,2})?$`)

var budgetCurrency = regexp.MustCompile(`^[A-Z]{3}$`)

// parseCents reads a form amount such as 500, 500.5 or 500.50 into cents.
func parseCents(amount string) (uint64, error) {
	if !budgetAmount.MatchString(amount) {
		return 0, errors.New("amount must be a number with at most 2 decimals, such as 500.00")
	}
	whole, fraction, _ := strings.Cut(amount, ".")
	major, err := strconv.ParseUint(whole, 10, 64)
	if err != nil || major > maxBudgetMajorUnits {
		return 0, errors.New("amount must be at most 10000000000")
	}
	var minor uint64
	if fraction != "" {
		// "5" is 50 cents, "05" is 5 cents.
		minor, _ = strconv.ParseUint((fraction + "0")[:2], 10, 64)
	}
	if major == 0 && minor == 0 {
		return 0, errors.New("amount must be more than zero")
	}
	return major*100 + minor, nil
}

// parseBudget builds the budget a form names, stamped by setBy at now.
func parseBudget(form url.Values, setBy string, now time.Time) (budget.Budget, error) {
	cents, err := parseCents(form.Get("amount"))
	if err != nil {
		return budget.Budget{}, err
	}
	currency := form.Get("currency")
	if !budgetCurrency.MatchString(currency) {
		return budget.Budget{}, errors.New("currency must be three upper case letters, such as BRL")
	}
	next := budget.Budget{Schema: budget.Schema, ID: entityid.New(), MonthlyCapCents: cents, Currency: currency,
		SetBy: setBy, SetAt: now}
	if err := next.Validate(); err != nil {
		return budget.Budget{}, err
	}
	return next, nil
}

// sameHostForm refuses a POST whose Origin, or Referer when Origin is absent,
// does not name this request's host. A POST with neither is refused too.
func sameHostForm(request *http.Request) bool {
	source := request.Header.Get("Origin")
	if source == "" {
		source = request.Header.Get("Referer")
	}
	parsed, err := url.Parse(source)
	return err == nil && parsed.Host != "" && parsed.Host == request.Host
}

// clientHost is the address the request came from, without its port.
func clientHost(request *http.Request) string {
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		return host
	}
	return request.RemoteAddr
}

// setBudget changes the monthly budget. A request from another host is refused
// before anything is parsed; the home's global leader writes the budget.
func (dashboard *Dashboard) setBudget(writer http.ResponseWriter, request *http.Request) {
	if !sameHostForm(request) {
		http.Error(writer, "cross-site request refused", http.StatusForbidden)
		return
	}
	journal := dashboard.journal.Load()
	if journal == nil || journal.Capacity == nil {
		http.Error(writer, "the capacity page is still starting", http.StatusServiceUnavailable)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxBudgetFormBytes)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid budget form", http.StatusBadRequest)
		return
	}
	next, err := parseBudget(request.PostForm, "dashboard "+clientHost(request), dashboard.options.Now().UTC())
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), budgetSetTimeout)
	defer cancel()
	switch err := journal.Capacity.SetBudget(ctx, next); {
	case errors.Is(err, ErrBudgetNotHome):
		http.Error(writer, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(writer, "the global leader did not set the budget: "+err.Error(), http.StatusServiceUnavailable)
	default:
		http.Redirect(writer, request, "/capacity", http.StatusSeeOther)
	}
}
