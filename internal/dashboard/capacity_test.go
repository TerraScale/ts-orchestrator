package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/regionsuggest"
)

// fakeCapacity records budget changes and answers reads with view.
type fakeCapacity struct {
	view    CapacityView
	setErr  error
	budgets []budget.Budget
}

func (source *fakeCapacity) Capacity(context.Context) CapacityView { return source.view }

func (source *fakeCapacity) SetBudget(_ context.Context, next budget.Budget) error {
	source.budgets = append(source.budgets, next)
	return source.setErr
}

// postBudget submits the budget form to the dashboard's routes. The test
// request's host is example.com, so the default Origin is same-host; an empty
// header value is an absent one.
func postBudget(handler http.Handler, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/capacity/budget", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	request.RemoteAddr = "192.0.2.7:4444"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func validBudgetForm() url.Values {
	return url.Values{"amount": {"500.00"}, "currency": {"BRL"}}
}

func TestSetBudgetWritesThroughTheHomeAndRedirects(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{}
	handler := newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler()
	for _, headers := range []map[string]string{
		nil,
		{"Origin": "", "Referer": "http://example.com/capacity"},
	} {
		source.budgets = nil
		response := postBudget(handler, validBudgetForm(), headers)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/capacity" {
			t.Fatalf("POST with %v = %d to %q, want 303 to /capacity", headers, response.Code, response.Header().Get("Location"))
		}
		if len(source.budgets) != 1 {
			t.Fatalf("POST with %v wrote %d budgets, want 1", headers, len(source.budgets))
		}
		got := source.budgets[0]
		if got.Schema != budget.Schema || got.MonthlyCapCents != 50000 || got.Currency != "BRL" ||
			got.SetBy != "dashboard 192.0.2.7" || !got.SetAt.Equal(testNow) || got.Validate() != nil {
			t.Fatalf("budget = %+v, want BRL 500.00 set from 192.0.2.7 at the clock", got)
		}
	}
}

func TestSetBudgetRefusesCrossSiteAndBadInput(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		headers map[string]string
		form    url.Values
		code    int
	}{
		"foreign origin":       {map[string]string{"Origin": "https://evil.example"}, validBudgetForm(), http.StatusForbidden},
		"null origin":          {map[string]string{"Origin": "null"}, validBudgetForm(), http.StatusForbidden},
		"foreign referer":      {map[string]string{"Origin": "", "Referer": "https://evil.example/capacity"}, validBudgetForm(), http.StatusForbidden},
		"no origin or referer": {map[string]string{"Origin": ""}, validBudgetForm(), http.StatusForbidden},
		"zero amount":          {nil, url.Values{"amount": {"0"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"negative amount":      {nil, url.Values{"amount": {"-1"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"three decimals":       {nil, url.Values{"amount": {"1.001"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"exponent":             {nil, url.Values{"amount": {"1e3"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"trailing point":       {nil, url.Values{"amount": {"500."}, "currency": {"BRL"}}, http.StatusBadRequest},
		"empty amount":         {nil, url.Values{"amount": {""}, "currency": {"BRL"}}, http.StatusBadRequest},
		"over the limit":       {nil, url.Values{"amount": {"10000000001"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"cents over the limit": {nil, url.Values{"amount": {"10000000000.01"}, "currency": {"BRL"}}, http.StatusBadRequest},
		"lower case currency":  {nil, url.Values{"amount": {"500"}, "currency": {"brl"}}, http.StatusBadRequest},
		"four letter currency": {nil, url.Values{"amount": {"500"}, "currency": {"BRLX"}}, http.StatusBadRequest},
		"missing currency":     {nil, url.Values{"amount": {"500"}}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			source := &fakeCapacity{}
			handler := newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler()
			response := postBudget(handler, tc.form, tc.headers)
			if response.Code != tc.code {
				t.Fatalf("POST = %d %q, want %d", response.Code, response.Body.String(), tc.code)
			}
			if len(source.budgets) != 0 {
				t.Fatalf("refused POST wrote %d budgets", len(source.budgets))
			}
		})
	}
}

func TestParseCentsReadsTheMajorUnit(t *testing.T) {
	t.Parallel()
	for amount, want := range map[string]uint64{"500": 50000, "500.5": 50050, "500.50": 50050, "500.05": 50005, "0.01": 1,
		"10000000000": 1_000_000_000_000} {
		got, err := parseCents(amount)
		if err != nil || got != want {
			t.Errorf("parseCents(%q) = %d, %v; want %d", amount, got, err, want)
		}
	}
}

func TestSetBudgetOutsideTheHomeConflictsAndSilentLeaderIsUnavailable(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{setErr: ErrBudgetNotHome}
	handler := newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler()
	response := postBudget(handler, validBudgetForm(), nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "set the budget on the home region's dashboard") {
		t.Fatalf("POST outside the home = %d %q, want 409 naming the home", response.Code, response.Body.String())
	}

	source.setErr = errors.New("ask the global leader: nats: timeout")
	response = postBudget(handler, validBudgetForm(), nil)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "global leader did not set the budget") {
		t.Fatalf("POST with a silent leader = %d %q, want 503", response.Code, response.Body.String())
	}

	starting := newTestDashboard(Options{}).Handler()
	if response := postBudget(starting, validBudgetForm(), nil); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST before the provider is attached = %d, want 503", response.Code)
	}
}

func TestCapacityPageShowsBudgetCapacityScalingAndSuggestion(t *testing.T) {
	t.Parallel()
	at := testNow.Add(-time.Minute)
	source := &fakeCapacity{view: CapacityView{Home: true,
		Budget: &budget.Budget{Schema: budget.Schema, ID: "00000000009DQWP5T1WY4KP1TS", MonthlyCapCents: 50000,
			Currency: "BRL", SetBy: "dashboard 192.0.2.7", SetAt: testNow.Add(-48 * time.Hour)},
		Capacity: &budget.Capacity{Schema: budget.Schema, At: at, CapCents: 50000, Currency: "BRL", ProjectedCents: 42000,
			Ratio: 0.84, State: budget.StateWarn, Reason: "projected spend is 84% of the cap",
			Regions: []budget.RegionAllowance{{Cell: "gru", Nodes: 4, Want: 5, Allowance: 4, Pressure: 0.9}}},
		Scale: &nodescale.Status{Schema: nodescale.StatusSchema, Cell: "gru", At: at, Nodes: 4, QuorumNodes: 3,
			PoolNodes: 1, Want: 5, Allowance: 4, Action: nodescale.Up, Pressure: 0.9,
			Reason:     "cpu above target for ten minutes",
			Signals:    map[nodescale.Signal]float64{nodescale.SignalCPU: 0.91, nodescale.SignalMemory: 0.4},
			InFlight:   &nodescale.InFlight{ID: "op-1", Kind: nodescale.Up, Step: "launch", Node: "ts-gru-node-7", Started: at},
			LastChange: at},
		Suggestion: &regionsuggest.Suggestion{Action: "none", Reason: "no region is saturated", At: at},
	}}
	body := get(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler(), "/capacity").Body.String()
	for _, want := range []string{
		"Capacity", "Monthly budget", "BRL 500.00", "dashboard 192.0.2.7", `action="/capacity/budget"`,
		`value="500.00"`, `value="BRL"`, "BRL 420.00", "84", "projected spend is 84% of the cap",
		"GRU", "4 nodes (3 quorum, 1 pool)", "cpu above target for ten minutes", "0.91",
		"launch", "ts-gru-node-7", "no region is saturated", "Information only: regions change only when the user runs ts-orch region create or remove.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("capacity page lacks %q", want)
		}
	}
}

func TestCapacityPageExplainsAnEmptyHome(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{view: CapacityView{Home: true}}
	body := get(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler(), "/capacity").Body.String()
	for _, want := range []string{"No monthly budget is set; nothing grows past its current size.",
		"No capacity document has been written yet.", "This region has no node scaling status yet.",
		"The region suggestion has not been computed yet.", `action="/capacity/budget"`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty home capacity page lacks %q", want)
		}
	}
}

func TestCapacityPageOutsideTheHomeHidesTheFormAndSuggestion(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{view: CapacityView{Unavailable: []string{"capacity document"},
		Budget: &budget.Budget{Schema: budget.Schema, ID: "00000000009DQWP5T1WY4KP1TS", MonthlyCapCents: 50000,
			Currency: "BRL", SetBy: "dashboard 192.0.2.7", SetAt: testNow}}}
	body := get(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}).Handler(), "/capacity").Body.String()
	for _, want := range []string{"The budget is set on the home region's dashboard.",
		"The region suggestion is computed in the home region.", "could not be read", "BRL 500.00"} {
		if !strings.Contains(body, want) {
			t.Errorf("mirror capacity page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/capacity/budget"`) {
		t.Error("a region outside the home shows the budget form")
	}
}
