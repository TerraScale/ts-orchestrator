package dashboard

import (
	"context"
	"errors"
	"io"
	"net/http"
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

// capacityRequest keeps the original example.com host for same-host form checks.
func capacityRequest(t *testing.T, dashboard *Dashboard, form url.Values, headers map[string]string) (*http.Response, string) {
	t.Helper()
	server := newStreamServer(t, dashboard)
	defer server.Close() // Join handlers before callers inspect or change the provider.
	client := *server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	method, path := http.MethodGet, "/capacity"
	if form != nil {
		method, path = http.MethodPost, "/capacity/budget"
	}
	request, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.com"
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "http://example.com")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("%s %s read=%v close=%v", method, path, readErr, closeErr)
	}
	return response, string(body)
}

func validBudgetForm() url.Values {
	return url.Values{"amount": {"500.00"}, "currency": {"BRL"}}
}

func TestSetBudgetWritesThroughTheHomeAndRedirects(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{}
	dashboard := newTestDashboard(Options{Journal: &Journal{Capacity: source}})
	for _, headers := range []map[string]string{
		nil,
		{"Origin": "", "Referer": "http://example.com/capacity"},
	} {
		source.budgets = nil
		response, _ := capacityRequest(t, dashboard, validBudgetForm(), headers)
		if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/capacity" {
			t.Fatalf("POST with %v = %d to %q, want 303 to /capacity", headers, response.StatusCode, response.Header.Get("Location"))
		}
		if len(source.budgets) != 1 {
			t.Fatalf("POST with %v wrote %d budgets, want 1", headers, len(source.budgets))
		}
		got := source.budgets[0]
		if got.Schema != budget.Schema || got.MonthlyCapCents != 50000 || got.Currency != "BRL" ||
			got.SetBy != "dashboard 127.0.0.1" || !got.SetAt.Equal(testNow) || got.Validate() != nil {
			t.Fatalf("budget = %+v, want BRL 500.00 set from 127.0.0.1 at the clock", got)
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
			dashboard := newTestDashboard(Options{Journal: &Journal{Capacity: source}})
			response, body := capacityRequest(t, dashboard, tc.form, tc.headers)
			if response.StatusCode != tc.code {
				t.Fatalf("POST = %d %q, want %d", response.StatusCode, body, tc.code)
			}
			if len(source.budgets) != 0 {
				t.Fatalf("refused POST wrote %d budgets", len(source.budgets))
			}
		})
	}
}

func TestBudgetFormReadsTheMajorUnit(t *testing.T) {
	t.Parallel()
	for amount, want := range map[string]uint64{"500": 50000, "500.5": 50050, "500.50": 50050, "500.05": 50005, "0.01": 1, "10000000000": 1_000_000_000_000} {
		source := &fakeCapacity{}
		dashboard := newTestDashboard(Options{Journal: &Journal{Capacity: source}})
		response, _ := capacityRequest(t, dashboard, url.Values{"amount": {amount}, "currency": {"BRL"}}, nil)
		if response.StatusCode != http.StatusSeeOther || len(source.budgets) != 1 || source.budgets[0].MonthlyCapCents != want {
			t.Fatalf("POST amount %s = %d, budgets %+v", amount, response.StatusCode, source.budgets)
		}
	}
}

func TestSetBudgetOutsideTheHomeConflictsAndSilentLeaderIsUnavailable(t *testing.T) {
	t.Parallel()
	source := &fakeCapacity{setErr: ErrBudgetNotHome}
	dashboard := newTestDashboard(Options{Journal: &Journal{Capacity: source}})
	response, body := capacityRequest(t, dashboard, validBudgetForm(), nil)
	if response.StatusCode != http.StatusConflict || !strings.Contains(body, "set the budget on the home region's dashboard") {
		t.Fatalf("POST outside the home = %d %q, want 409 naming the home", response.StatusCode, body)
	}

	source.setErr = errors.New("ask the global leader: nats: timeout")
	response, body = capacityRequest(t, dashboard, validBudgetForm(), nil)
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "global leader did not set the budget") {
		t.Fatalf("POST with a silent leader = %d %q, want 503", response.StatusCode, body)
	}

	starting := newTestDashboard(Options{})
	if response, _ := capacityRequest(t, starting, validBudgetForm(), nil); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST before the provider is attached = %d, want 503", response.StatusCode)
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
	_, body := capacityRequest(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}), nil, nil)
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
	_, body := capacityRequest(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}), nil, nil)
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
	_, body := capacityRequest(t, newTestDashboard(Options{Journal: &Journal{Capacity: source}}), nil, nil)
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
