package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestManagerUsageHistoryHTTPRefusesUnprovenInventory(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "empty_history"
		if retained {
			name = "retained_history"
		}
		t.Run(name, func(t *testing.T) {
			store := capacity.NewStore("gru")
			store.SetExpected(managerExpectedUsage)
			to := time.Now().UTC().Truncate(time.Second)
			from := to.Add(-2 * time.Minute)
			query := observability.HistoryQuery{Metric: "capacity_cpu_request", Start: from, End: to, Tier: observability.TierRaw}
			if retained {
				store.History.Append(from.Add(time.Minute), []observability.Sample{{Metric: query.Metric,
					Labels: observability.L("node", "host-a", "service", "api", "environment", "production"), Value: 2}})
			}
			before := store.History.Range(query)
			server := httptest.NewServer(store.Handler(store.Expected))
			defer server.Close()
			client := server.Client()
			client.Timeout = 2 * time.Second
			values := url.Values{"region": {"gru"}, "from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"?"+values.Encode(), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusServiceUnavailable || strings.TrimSpace(string(body)) != "regional inventory unavailable" {
				t.Fatalf("unproven manager history: status=%d body=%q err=%v", response.StatusCode, body, err)
			}
			// RetentionStart follows the clock; the retained series must not move.
			if after := store.History.Range(query); !reflect.DeepEqual(before.Series, after.Series) {
				t.Fatal("unknown allocation history rewrote retained capacity measurements")
			}
		})
	}
}
