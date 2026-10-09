package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestUsageAPIUsesRequestedInventoryWindow(t *testing.T) {
	s, from, to := fixture(t)
	s.SetExpected(func(_ context.Context, gotFrom, gotTo time.Time) ([]string, error) {
		if !gotFrom.Equal(from) || !gotTo.Equal(to) {
			t.Fatalf("inventory window shifted: %s %s", gotFrom, gotTo)
		}
		return []string{"a", "b", "a/terrabase", "b/terrabase", "withdrawn/api"}, nil
	})
	query := url.Values{"region": {"gru"}, "from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
	request := httptest.NewRequest(http.MethodGet, "/v1/usage?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	s.Handler(s.Expected).ServeHTTP(response, request)
	var usage Usage
	if err := json.Unmarshal(response.Body.Bytes(), &usage); err != nil || response.Code != 200 || usage.Complete || len(usage.Missing) != 1 || usage.Missing[0] != "withdrawn/api" {
		t.Fatalf("historical missing replica was concealed: %s %v", response.Body, err)
	}
	s.SetExpected(func(context.Context, time.Time, time.Time) ([]string, error) {
		return nil, errors.New("log unavailable")
	})
	response = httptest.NewRecorder()
	s.Handler(s.Expected).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed historical inventory returned %d", response.Code)
	}
}

func TestExpiredCapacitySeriesReleaseTheirSlots(t *testing.T) {
	s := NewStore("gru")
	from := time.Now().UTC().Truncate(5 * time.Second).Add(-time.Minute)
	// A fully measured node/role uses 16 series; fill the default 4096 cap.
	for node := range 256 {
		appendResourceSample(s, from.Add(-Retention-time.Second), fmt.Sprintf("departed-%d", node), 3)
	}
	if stats := s.History.Stats(); stats.Series != 4096 || stats.Dropped != 0 {
		t.Fatalf("churn fixture did not fill the cap: %+v", stats)
	}
	for at := from; at.Before(from.Add(30 * time.Second)); at = at.Add(5 * time.Second) {
		appendResourceSample(s, at, "replacement", 3)
	}
	usage, err := s.Query(from, from.Add(30*time.Second), []string{"replacement", "replacement/api"})
	if err != nil || !usage.Complete || usage.Truncated || len(usage.Nodes) != 1 || s.History.Stats().Series != 16 || s.History.Stats().Dropped != 0 {
		t.Fatalf("departed series starved a measured replacement: %+v %+v %v", usage, s.History.Stats(), err)
	}
}

func TestLaterTelemetryCannotAddRowsToAnEarlierWindow(t *testing.T) {
	s, from, to := fixture(t)
	appendResourceSample(s, to, "later-node", 3)
	usage, err := s.Query(from, to, []string{"a", "b", "a/terrabase", "b/terrabase"})
	if err != nil || !usage.Complete || len(usage.Nodes) != 2 || len(usage.Replicas) != 2 {
		t.Fatalf("exclusive-end telemetry changed historical completeness: %+v %v", usage, err)
	}
}
