package databaseadmission

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

type freezeHTTPJournal struct {
	calls       int
	environment string
}

func (j *freezeHTTPJournal) FreezeEnvironmentInventory(_ context.Context, environment, org string, start, end time.Time) (databaselifecycle.Snapshot, error) {
	j.calls++
	j.environment = environment
	return databaselifecycle.Snapshot{Environment: environment, OrganizationID: org, Start: start, End: end, Revision: 1, Digest: "receipt", Resources: []databaselifecycle.Resource{}}, nil
}
func TestFreezeInventoryHTTPSAuthenticationAndScope(t *testing.T) {
	const key = "01234567890123456789012345678901"
	const body = `{"organization_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","start":"2020-01-01T00:00:00Z","end":"2020-02-01T00:00:00Z"}`
	for _, test := range []struct {
		name, key, body string
		secure          bool
		want            int
	}{
		{"valid", key, body, true, 200}, {"wrong credential", "wrong", body, true, 401}, {"plaintext", key, body, false, 400}, {"unknown scope", key, `{"environment":"other"}`, true, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal := &freezeHTTPJournal{}
			handler, err := NewFreezeInventoryHandler(journal, "production", key)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, InventoryFreezePath, strings.NewReader(test.body))
			request.Header.Set(InventoryKeyHeader, test.key)
			if test.secure {
				request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("%d: %s", recorder.Code, recorder.Body.String())
			}
			if test.want == 200 {
				if journal.calls != 1 || journal.environment != "production" {
					t.Fatal("scope not bound")
				}
			} else if journal.calls != 0 {
				t.Fatal("unauthorized journal call")
			}
		})
	}
}
