package main

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func TestDatabaseAuthorizerRequiresExactFreshProducerDecision(t *testing.T) {
	_, request := databasePlanFixture()
	for _, tt := range []struct {
		name                     string
		status                   int
		allowed                  bool
		project                  string
		expiry                   int64
		wantForbidden, wantError bool
	}{
		{name: "allowed", status: 200, allowed: true, project: request.Request.ProjectID, expiry: time.Now().Add(30 * time.Second).Unix()},
		{name: "denied", status: 200, project: request.Request.ProjectID, expiry: time.Now().Add(30 * time.Second).Unix(), wantForbidden: true, wantError: true},
		{name: "wrong-project", status: 200, allowed: true, project: "other", expiry: time.Now().Add(30 * time.Second).Unix(), wantError: true},
		{name: "expired", status: 200, allowed: true, project: request.Request.ProjectID, expiry: time.Now().Add(-time.Second).Unix(), wantError: true},
		{name: "unavailable", status: 503, wantError: true},
		{name: "forbidden", status: 403, wantForbidden: true, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-terrascale-database-admission-key") != "test-dedicated-key" || r.Method != http.MethodPost {
					t.Error("service authentication missing")
				}
				var input databaseadmission.Request
				if err := json.UnmarshalRead(r.Body, &input); err != nil || input.ProjectID != request.Request.ProjectID {
					t.Error("request scope lost")
				}
				w.WriteHeader(tt.status)
				_ = json.MarshalWrite(w, map[string]any{"allowed": tt.allowed, "environment": input.Environment, "tenant_id": input.TenantID, "project_id": tt.project, "operation_id": input.OperationID, "expires_at": tt.expiry})
			}))
			defer server.Close()
			err := databaseAuthorizer(server.Client(), server.URL, "test-dedicated-key")(t.Context(), request.Request)
			if (err != nil) != tt.wantError || errors.Is(err, databaseadmission.ErrForbidden) != tt.wantForbidden {
				t.Fatalf("decision error %v", err)
			}
		})
	}
}
