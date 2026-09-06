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

func TestDatabaseDeletionAuthorizationRequiresExactFreshUnprotectedDecision(t *testing.T) {
	request := databaseadmission.DeleteRequest{Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", OperationID: "delete-one"}
	for _, scenario := range []string{"allowed", "protected", "missing-protection", "wrong-database", "expired", "retention-past", "denied"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			decision := map[string]any{"allowed": true, "protected": false, "environment": request.Environment, "tenant_id": request.TenantID, "project_id": request.ProjectID, "database_id": request.DatabaseID, "operation_id": request.OperationID, "expires_at": now.Add(30 * time.Second).Unix(), "retain_until": now.Add(time.Hour).UnixMilli()}
			switch scenario {
			case "protected":
				decision["protected"] = true
			case "missing-protection":
				delete(decision, "protected")
			case "wrong-database":
				decision["database_id"] = "another"
			case "expired":
				decision["expires_at"] = now.Unix()
			case "retention-past":
				decision["retain_until"] = now.Add(-time.Hour).UnixMilli()
			case "denied":
				decision["allowed"] = false
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("x-terrascale-database-admission-key") != "secret" {
					t.Error("missing authenticated POST")
				}
				body, err := json.Marshal(decision)
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			result, err := databaseDeletionAuthorizer(server.Client(), server.URL, "secret")(t.Context(), request)
			if scenario == "allowed" {
				if err != nil || result.RetainUntil.UnixMilli() != decision["retain_until"] {
					t.Fatalf("unexpected decision: %+v %v", result, err)
				}
			} else if err == nil {
				t.Fatal("unsafe decision accepted")
			}
			if scenario == "protected" && !errors.Is(err, databaseadmission.ErrForbidden) {
				t.Fatalf("protected deletion: %v", err)
			}
		})
	}
}
