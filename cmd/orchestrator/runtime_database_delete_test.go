package main

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"testing"
	"time"
)

func TestDatabaseDeletionAuthorizationRequiresExactFreshOwnerDecision(t *testing.T) {
	request := databaseadmission.DeleteRequest{Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", OperationID: "delete-one"}
	for _, scenario := range []string{"allowed"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			decision := map[string]any{"allowed": true, "action": "delete", "subject": "owner-id", "actor": "token-id", "environment": request.Environment, "tenant_id": request.TenantID, "project_id": request.ProjectID, "database_id": request.DatabaseID, "operation_id": request.OperationID, "issued_at": now.Unix(), "expires_at": now.Add(29 * time.Second).Unix(), "schemaVersion": 1, "policy_revision": "revision", "policy_fingerprint": "fingerprint", "grace_condition": "card-loss", "deadline": now.Add(time.Hour), "accepted_at": now, "authority_epoch": "epoch"}
			switch scenario {
			case "missing-actor":
				delete(decision, "actor")
			case "wrong-action":
				decision["action"] = "create"
			case "wrong-database":
				decision["database_id"] = "another"
			case "expired":
				decision["expires_at"] = now.Unix()
			case "future-issued":
				decision["issued_at"] = now.Add(time.Hour).Unix()
			case "denied":
				decision["allowed"] = false
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("x-terrascale-database-admission-key") != "secret" || r.Header.Get("Authorization") != "Bearer customer-token" {
					t.Error("missing authenticated POST")
				}
				_ = json.MarshalWrite(w, decision)
			}))
			defer server.Close()
			err := databaseDeletionAuthorizer(server.Client(), server.URL, "secret")(databaseadmission.WithDeletionAuthorization(t.Context(), "Bearer customer-token"), request)
			if scenario == "allowed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe decision accepted")
			}
		})
	}
}
func TestDatabaseDeletionAuthorizationRequiresCustomerBearer(t *testing.T) {
	policy := databaseDeletionAuthorizer(&http.Client{}, "https://example.invalid", "secret")
	if err := policy(t.Context(), databaseadmission.DeleteRequest{}); !errors.Is(err, databaseadmission.ErrForbidden) {
		t.Fatalf("missing customer bearer: %v", err)
	}
}
