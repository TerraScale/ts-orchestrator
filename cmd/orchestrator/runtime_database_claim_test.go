package main

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAutomaticDeletionClaimHTTPWire(t *testing.T) {
	key := strings.Repeat("k", 32)
	request := automaticDeletionClaimRequest{SchemaVersion: 1, Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", OperationID: "operation", PolicyRevision: "revision", GraceCondition: "card-loss"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/claim" || r.Header.Get("x-terrascale-lifecycle-service-key") != key || r.Header.Get("Authorization") != "" {
			t.Errorf("request=%s %s key=%q authorization=%q", r.Method, r.URL, r.Header.Get("x-terrascale-lifecycle-service-key"), r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		var got automaticDeletionClaimRequest
		if err := json.Unmarshal(body, &got); err != nil || got != request {
			t.Errorf("body=%s decoded=%+v err=%v", body, got, err)
		}
		_, _ = io.WriteString(w, `{"schemaVersion":1,"environment":"production","tenant_id":"tenant","project_id":"project","database_id":"database","operation_id":"operation","policy_revision":"revision","policy_fingerprint":"fingerprint","grace_condition":"card-loss","deadline":"2026-01-01T00:00:00Z","accepted_at":"2026-01-01T00:00:00Z","authority_epoch":"epoch"}`)
	}))
	defer server.Close()
	receipt, err := databaseDeletionClaimHTTPClient(server.Client(), server.URL+"/claim", key)(t.Context(), request)
	if err != nil || receipt.OperationID != request.OperationID {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

func TestAutomaticDeletionClaimRejectsScopeAndUnknownReceipt(t *testing.T) {
	request := automaticDeletionClaimRequest{SchemaVersion: 1, Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", OperationID: "operation", PolicyRevision: "revision", GraceCondition: "card-loss"}
	for _, response := range []string{
		`{"schemaVersion":1,"environment":"other"}`,
		`{"schemaVersion":1,"environment":"production","tenant_id":"tenant","project_id":"project","database_id":"database","operation_id":"operation","policy_revision":"revision","policy_fingerprint":"fingerprint","grace_condition":"card-loss","deadline":"2026-01-01T00:00:00Z","accepted_at":"2026-01-01T00:00:00Z","authority_epoch":"epoch","extra":true}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, response) }))
		_, err := databaseDeletionClaimHTTPClient(server.Client(), server.URL, strings.Repeat("k", 32))(t.Context(), request)
		server.Close()
		if err == nil {
			t.Fatalf("response %s was accepted", response)
		}
	}
	if _, err := databaseDeletionClaimHTTPClient(http.DefaultClient, "", strings.Repeat("k", 32))(t.Context(), request); err == nil {
		t.Fatal("empty endpoint was accepted")
	}
}

func TestAutomaticUncoveredStorageClaimRevalidationResponse(t *testing.T) {
	request := automaticDeletionClaimRequest{SchemaVersion: 1, Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", OperationID: "operation", PolicyRevision: "revision", GraceCondition: "uncovered-storage"}
	const accepted = `{"schemaVersion":1,"environment":"production","tenant_id":"tenant","project_id":"project","database_id":"database","operation_id":"operation","policy_revision":"revision","policy_fingerprint":"measurement-and-policy-proof","grace_condition":"uncovered-storage","deadline":"2026-01-01T00:00:00Z","accepted_at":"2026-01-01T00:00:00Z","authority_epoch":"epoch"}`
	for _, tc := range []struct {
		name     string
		status   int
		response string
		valid    bool
	}{
		{"fresh exact evidence accepted", http.StatusOK, accepted, true},
		{"measurement restored allowance", http.StatusConflict, `{}`, false},
		{"fresh quantity unavailable", http.StatusServiceUnavailable, `{}`, false},
		{"policy changed", http.StatusOK, strings.Replace(accepted, `"policy_revision":"revision"`, `"policy_revision":"new-revision"`, 1), false},
		{"grace still active", http.StatusOK, strings.Replace(accepted, `"accepted_at":"2026-01-01T00:00:00Z"`, `"accepted_at":"2025-12-31T00:00:00Z"`, 1), false},
		{"unbound reason", http.StatusOK, strings.Replace(accepted, `"grace_condition":"uncovered-storage"`, `"grace_condition":"card-loss"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()
			receipt, err := databaseDeletionClaimHTTPClient(server.Client(), server.URL, strings.Repeat("k", 32))(t.Context(), request)
			if (err == nil) != tc.valid {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}
