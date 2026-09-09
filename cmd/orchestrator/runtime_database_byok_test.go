package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func TestBYOKPolicyAuthorizerAcceptsExactVerifiedScope(t *testing.T) {
	request := byokRequest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-terrascale-byok-service-key"); got != "service-key" {
			t.Fatalf("service key = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"allowed":true,"status":"verified","environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAD","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAE","operation_id":"create-orders","expires_at":%d,"configuration_updated_at":"2026-09-09T12:00:00.000Z","byok":{"backup_endpoint":"https://s3.example.test","backup_bucket":"backups","backup_region":"gru","backup_role_arn":"arn:aws:iam::123456789012:role/backup","key_provider":"aws-kms","key_id":"key-12345678","key_region":"gru","key_endpoint":"https://kms.example.test"}}`, time.Now().Add(30*time.Second).Unix())
	}))
	defer server.Close()
	if err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request); err != nil {
		t.Fatalf("authorize BYOK: %v", err)
	}
}

func TestValidConfigurationUpdatedAtRequiresCanonicalDashboardTimestamp(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "2026-09-09T12:00:00.000Z", valid: true},
		{value: "2026-09-09T12:00:00Z"},
		{value: "2026-09-09T12:00:00.000+00:00"},
		{value: "2026-09-09T12:00:00.00Z"},
		{value: "2026-09-09T12:00:00.0000Z"},
		{value: "2026-02-30T12:00:00.000Z"},
	} {
		t.Run(test.value, func(t *testing.T) {
			if got := validConfigurationUpdatedAt(test.value); got != test.valid {
				t.Fatalf("validConfigurationUpdatedAt(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestBYOKPolicyAuthorizerFailsClosedOnMismatchOrPending(t *testing.T) {
	request := byokRequest()
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "pending", body: `{"allowed":true,"status":"pending","environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAD","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAE","operation_id":"create-orders","expires_at":4102444800}`},
		{name: "wrong-project", body: `{"allowed":true,"status":"verified","environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAD","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAF","operation_id":"create-orders","expires_at":4102444800}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request)
			if err == nil {
				t.Fatal("expected fail-closed error")
			}
		})
	}
}

func TestBYOKPolicyAuthorizerRejectsUnconfiguredEndpoint(t *testing.T) {
	if _, err := newBYOKPolicyAuthorizer(byokPolicyFileConfig{Endpoint: "http://127.0.0.1"}); err == nil {
		t.Fatal("expected HTTPS endpoint error")
	}
}

func byokRequest() databaseadmission.Request {
	return databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAD", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAE", Name: "orders", OperationID: "create-orders", Regions: []string{"GRU"}, Residency: "br-only", BYOK: &databaseadmission.BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test"}}
}
