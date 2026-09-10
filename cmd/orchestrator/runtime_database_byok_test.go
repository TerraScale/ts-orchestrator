package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
		_, _ = fmt.Fprintf(w, `{"allowed":true,"status":"verified","environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAD","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAE","operation_id":"create-orders","expires_at":%d,"byok":{"backup_endpoint":"https://s3.example.test","backup_bucket":"backups","backup_region":"gru","backup_role_arn":"arn:aws:iam::123456789012:role/backup","key_provider":"aws-kms","key_id":"key-12345678","key_region":"gru","key_endpoint":"https://kms.example.test","configuration_updated_at":"2026-09-09T12:00:00.000Z"}}`, time.Now().Add(30*time.Second).Unix())
	}))
	defer server.Close()
	if err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request); err != nil {
		t.Fatalf("authorize BYOK: %v", err)
	}
	if request.BYOK.ConfigurationUpdatedAt != "2026-09-09T12:00:00.000Z" {
		t.Fatalf("authorizer mutated immutable request timestamp: %q", request.BYOK.ConfigurationUpdatedAt)
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

func TestBYOKPolicyAuthorizerAcceptsPendingSavedReference(t *testing.T) {
	request := byokRequest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"allowed":true,"status":"pending","environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAD","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAE","operation_id":"create-orders","expires_at":%d,"byok":{"backup_endpoint":"https://s3.example.test","backup_bucket":"backups","backup_region":"gru","backup_role_arn":"arn:aws:iam::123456789012:role/backup","key_provider":"aws-kms","key_id":"key-12345678","key_region":"gru","key_endpoint":"https://kms.example.test","configuration_updated_at":"2026-09-09T12:00:00.000Z"}}`, time.Now().Add(30*time.Second).Unix())
	}))
	defer server.Close()
	if err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request); err != nil {
		t.Fatalf("pending policy rejected: %v", err)
	}
}

func TestBYOKPolicyAuthorizerConsumesDashboardPendingFixture(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(source), "testdata", "producer-pending.json")
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if got := hex.EncodeToString(digest[:]); got != "1c3038963d0bb3e8b20be1e72da9612629d6ac8a465c8c4488c403c556379216" {
		t.Fatalf("dashboard fixture changed: sha256=%s", got)
	}
	request := databaseadmission.Request{Environment: "production", TenantID: "01J00000000000000000000001", ProjectID: "01J00000000000000000000002", Name: "orders", OperationID: "01J00000000000000000000003", Regions: []string{"GRU"}, BYOK: &databaseadmission.BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test", ConfigurationUpdatedAt: "2026-09-09T00:00:00.000Z"}}
	wire := bytes.Replace(body, []byte("1799270430"), []byte(fmt.Sprintf("%d", time.Now().Add(30*time.Second).Unix())), 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wire) }))
	defer server.Close()
	if err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request); err != nil {
		t.Fatalf("dashboard pending fixture rejected: %v", err)
	}
	mismatched := bytes.Replace(wire, []byte("2026-09-09T00:00:00.000Z"), []byte("2026-09-09T00:00:01.000Z"), 1)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(mismatched) })
	if err := byokPolicyAuthorizer(server.Client(), server.URL, "service-key")(t.Context(), request); err == nil {
		t.Fatal("dashboard fixture with mismatched immutable timestamp accepted")
	}
}

func byokRequest() databaseadmission.Request {
	return databaseadmission.Request{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAD", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAE", Name: "orders", OperationID: "create-orders", Regions: []string{"GRU"}, Residency: "br-only", BYOK: &databaseadmission.BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test", ConfigurationUpdatedAt: "2026-09-09T12:00:00.000Z"}}
}
