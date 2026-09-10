package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

func TestRenewalPolicyCheckerExactScopeAndExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-terrascale-byok-service-key") != "secret" {
			t.Error("missing protected service key")
		}
		_, _ = io.WriteString(w, renewalReply(renewalTestRequest(), "01J00000000000000000000001", "01J00000000000000000000002", "01J00000000000000000000004", "01J00000000000000000000003", 20))
	}))
	defer server.Close()
	checker, err := newRenewalPolicyChecker(server.URL, "secret")
	if err == nil {
		t.Fatal("plaintext endpoint accepted")
	}
	// The test server is intentionally HTTP; validate configuration separately.
	checker, err = newRenewalPolicyChecker("https://dashboard.example.test/internal/byok/renewal-policy", "secret")
	if err != nil || checker == nil {
		t.Fatalf("valid checker config rejected: %v", err)
	}
}

func TestRenewalPolicyCheckerRejectsMissingMetadata(t *testing.T) {
	checker, err := newRenewalPolicyChecker("https://dashboard.example.test/internal/byok/renewal-policy", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.Check(t.Context(), keylease.RenewalRequest{}); err == nil {
		t.Fatal("missing admission operation accepted")
	}
}

func TestRenewalPolicyCheckerRejectsNilCatalogMetadataBeforeHTTP(t *testing.T) {
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
	if _, err := checker.Check(t.Context(), renewalTestRequestWithoutBYOK()); err == nil {
		t.Fatal("nil catalog metadata accepted")
	}
	if called {
		t.Fatal("nil catalog metadata reached HTTP")
	}
}

func renewalTestRequestWithoutBYOK() keylease.RenewalRequest {
	request := renewalTestRequest()
	request.BYOK = nil
	return request
}

func TestRenewalPolicyCheckerUsesConcreteTLSWireTuple(t *testing.T) {
	request := renewalTestRequest()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-terrascale-byok-service-key") != "secret" {
			t.Error("missing service key")
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil || body["environment"] != request.Binding.Environment || body["tenant_id"] != request.Binding.TenantID || body["project_id"] != request.Binding.ProjectID || body["database_id"] != request.Binding.DatabaseID || body["admission_operation_id"] != request.AdmissionOperationID || body["purpose"] != "key-unseal" {
			t.Errorf("wire tuple mismatch: %+v", body)
		}
		_, _ = io.WriteString(w, renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20))
	}))
	defer server.Close()
	checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
	if expiry, err := checker.Check(t.Context(), request); err != nil || expiry.Before(time.Now()) {
		t.Fatalf("TLS policy check = %v, %v", expiry, err)
	}
}

func TestRenewalPolicyCheckerRejectsChangedScopeExpiryAndMalformedResponses(t *testing.T) {
	request := renewalTestRequest()
	for _, test := range []struct {
		name string
		body func() string
	}{
		{name: "wrong actor", body: func() string {
			return renewalReply(request, request.Binding.TenantID+"x", request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20)
		}},
		{name: "wrong operation", body: func() string {
			return renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID+"x", 20)
		}},
		{name: "expired", body: func() string {
			return renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, -1)
		}},
		{name: "expiry beyond decision bound", body: func() string {
			return renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 120)
		}},
		{name: "malformed", body: func() string { return "not-json" }},
		{name: "missing status", body: func() string {
			return strings.Replace(renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20), `"status":"verified",`, "", 1)
		}},
		{name: "missing purpose", body: func() string {
			return strings.Replace(renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20), `"purpose":"key-unseal",`, "", 1)
		}},
		{name: "missing byok", body: func() string {
			return strings.Replace(renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20), `,"byok":{`, `,"byok_missing":{`, 1)
		}},
		{name: "changed revision", body: func() string {
			return strings.Replace(renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20), "2026-09-09T00:00:00.000Z", "2026-09-09T00:00:01.000Z", 1)
		}},
		{name: "oversized response", body: func() string {
			return renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20) + strings.Repeat(" ", 8192)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(test.body())) }))
			defer server.Close()
			checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
			if _, err := checker.Check(t.Context(), request); err == nil {
				t.Fatal("invalid renewal policy response accepted")
			}
		})
	}
}

func TestRenewalPolicyCheckerS3OmitsEmptyExternalID(t *testing.T) {
	request := renewalTestRequest()
	request.Workload = &keylease.WorkloadIdentityScope{Environment: request.Binding.Environment, TenantID: request.Binding.TenantID, ProjectID: request.Binding.ProjectID, DatabaseID: request.Binding.DatabaseID, Role: "arn:aws:iam::123456789012:role/backup", Endpoint: "https://s3.example.test", Bucket: "backups", Region: "gru", PlacementRevision: "placement-1"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Fatal(err)
		}
		scope := body["s3"].(map[string]any)
		if _, present := scope["external_id"]; present {
			t.Fatal("empty external_id was emitted")
		}
		_, _ = io.WriteString(w, renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20))
	}))
	defer server.Close()
	checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
	if _, err := checker.Check(t.Context(), request); err != nil {
		t.Fatalf("S3 policy response rejected: %v", err)
	}
}

func TestRenewalPolicyCheckerResponseByteBoundary(t *testing.T) {
	request := renewalTestRequest()
	for _, test := range []struct {
		name    string
		extra   int
		wantErr bool
	}{{"8192", 8192, false}, {"8193", 8193, true}} {
		t.Run(test.name, func(t *testing.T) {
			base := renewalReply(request, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID, request.AdmissionOperationID, 20)
			body := base + strings.Repeat(" ", max(0, test.extra-len(base)))
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			defer server.Close()
			checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
			_, err := checker.Check(t.Context(), request)
			if (err != nil) != test.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestRenewalPolicyCheckerConsumesDashboardGeneratedWorkloadFixture(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(source), "../../../.agents/qualification/current-20260910/byok-wire-contract/dashboard-generated")
	requestBytes, err := os.ReadFile(filepath.Join(fixtureDir, "request-workload.json"))
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := os.ReadFile(filepath.Join(fixtureDir, "response-workload.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Environment          string                                                             `json:"environment"`
		TenantID             string                                                             `json:"tenant_id"`
		ProjectID            string                                                             `json:"project_id"`
		DatabaseID           string                                                             `json:"database_id"`
		AdmissionOperationID string                                                             `json:"admission_operation_id"`
		Purpose              string                                                             `json:"purpose"`
		BYOK                 keylease.BYOKMetadata                                              `json:"byok"`
		S3                   struct{ Endpoint, Bucket, Region, Role, PlacementRevision string } `json:"s3"`
	}
	if err := json.Unmarshal(requestBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	responseBytes = bytes.Replace(responseBytes, []byte("1789068287"), []byte(fmt.Sprint(time.Now().Add(20*time.Second).Unix())), 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(responseBytes) }))
	defer server.Close()
	request := keylease.RenewalRequest{Binding: keylease.Binding{Environment: fixture.Environment, TenantID: fixture.TenantID, ProjectID: fixture.ProjectID, DatabaseID: fixture.DatabaseID}, AdmissionOperationID: fixture.AdmissionOperationID, BYOK: &fixture.BYOK, Workload: &keylease.WorkloadIdentityScope{Environment: fixture.Environment, TenantID: fixture.TenantID, ProjectID: fixture.ProjectID, DatabaseID: fixture.DatabaseID, Role: fixture.S3.Role, Endpoint: fixture.S3.Endpoint, Bucket: fixture.S3.Bucket, Region: fixture.S3.Region, PlacementRevision: fixture.S3.PlacementRevision}}
	checker := renewalPolicyChecker{endpoint: server.URL, serviceKey: "secret", client: server.Client()}
	if _, err := checker.Check(t.Context(), request); err != nil {
		t.Fatalf("dashboard-generated workload fixture rejected: %v", err)
	}
}

func renewalTestRequest() keylease.RenewalRequest {
	return keylease.RenewalRequest{Binding: keylease.Binding{Environment: "production", TenantID: "01J00000000000000000000001", ProjectID: "01J00000000000000000000002", DatabaseID: "01J00000000000000000000004", Region: "GRU", KeyVersion: "01J00000000000000000000005", Purpose: "data"}, AdmissionOperationID: "01J00000000000000000000003", BYOK: &keylease.BYOKMetadata{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test", ConfigurationUpdatedAt: "2026-09-09T00:00:00.000Z"}, Provider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test"}
}

func renewalReply(request keylease.RenewalRequest, tenant, project, database, operation string, seconds int64) string {
	b := request.BYOK
	purpose := "key-unseal"
	if request.Workload != nil {
		purpose = "workload-credentials"
	}
	return fmt.Sprintf(`{"allowed":true,"status":"verified","purpose":"%s","environment":"production","tenant_id":"%s","project_id":"%s","database_id":"%s","admission_operation_id":"%s","expires_at":%d,"byok":{"backup_endpoint":"%s","backup_bucket":"%s","backup_region":"%s","backup_role_arn":"%s","key_provider":"%s","key_id":"%s","key_region":"%s","key_endpoint":"%s","configuration_updated_at":"%s"}}`, purpose, tenant, project, database, operation, time.Now().Add(time.Duration(seconds)*time.Second).Unix(), b.BackupEndpoint, b.BackupBucket, b.BackupRegion, b.BackupRoleARN, b.KeyProvider, b.KeyID, b.KeyRegion, b.KeyEndpoint, b.ConfigurationUpdatedAt)
}
