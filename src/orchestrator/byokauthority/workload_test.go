package byokauthority

import (
	"context"
	"testing"
)

func TestWorkloadIssuerBindsCompleteScope(t *testing.T) {
	scope := WorkloadScope{Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", Role: "arn:aws:iam::123456789012:role/customer", Endpoint: "https://s3.example.test", Bucket: "backups", Region: "us-east-1", PlacementRevision: "revision"}
	issuer := &WorkloadIssuer{config: WorkloadConfig{Allowed: scope}, issue: func(context.Context) (WorkloadCredentials, error) {
		return WorkloadCredentials{AccessKey: "a", SecretKey: "s", SessionToken: "t", ExpiresAtUnixSeconds: 2}, nil
	}}
	if _, err := issuer.Issue(t.Context(), scope); err != nil {
		t.Fatal(err)
	}
	scope.DatabaseID = "other"
	if _, err := issuer.Issue(t.Context(), scope); err == nil {
		t.Fatal("issuer accepted a different database scope")
	}
}

func TestWorkloadIssuerRejectsNonHTTPSAuthorityEndpoint(t *testing.T) {
	scope := WorkloadScope{Environment: "production", TenantID: "tenant", ProjectID: "project", DatabaseID: "database", Role: "arn:aws:iam::123456789012:role/customer", Endpoint: "http://s3.example.test", Bucket: "backups", Region: "us-east-1", PlacementRevision: "revision"}
	if _, err := NewWorkloadIssuer(t.Context(), WorkloadConfig{Region: scope.Region, RoleARN: scope.Role, OIDCTokenFile: "/tmp/missing", SessionName: "session", Allowed: scope}); err == nil {
		t.Fatal("non-HTTPS workload authority endpoint accepted")
	}
}
