package databaseadmission

import (
	"encoding/json/v2"
	"testing"
)

func TestValidateBYOKReferenceRejectsUnimplementedProviders(t *testing.T) {
	base := BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "arn:aws:kms:sa-east-1:123456789012:key/12345678-1234-1234-1234-123456789012", KeyRegion: "sa-east-1", KeyEndpoint: "https://kms.example.test"}
	for _, provider := range []string{"oci-vault", "azure-key-vault", "customer-kms"} {
		t.Run(provider, func(t *testing.T) {
			candidate := base
			candidate.KeyProvider = provider
			if err := ValidateBYOKReference(&candidate); err == nil {
				t.Fatal("unimplemented provider accepted")
			}
		})
	}
}

func TestBYOKWireRejectsCredentialFields(t *testing.T) {
	for _, field := range []string{"access_key", "secret_key", "session_token", "plaintext"} {
		t.Run(field, func(t *testing.T) {
			var request Request
			payload := []byte(`{"environment":"production","tenant_id":"01ARZ3NDEKTSV4RRFFQ69G5FAY","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAZ","name":"example","operation_id":"op","regions":["GRU"],"` + field + `":"secret"}`)
			if err := json.Unmarshal(payload, &request, json.RejectUnknownMembers(true)); err == nil {
				t.Fatal("credential field accepted on BYOK wire")
			}
		})
	}
}
