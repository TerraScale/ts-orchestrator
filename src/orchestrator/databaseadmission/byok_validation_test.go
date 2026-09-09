package databaseadmission

import "testing"

func TestValidateBYOKReferenceRejectsUnimplementedProviders(t *testing.T) {
	base := BYOKReference{BackupEndpoint: "https://s3.example.test", BackupBucket: "backups", BackupRegion: "gru", BackupRoleARN: "arn:aws:iam::123456789012:role/backup", KeyProvider: "aws-kms", KeyID: "key-12345678", KeyRegion: "gru", KeyEndpoint: "https://kms.example.test"}
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
