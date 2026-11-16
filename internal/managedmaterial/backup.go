package managedmaterial

import (
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// BackupS3Target is independent of the live source and has its own exact Vault
// credential version. CredentialSHA256 pins the target-bound host file, not a
// secret value in placement.
type BackupS3Target struct {
	Bucket           string                     `json:"bucket"`
	Region           string                     `json:"region"`
	Endpoint         string                     `json:"endpoint,omitempty"`
	Credential       oci.SecretVersionReference `json:"credential"`
	CredentialSHA256 string                     `json:"credential_sha256"`
}

// InitialBackupSpec is signed by the initial operator request and retained in
// the fenced R3 receipt. The key and credential versions must be kept for the
// declared retention window, including destination restores.
type InitialBackupSpec struct {
	Target               BackupS3Target             `json:"target"`
	OwnerMemberID        string                     `json:"owner_member_id"`
	DataKey              oci.SecretVersionReference `json:"data_key"`
	DataKeyID            string                     `json:"data_key_id"`
	DataKeySHA256        string                     `json:"data_key_sha256"`
	RetentionPolicyID    string                     `json:"retention_policy_id"`
	RetentionUntilUnixMS uint64                     `json:"retention_until_unix_ms"`
	MaxPointCadenceMS    uint64                     `json:"max_point_cadence_ms"`
}

// BackupManifestPayload is signed as exact JSON bytes in a compact envelope.
// There are no paths or secret values in these bytes.
type BackupManifestPayload struct {
	Version                  uint64 `json:"version"`
	ClusterID                string `json:"cluster_id"`
	TenantID                 string `json:"tenant_id"`
	DatabaseID               string `json:"database_id"`
	ShardID                  uint64 `json:"shard_id"`
	SourceScopeDigest        string `json:"source_scope_digest"`
	SourceAuthoritySHA256    string `json:"source_authority_sha256"`
	SourceConfigurationID    string `json:"source_configuration_id"`
	SourceTargetDigest       string `json:"source_target_digest"`
	BackupSet                string `json:"backup_set"`
	OwnerMemberID            string `json:"owner_member_id"`
	OwnerIncarnation         string `json:"owner_incarnation"`
	BackupTargetDigest       string `json:"backup_target_digest"`
	BackupS3ConfigSHA256     string `json:"backup_s3_config_sha256"`
	BackupS3CredentialSHA256 string `json:"backup_s3_credential_sha256"`
	SignerKeyID              string `json:"signer_key_id"`
	BackupDataKeyID          string `json:"backup_data_key_id"`
	BackupDataKeySHA256      string `json:"backup_data_key_sha256"`
	RetentionPolicyID        string `json:"retention_policy_id"`
	RetentionUntilUnixMS     uint64 `json:"retention_until_unix_ms"`
	MaxPointCadenceMS        uint64 `json:"max_point_cadence_ms"`
}
