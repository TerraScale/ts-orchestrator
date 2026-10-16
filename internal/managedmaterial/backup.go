package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	backupManifestName   = "backup-managed-manifest.json"
	backupConfigName     = "backup-s3-config.json"
	backupManifestDomain = "TB-BACKUP-MANIFEST-V1\x00"
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

func (target BackupS3Target) liveShape() LiveS3Target {
	return LiveS3Target{Bucket: target.Bucket, Region: target.Region,
		Endpoint: target.Endpoint, Credential: target.Credential}
}

func (target BackupS3Target) Digest() (string, error) {
	if !lowerHexDigest(target.CredentialSHA256) {
		return "", errors.New("backup S3 credential digest is invalid")
	}
	return target.liveShape().Digest()
}

func (target BackupS3Target) ConfigJSON() ([]byte, error) {
	if _, err := target.Digest(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version  uint64 `json:"version"`
		Bucket   string `json:"bucket"`
		Region   string `json:"region"`
		Endpoint string `json:"endpoint,omitempty"`
	}{1, target.Bucket, target.Region, target.Endpoint})
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

func (backup InitialBackupSpec) Validate(live LiveS3Target, members [2]InitialMember, now time.Time) error {
	liveDigest, liveErr := live.Digest()
	backupDigest, backupErr := backup.Target.Digest()
	if liveErr != nil || backupErr != nil || backupDigest == liveDigest ||
		strings.EqualFold(backup.Target.Bucket, live.Bucket) &&
			strings.EqualFold(backup.Target.Region, live.Region) ||
		backup.Target.Credential.SecretOCID == live.Credential.SecretOCID ||
		backup.DataKey.Validate() != nil || !lowerHexDigest(backup.DataKeySHA256) ||
		backup.DataKey.SecretOCID == backup.Target.Credential.SecretOCID ||
		backup.OwnerMemberID != members[0].MemberID && backup.OwnerMemberID != members[1].MemberID ||
		!entityid.Valid(backup.DataKeyID) || !validBackupPolicyID(backup.RetentionPolicyID) ||
		backup.MaxPointCadenceMS < 60_000 || backup.MaxPointCadenceMS > 30*24*60*60*1000 ||
		backup.RetentionUntilUnixMS <= uint64(now.UnixMilli()) ||
		backup.RetentionUntilUnixMS > uint64(now.Add(365*24*time.Hour).UnixMilli()) {
		return errors.New("initial independent backup target, key or retention is invalid")
	}
	return nil
}

func validBackupToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range []byte(value) {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func validBackupPolicyID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
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

type backupManifestEnvelope struct {
	Version   uint64 `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func backupScopeDigest(scope AuthorityScope) (string, error) {
	tenant, err := canonicalID(scope.TenantID)
	if err != nil {
		return "", err
	}
	database, err := canonicalID(scope.DatabaseID)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("TBLOGS01"))
	h.Write(tenant[:])
	h.Write(database[:])
	var shard [8]byte
	binary.LittleEndian.PutUint64(shard[:], scope.ShardID)
	h.Write(shard[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

func generateBackupMaterial(spec InitialSpec, authority SignedAuthority, signer ed25519.PrivateKey) (File, File, error) {
	if spec.Backup == nil {
		return File{}, File{}, nil
	}
	config, err := spec.Backup.Target.ConfigJSON()
	if err != nil {
		return File{}, File{}, err
	}
	configFile := makeFile(config)
	liveDigest, err := spec.LiveS3.Digest()
	if err != nil {
		return File{}, File{}, err
	}
	backupDigest, err := spec.Backup.Target.Digest()
	if err != nil {
		return File{}, File{}, err
	}
	scopeDigest, err := backupScopeDigest(spec.Scope)
	if err != nil {
		return File{}, File{}, err
	}
	set := entityid.New()
	var owner InitialMember
	for _, member := range spec.Members {
		if member.MemberID == spec.Backup.OwnerMemberID {
			owner = member
			break
		}
	}
	authoritySHA := sha256.Sum256(authority.Certificate)
	keyID, err := protocol.KeyID(authority.TrustedKey)
	if err != nil {
		return File{}, File{}, err
	}
	payload := BackupManifestPayload{Version: 1, ClusterID: spec.Scope.ClusterID,
		TenantID: spec.Scope.TenantID, DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
		SourceScopeDigest: scopeDigest, SourceAuthoritySHA256: hex.EncodeToString(authoritySHA[:]),
		SourceConfigurationID: authority.ConfigurationID, SourceTargetDigest: liveDigest,
		BackupSet: set, OwnerMemberID: owner.MemberID,
		OwnerIncarnation: owner.Incarnation, BackupTargetDigest: backupDigest,
		BackupS3ConfigSHA256:     configFile.SHA256,
		BackupS3CredentialSHA256: spec.Backup.Target.CredentialSHA256, SignerKeyID: keyID,
		BackupDataKeyID: spec.Backup.DataKeyID, BackupDataKeySHA256: spec.Backup.DataKeySHA256,
		RetentionPolicyID:    spec.Backup.RetentionPolicyID,
		RetentionUntilUnixMS: spec.Backup.RetentionUntilUnixMS,
		MaxPointCadenceMS:    spec.Backup.MaxPointCadenceMS}
	body, err := json.Marshal(payload)
	if err != nil {
		return File{}, File{}, err
	}
	preimage := append([]byte(backupManifestDomain), body...)
	manifest, err := json.Marshal(backupManifestEnvelope{1,
		base64.RawURLEncoding.EncodeToString(body),
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, preimage))})
	if err != nil || len(manifest) > 16<<10 {
		return File{}, File{}, errors.New("backup manifest exceeds bound")
	}
	return makeFile(manifest), configFile, nil
}

func verifyStoredBackupMaterial(spec InitialSpec, bundle InitialBundle) error {
	for _, member := range bundle.Members {
		manifestFile, hasManifest := member.Files[backupManifestName]
		configFile, hasConfig := member.Files[backupConfigName]
		if spec.Backup == nil {
			if hasManifest || hasConfig {
				return ErrMaterialConflict
			}
			continue
		}
		if !hasManifest || !hasConfig || len(manifestFile.Contents) > 16<<10 {
			return ErrMaterialConflict
		}
		wantConfig, err := spec.Backup.Target.ConfigJSON()
		if err != nil || !bytes.Equal(configFile.Contents, wantConfig) {
			return ErrMaterialConflict
		}
		var envelope backupManifestEnvelope
		if err := json.Unmarshal(manifestFile.Contents, &envelope, json.RejectUnknownMembers(true)); err != nil || envelope.Version != 1 {
			return ErrMaterialConflict
		}
		canonical, err := json.Marshal(envelope)
		if err != nil || !bytes.Equal(canonical, manifestFile.Contents) {
			return ErrMaterialConflict
		}
		body, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil || base64.RawURLEncoding.EncodeToString(body) != envelope.Payload {
			return ErrMaterialConflict
		}
		sig, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != envelope.Signature ||
			!ed25519.Verify(bundle.Authority.TrustedKey, append([]byte(backupManifestDomain), body...), sig) {
			return ErrMaterialConflict
		}
		var payload BackupManifestPayload
		if err := json.Unmarshal(body, &payload, json.RejectUnknownMembers(true)); err != nil {
			return ErrMaterialConflict
		}
		canonical, err = json.Marshal(payload)
		if err != nil || !bytes.Equal(canonical, body) || payload.Version != 1 {
			return ErrMaterialConflict
		}
		want, err := expectedBackupPayload(spec, bundle.Authority, payload.BackupSet, configFile.SHA256)
		if err != nil || payload != want {
			return ErrMaterialConflict
		}
	}
	if spec.Backup != nil && !bytes.Equal(bundle.Members[0].Files[backupManifestName].Contents,
		bundle.Members[1].Files[backupManifestName].Contents) {
		return ErrMaterialConflict
	}
	return nil
}

func expectedBackupPayload(spec InitialSpec, authority SignedAuthority, backupSet, configSHA string) (BackupManifestPayload, error) {
	if spec.Backup == nil {
		return BackupManifestPayload{}, ErrMaterialConflict
	}
	set, err := entityid.Parse(backupSet)
	if err != nil || len(set) != 16 || !entityid.Valid(set.String()) {
		return BackupManifestPayload{}, ErrMaterialConflict
	}
	scopeDigest, err := backupScopeDigest(spec.Scope)
	if err != nil {
		return BackupManifestPayload{}, err
	}
	liveDigest, err := spec.LiveS3.Digest()
	if err != nil {
		return BackupManifestPayload{}, err
	}
	backupDigest, err := spec.Backup.Target.Digest()
	if err != nil {
		return BackupManifestPayload{}, err
	}
	keyID, err := protocol.KeyID(authority.TrustedKey)
	if err != nil {
		return BackupManifestPayload{}, err
	}
	var owner InitialMember
	for _, member := range spec.Members {
		if member.MemberID == spec.Backup.OwnerMemberID {
			owner = member
			break
		}
	}
	authoritySHA := sha256.Sum256(authority.Certificate)
	return BackupManifestPayload{Version: 1, ClusterID: spec.Scope.ClusterID, TenantID: spec.Scope.TenantID,
		DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID,
		SourceScopeDigest: scopeDigest, SourceAuthoritySHA256: hex.EncodeToString(authoritySHA[:]),
		SourceConfigurationID: authority.ConfigurationID, SourceTargetDigest: liveDigest,
		BackupSet: backupSet, OwnerMemberID: owner.MemberID, OwnerIncarnation: owner.Incarnation,
		BackupTargetDigest: backupDigest, BackupS3ConfigSHA256: configSHA,
		BackupS3CredentialSHA256: spec.Backup.Target.CredentialSHA256,
		SignerKeyID:              keyID, BackupDataKeyID: spec.Backup.DataKeyID,
		BackupDataKeySHA256:  spec.Backup.DataKeySHA256,
		RetentionPolicyID:    spec.Backup.RetentionPolicyID,
		RetentionUntilUnixMS: spec.Backup.RetentionUntilUnixMS,
		MaxPointCadenceMS:    spec.Backup.MaxPointCadenceMS}, nil
}
