//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"uuid"
)

const (
	backupManifestFileName   = "backup-managed-manifest.json"
	backupS3ConfigFileName   = "backup-s3-config.json"
	backupCredentialFileName = "backup-s3-credentials.json"
	backupDataKeyFileName    = "backup-data.key"
	backupManifestSignDomain = "TB-BACKUP-MANIFEST-V1\x00"
	backupTargetDomain       = "terrabase-s3-target-v1\x00"
)

type managedBackupEnvelope struct {
	Version   uint64 `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type managedBackupManifest struct {
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

type managedBackupS3Config struct {
	Version  uint64 `json:"version"`
	Bucket   string `json:"bucket"`
	Region   string `json:"region"`
	Endpoint string `json:"endpoint,omitempty"`
}

type managedBackupCredential struct {
	Version         uint64 `json:"version"`
	TargetDigest    string `json:"target_digest"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

func backupScopeDigest(scope MemberScope) (string, error) {
	tenant, err := uuid.Parse(scope.TenantID)
	if err != nil {
		return "", err
	}
	database, err := uuid.Parse(scope.DatabaseID)
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

func backupTargetDigest(config managedBackupS3Config) (string, error) {
	if config.Version != 1 || len(config.Bucket) == 0 || len(config.Bucket) > 255 ||
		len(config.Region) == 0 || len(config.Region) > 64 || strings.ContainsAny(config.Region, "._") {
		return "", errors.New("managed backup S3 config is invalid")
	}
	for _, value := range []string{config.Bucket, config.Region} {
		for _, c := range value {
			if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
				return "", errors.New("managed backup S3 name is invalid")
			}
		}
	}
	if config.Endpoint != "" {
		u, err := url.Parse(config.Endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" || u.Path != "" ||
			u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Host, ":443") ||
			config.Endpoint != "https://"+u.Host {
			return "", errors.New("managed backup S3 endpoint is not canonical")
		}
	}
	h := sha256.New()
	h.Write([]byte(backupTargetDomain))
	for _, part := range []string{config.Region, config.Bucket, config.Endpoint} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readManagedBackupMaterial(material string, launch ManagedMemberLaunch, trustKey, liveConfig []byte,
	identity WorkloadIdentity, ownerUID uint32, checkOwnerFiles bool,
) ([]string, error) {
	pins := launch.Runtime
	if pins == nil || pins.BackupManifestSHA256 == "" {
		return nil, nil
	}
	manifestPath := filepath.Join(material, backupManifestFileName)
	data, err := readManagedClientFile(manifestPath, pins.BackupManifestSHA256, identity, 16<<10, ownerUID)
	if err != nil {
		return nil, err
	}
	var envelope managedBackupEnvelope
	if err := json.Unmarshal(data, &envelope, json.RejectUnknownMembers(true)); err != nil || envelope.Version != 1 {
		return nil, errors.New("managed backup manifest envelope is invalid")
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, errors.New("managed backup manifest envelope is not canonical")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != envelope.Payload {
		return nil, errors.New("managed backup manifest payload is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature || len(trustKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(trustKey, append([]byte(backupManifestSignDomain), payload...), signature) {
		return nil, errors.New("managed backup manifest signature is invalid")
	}
	var manifest managedBackupManifest
	if err := json.Unmarshal(payload, &manifest, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("managed backup manifest payload is invalid")
	}
	canonical, err = json.Marshal(manifest)
	if err != nil || !bytes.Equal(payload, canonical) {
		return nil, errors.New("managed backup manifest payload is not canonical")
	}
	configPath := filepath.Join(material, backupS3ConfigFileName)
	configBytes, err := readManagedClientFile(configPath, pins.BackupS3ConfigSHA256, identity, 16<<10, ownerUID)
	if err != nil {
		return nil, err
	}
	var config managedBackupS3Config
	if err := json.Unmarshal(configBytes, &config, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("managed backup S3 config is invalid")
	}
	canonical, err = json.Marshal(config)
	if err != nil || !bytes.Equal(configBytes, canonical) {
		return nil, errors.New("managed backup S3 config is not canonical")
	}
	targetDigest, err := backupTargetDigest(config)
	if err != nil {
		return nil, err
	}
	var live struct {
		Bucket string `json:"bucket"`
		Region string `json:"region"`
	}
	if err := json.Unmarshal(liveConfig, &live); err != nil ||
		strings.EqualFold(live.Bucket, config.Bucket) && strings.EqualFold(live.Region, config.Region) {
		return nil, errors.New("managed backup target aliases live source")
	}
	scopeDigest, err := backupScopeDigest(launch.Member.Scope)
	if err != nil {
		return nil, err
	}
	keySHA := sha256.Sum256(trustKey)
	owner := manifest.OwnerMemberID == launch.Member.Scope.MemberID
	backupSet, err := hex.DecodeString(manifest.BackupSet)
	if err != nil || len(backupSet) != 16 || bytes.Equal(backupSet, make([]byte, 16)) ||
		hex.EncodeToString(backupSet) != manifest.BackupSet ||
		manifest.Version != 1 || manifest.ClusterID != launch.Member.Scope.ClusterID ||
		manifest.TenantID != launch.Member.Scope.TenantID || manifest.DatabaseID != launch.Member.Scope.DatabaseID ||
		manifest.ShardID != launch.Member.Scope.ShardID || manifest.SourceScopeDigest != scopeDigest ||
		manifest.SourceAuthoritySHA256 != launch.Authority.CertificateSHA256 ||
		manifest.SourceConfigurationID != launch.Authority.ConfigurationID ||
		manifest.SourceTargetDigest != pins.LiveS3TargetSHA256 ||
		manifest.BackupTargetDigest != pins.BackupS3TargetSHA256 || targetDigest != pins.BackupS3TargetSHA256 ||
		manifest.BackupS3ConfigSHA256 != pins.BackupS3ConfigSHA256 ||
		manifest.BackupS3CredentialSHA256 != pins.BackupS3CredentialSHA256 ||
		manifest.BackupDataKeySHA256 != pins.BackupDataKeySHA256 ||
		manifest.SignerKeyID != "sha256:"+hex.EncodeToString(keySHA[:]) ||
		!validBackupMaterialToken(manifest.BackupDataKeyID, 256) ||
		!validBackupMaterialPolicyID(manifest.RetentionPolicyID) ||
		manifest.RetentionUntilUnixMS == 0 || manifest.MaxPointCadenceMS < 60_000 ||
		manifest.MaxPointCadenceMS > 30*24*60*60*1000 ||
		owner != pins.BackupOwner ||
		owner && manifest.OwnerIncarnation != launch.Member.Scope.Incarnation ||
		!owner && manifest.OwnerMemberID != pins.ReplicationPeerMemberID ||
		!lowerHex(manifest.OwnerIncarnation, 32) {
		return nil, errors.New("managed backup manifest differs from signed runtime authority")
	}
	args := []string{"--backup-managed-manifest", manifestPath,
		"--backup-managed-manifest-sha256", pins.BackupManifestSHA256,
		"--backup-s3-config", configPath}
	if owner && checkOwnerFiles {
		credentialPath := filepath.Join(material, backupCredentialFileName)
		credentialBytes, err := readManagedClientFile(credentialPath, pins.BackupS3CredentialSHA256, identity, 4<<10, ownerUID)
		if err != nil {
			return nil, err
		}
		var credential managedBackupCredential
		if err := json.Unmarshal(credentialBytes, &credential, json.RejectUnknownMembers(true)); err != nil ||
			credential.Version != 1 || credential.TargetDigest != targetDigest ||
			!validS3Credential(credential.AccessKeyID) || !validS3Credential(credential.SecretAccessKey) {
			return nil, errors.New("managed backup credential is invalid")
		}
		canonical, err := json.Marshal(credential)
		if err != nil || !bytes.Equal(credentialBytes, canonical) {
			return nil, errors.New("managed backup credential is not canonical")
		}
		keyPath := filepath.Join(material, backupDataKeyFileName)
		key, err := readManagedClientFile(keyPath, pins.BackupDataKeySHA256, identity, 32, ownerUID)
		if err != nil || len(key) != 32 {
			return nil, errors.New("managed backup data key is invalid")
		}
		clear(key)
		args = append(args, "--backup-s3-credentials", credentialPath, "--backup-data-key", keyPath)
	} else if !owner {
		for _, name := range []string{backupCredentialFileName, backupDataKeyFileName} {
			if _, err := os.Lstat(filepath.Join(material, name)); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("backup peer has owner-only material")
			}
		}
	}
	return args, nil
}

func prepareManagedBackupFiles(ctx context.Context, cfg AgentConfig, launch ManagedMemberLaunch,
	material string,
) error {
	pins := launch.Runtime
	if pins == nil || pins.BackupManifestSHA256 == "" || !pins.BackupOwner {
		return nil
	}
	if cfg.ManagedS3Credentials == nil || cfg.ManagedBackupDataKeys == nil {
		return errors.New("managed backup Vault resolvers are unavailable")
	}
	credentials, err := cfg.ManagedS3Credentials.Resolve(ctx, pins.BackupS3Credential)
	if err != nil || !validS3Credential(credentials.AccessKeyID) || !validS3Credential(credentials.SecretAccessKey) {
		return errors.New("managed backup S3 credential resolution failed")
	}
	data, err := json.Marshal(managedBackupCredential{Version: 1, TargetDigest: pins.BackupS3TargetSHA256,
		AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey})
	if err != nil {
		return errors.New("managed backup credential encoding failed")
	}
	defer clear(data)
	credentialSHA := sha256.Sum256(data)
	if hex.EncodeToString(credentialSHA[:]) != pins.BackupS3CredentialSHA256 {
		return errors.New("managed backup credential differs from signed target binding")
	}
	key, err := cfg.ManagedBackupDataKeys.ResolveBackupDataKey(ctx, pins.BackupDataKey)
	if err != nil || len(key) != 32 {
		clear(key)
		return errors.New("managed backup data key resolution failed")
	}
	defer clear(key)
	keySHA := sha256.Sum256(key)
	if hex.EncodeToString(keySHA[:]) != pins.BackupDataKeySHA256 {
		return errors.New("managed backup data key differs from signed pin")
	}
	if err := installManagedFile(material, backupCredentialFileName, data,
		pins.BackupS3CredentialSHA256, cfg.WorkloadIdentity); err != nil {
		return err
	}
	return installManagedFile(material, backupDataKeyFileName, key,
		pins.BackupDataKeySHA256, cfg.WorkloadIdentity)
}

func validBackupMaterialToken(value string, maximum int) bool {
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

func validBackupMaterialPolicyID(value string) bool {
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
