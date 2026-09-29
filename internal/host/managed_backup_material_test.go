//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

type backupCredentialResolverFixture struct {
	reference oci.SecretVersionReference
	value     ManagedS3Credentials
	calls     int
}

func (resolver *backupCredentialResolverFixture) Resolve(_ context.Context,
	reference oci.SecretVersionReference,
) (ManagedS3Credentials, error) {
	resolver.calls++
	if reference != resolver.reference {
		return ManagedS3Credentials{}, errors.New("unexpected backup credential version")
	}
	return resolver.value, nil
}

type backupDataKeyResolverFixture struct {
	reference oci.SecretVersionReference
	key       []byte
	calls     int
}

func (resolver *backupDataKeyResolverFixture) ResolveBackupDataKey(_ context.Context,
	reference oci.SecretVersionReference,
) ([]byte, error) {
	resolver.calls++
	if reference != resolver.reference {
		return nil, errors.New("unexpected backup data-key version")
	}
	return bytes.Clone(resolver.key), nil
}

type backupGoldenFixture struct {
	PublicKeyHex           string `json:"public_key_hex"`
	SourceTargetDigest     string `json:"source_target_digest"`
	BackupTargetDigest     string `json:"backup_target_digest"`
	BackupS3ConfigJSON     string `json:"backup_s3_config_json"`
	BackupS3CredentialJSON string `json:"backup_s3_credential_json"`
	BackupDataKeyHex       string `json:"backup_data_key_hex"`
	Manifest               struct {
		PayloadJSON    string `json:"payload_json"`
		EnvelopeJSON   string `json:"envelope_json"`
		EnvelopeSHA256 string `json:"envelope_sha256"`
	} `json:"manifest"`
}

func readBackupGoldenFixture(t *testing.T) backupGoldenFixture {
	t.Helper()
	data, err := os.ReadFile("../../testdata/backup-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture backupGoldenFixture
	if err := json.Unmarshal(data, &fixture, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func writeBackupTestFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0440); err != nil {
		t.Fatal(err)
	}
}

func TestManagedBackupLaunchReadsExactSignedMaterialAndKeepsSecretsOutOfArgs(t *testing.T) {
	fixture := readBackupGoldenFixture(t)
	var manifest managedBackupManifest
	if err := json.Unmarshal([]byte(fixture.Manifest.PayloadJSON), &manifest); err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(fixture.BackupDataKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	material := t.TempDir()
	writeBackupTestFile(t, material, backupManifestFileName, []byte(fixture.Manifest.EnvelopeJSON))
	writeBackupTestFile(t, material, backupS3ConfigFileName, []byte(fixture.BackupS3ConfigJSON))
	writeBackupTestFile(t, material, backupCredentialFileName, []byte(fixture.BackupS3CredentialJSON))
	writeBackupTestFile(t, material, backupDataKeyFileName, key)
	identity := WorkloadIdentity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	launch := ManagedMemberLaunch{Member: ManagedMemberBinding{Scope: MemberScope{
		ClusterID: manifest.ClusterID, TenantID: manifest.TenantID, DatabaseID: manifest.DatabaseID,
		ShardID: manifest.ShardID, MemberID: manifest.OwnerMemberID, Incarnation: manifest.OwnerIncarnation,
	}}, Authority: MemberAuthority{ConfigurationID: manifest.SourceConfigurationID,
		CertificateSHA256: manifest.SourceAuthoritySHA256}, Runtime: &ManagedRuntimePins{
		BackupManifestSHA256:     fixture.Manifest.EnvelopeSHA256,
		BackupS3ConfigSHA256:     manifest.BackupS3ConfigSHA256,
		BackupS3TargetSHA256:     fixture.BackupTargetDigest,
		BackupS3CredentialSHA256: manifest.BackupS3CredentialSHA256,
		BackupDataKeySHA256:      manifest.BackupDataKeySHA256,
		BackupOwner:              true, LiveS3TargetSHA256: fixture.SourceTargetDigest,
		ReplicationPeerMemberID: "44444444-4444-4444-4444-444444444444",
	}}
	if slices.Contains(managedHostFileNames[:], backupCredentialFileName) ||
		slices.Contains(managedHostFileNames[:], backupDataKeyFileName) {
		t.Fatal("backup owner secrets entered NATS material allowlist")
	}
	live := []byte(`{"version":1,"ack_profile":"object_durable","bucket":"live-bucket","region":"sa-saopaulo-1","endpoint":"https://live.example.test"}`)
	args, err := readManagedBackupMaterial(material, launch, public, live, identity, identity.UID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--backup-managed-manifest") || !slices.Contains(args, "--backup-data-key") ||
		!slices.Contains(args, "--backup-s3-credentials") ||
		strings.Contains(strings.Join(args, " "), "fixture-secret") ||
		strings.Contains(strings.Join(args, " "), fixture.BackupDataKeyHex) {
		t.Fatal("backup launch omitted exact flags or exposed a secret")
	}
	if err := os.Chmod(filepath.Join(material, backupDataKeyFileName), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedBackupMaterial(material, launch, public, live, identity, identity.UID, true); err == nil {
		t.Fatal("world-readable backup key accepted")
	}
	if err := os.Chmod(filepath.Join(material, backupDataKeyFileName), 0440); err != nil {
		t.Fatal(err)
	}
	changed := launch
	pins := *launch.Runtime
	pins.BackupS3TargetSHA256 = strings.Repeat("f", 64)
	changed.Runtime = &pins
	if _, err := readManagedBackupMaterial(material, changed, public, live, identity, identity.UID, false); err == nil {
		t.Fatal("backup target pin mismatch accepted")
	}
	wrong := launch
	wrong.Member.Scope.DatabaseID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if _, err := readManagedBackupMaterial(material, wrong, public, live, identity, identity.UID, false); err == nil {
		t.Fatal("wrong source database accepted")
	}
	aliasedLive := []byte(`{"bucket":"backup-bucket","region":"sa-saopaulo-1"}`)
	if _, err := readManagedBackupMaterial(material, launch, public, aliasedLive, identity, identity.UID, false); err == nil {
		t.Fatal("backup target aliasing live bucket accepted")
	}
	caseAliasedLive := []byte(`{"bucket":"BACKUP-BUCKET","region":"SA-SAOPAULO-1"}`)
	if _, err := readManagedBackupMaterial(material, launch, public, caseAliasedLive, identity, identity.UID, false); err == nil {
		t.Fatal("case-only backup target aliasing live bucket accepted")
	}
	peerMaterial := t.TempDir()
	writeBackupTestFile(t, peerMaterial, backupManifestFileName, []byte(fixture.Manifest.EnvelopeJSON))
	writeBackupTestFile(t, peerMaterial, backupS3ConfigFileName, []byte(fixture.BackupS3ConfigJSON))
	peer := launch
	peer.Member.Scope.MemberID = "44444444-4444-4444-4444-444444444444"
	peer.Member.Scope.Incarnation = strings.Repeat("6", 32)
	peerPins := *launch.Runtime
	peerPins.BackupOwner = false
	peerPins.ReplicationPeerMemberID = manifest.OwnerMemberID
	peer.Runtime = &peerPins
	peerArgs, err := readManagedBackupMaterial(peerMaterial, peer, public, live, identity, identity.UID, true)
	if err != nil || slices.Contains(peerArgs, "--backup-s3-credentials") || slices.Contains(peerArgs, "--backup-data-key") {
		t.Fatalf("backup peer was given publication secrets: %v", err)
	}
	writeBackupTestFile(t, peerMaterial, backupCredentialFileName, []byte(fixture.BackupS3CredentialJSON))
	if _, err := readManagedBackupMaterial(peerMaterial, peer, public, live, identity, identity.UID, true); err == nil {
		t.Fatal("backup peer with owner credential was accepted")
	}
	if sha := sha256.Sum256([]byte(fixture.Manifest.EnvelopeJSON)); hex.EncodeToString(sha[:]) != fixture.Manifest.EnvelopeSHA256 {
		t.Fatal("golden manifest whole-file digest changed")
	}
}

func TestManagedBackupOwnerInstallsExactProtectedVaultVersions(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership requires the production host identity")
	}
	fixture := readBackupGoldenFixture(t)
	var manifest managedBackupManifest
	if err := json.Unmarshal([]byte(fixture.Manifest.PayloadJSON), &manifest); err != nil {
		t.Fatal(err)
	}
	var credential managedBackupCredential
	if err := json.Unmarshal([]byte(fixture.BackupS3CredentialJSON), &credential); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(fixture.BackupDataKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	credentialRef := oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backup", VersionNumber: 4}
	keyRef := oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backupkey", VersionNumber: 9}
	credentials := &backupCredentialResolverFixture{reference: credentialRef,
		value: ManagedS3Credentials{AccessKeyID: credential.AccessKeyID, SecretAccessKey: credential.SecretAccessKey}}
	keys := &backupDataKeyResolverFixture{reference: keyRef, key: key}
	identity := WorkloadIdentity{UID: 1000, GID: 1000}
	launch := ManagedMemberLaunch{Runtime: &ManagedRuntimePins{
		BackupOwner: true, BackupManifestSHA256: fixture.Manifest.EnvelopeSHA256,
		BackupS3TargetSHA256:     fixture.BackupTargetDigest,
		BackupS3CredentialSHA256: manifest.BackupS3CredentialSHA256,
		BackupDataKeySHA256:      manifest.BackupDataKeySHA256,
		BackupS3Credential:       credentialRef, BackupDataKey: keyRef,
	}}
	cfg := AgentConfig{ManagedS3Credentials: credentials, ManagedBackupDataKeys: keys,
		WorkloadIdentity: identity}
	material := t.TempDir()
	if err := prepareManagedBackupFiles(t.Context(), cfg, launch, material); err != nil {
		t.Fatal(err)
	}
	if credentials.calls != 1 || keys.calls != 1 {
		t.Fatal("backup owner did not fetch both exact Vault versions")
	}
	for _, item := range []struct {
		name, digest string
		maximum      int64
		want         []byte
	}{
		{backupCredentialFileName, manifest.BackupS3CredentialSHA256, 4 << 10, []byte(fixture.BackupS3CredentialJSON)},
		{backupDataKeyFileName, manifest.BackupDataKeySHA256, 32, key},
	} {
		got, err := readManagedClientFile(filepath.Join(material, item.name), item.digest, identity, item.maximum, 0)
		if err != nil || !bytes.Equal(got, item.want) {
			t.Fatalf("protected backup file %s differs from its exact Vault version: %v", item.name, err)
		}
	}
	if err := prepareManagedBackupFiles(t.Context(), cfg, launch, material); err != nil {
		t.Fatalf("exact retry changed protected backup files: %v", err)
	}
	badMaterial := t.TempDir()
	badKey := &backupDataKeyResolverFixture{reference: keyRef, key: bytes.Repeat([]byte{0x01}, 32)}
	cfg.ManagedBackupDataKeys = badKey
	if err := prepareManagedBackupFiles(t.Context(), cfg, launch, badMaterial); err == nil {
		t.Fatal("wrong exact Vault key passed the signed pin")
	}
	for _, name := range []string{backupCredentialFileName, backupDataKeyFileName} {
		if _, err := os.Lstat(filepath.Join(badMaterial, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed backup key left owner file %s: %v", name, err)
		}
	}
}
