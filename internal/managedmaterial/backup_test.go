package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func backupInitialFixture(t *testing.T) (InitialSpec, ed25519.PublicKey) {
	t.Helper()
	spec, signer, _ := initialFixture(t)
	target := BackupS3Target{Bucket: "alpha-backup", Region: "sa-saopaulo-1",
		Endpoint:         "https://backup.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
		Credential:       oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backup", VersionNumber: 4},
		CredentialSHA256: hex.EncodeToString(make([]byte, 32))}
	digest, err := target.Digest()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := json.Marshal(struct {
		Version         uint64 `json:"version"`
		TargetDigest    string `json:"target_digest"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}{1, digest, "fixture-access", "fixture-secret"})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(credential)
	target.CredentialSHA256 = hex.EncodeToString(hash[:])
	key := bytes.Repeat([]byte{0x42}, 32)
	keySHA := sha256.Sum256(key)
	spec.Backup = &InitialBackupSpec{Target: target, OwnerMemberID: spec.Members[0].MemberID,
		DataKey:   oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.backupkey", VersionNumber: 9},
		DataKeyID: "0000000000EANCHT87G4P8DB4B", DataKeySHA256: hex.EncodeToString(keySHA[:]),
		RetentionPolicyID: "retention-30d", RetentionUntilUnixMS: uint64(time.Now().Add(30 * 24 * time.Hour).UnixMilli()),
		MaxPointCadenceMS: 60_000}
	return spec, signer
}

func TestOptionalBackupProducerSignsIndependentManifestAndRejectsDrift(t *testing.T) {
	spec, signer := backupInitialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBundleForSpec(spec, bundle); err != nil {
		t.Fatalf("generated backup bundle rejected: %v", err)
	}
	for i, member := range bundle.Members {
		if len(member.Files) != len(initialHostFiles)+2 ||
			member.Files[backupManifestName].SHA256 == "" || member.Files[backupConfigName].SHA256 == "" {
			t.Fatalf("member %d lacks exact independent backup files", i)
		}
		if _, present := member.Files["backup-data.key"]; present {
			t.Fatal("producer exposed data key in host material")
		}
		if _, present := member.Files["backup-s3-credentials.json"]; present {
			t.Fatal("producer exposed credential in host material")
		}
	}
	if !bytes.Equal(bundle.Members[0].Files[backupManifestName].Contents,
		bundle.Members[1].Files[backupManifestName].Contents) {
		t.Fatal("backup set differs between members")
	}
	changed := bundle
	changed.Members[0].Files = make(map[string]File, len(bundle.Members[0].Files))
	for name, file := range bundle.Members[0].Files {
		changed.Members[0].Files[name] = file
	}
	changed.Members[0].Files[backupManifestName] = makeFile([]byte(`{"version":1,"payload":"bad","signature":"bad"}`))
	if err := validateBundleForSpec(spec, changed); err == nil {
		t.Fatal("changed signed manifest accepted")
	}
	aliased := *spec.Backup
	aliased.Target.Bucket = spec.LiveS3.Bucket
	aliased.Target.Region = spec.LiveS3.Region
	spec.Backup = &aliased
	if err := spec.Backup.Validate(spec.LiveS3, spec.Members, time.Now()); err == nil {
		t.Fatal("backup target aliasing live bucket accepted")
	}
	aliased.Target.Bucket = strings.ToUpper(spec.LiveS3.Bucket)
	aliased.Target.Region = strings.ToUpper(spec.LiveS3.Region)
	if err := aliased.Validate(spec.LiveS3, spec.Members, time.Now()); err == nil {
		t.Fatal("case-only backup target aliasing live bucket accepted")
	}
}

func TestBackupWireGoldenManifestUsesExactSignedRawPayload(t *testing.T) {
	data, err := os.ReadFile("../../testdata/backup-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		PublicKeyHex       string `json:"public_key_hex"`
		SourceScopeDigest  string `json:"source_scope_digest"`
		BackupTargetDigest string `json:"backup_target_digest"`
		Manifest           struct {
			PayloadJSON    string `json:"payload_json"`
			PreimageHex    string `json:"preimage_hex"`
			SignatureHex   string `json:"signature_hex"`
			EnvelopeJSON   string `json:"envelope_json"`
			EnvelopeSHA256 string `json:"envelope_sha256"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := hex.DecodeString(fixture.Manifest.PreimageHex)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(fixture.Manifest.SignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preimage, append([]byte(backupManifestDomain), fixture.Manifest.PayloadJSON...)) ||
		!ed25519.Verify(public, preimage, signature) {
		t.Fatal("manifest golden signature or preimage changed")
	}
	var envelope backupManifestEnvelope
	if err := json.Unmarshal([]byte(fixture.Manifest.EnvelopeJSON), &envelope, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || string(payload) != fixture.Manifest.PayloadJSON {
		t.Fatal("manifest envelope payload differs from golden")
	}
	var manifest BackupManifestPayload
	if err := json.Unmarshal(payload, &manifest, json.RejectUnknownMembers(true)); err != nil ||
		manifest.SourceScopeDigest != fixture.SourceScopeDigest ||
		manifest.BackupTargetDigest != fixture.BackupTargetDigest {
		t.Fatal("manifest golden fields differ")
	}
	scopeDigest, err := backupScopeDigest(AuthorityScope{TenantID: manifest.TenantID,
		DatabaseID: manifest.DatabaseID, ShardID: manifest.ShardID})
	if err != nil || scopeDigest != fixture.SourceScopeDigest {
		t.Fatalf("Go source scope digest differs from Rust golden: %v", err)
	}
	hash := sha256.Sum256([]byte(fixture.Manifest.EnvelopeJSON))
	if hex.EncodeToString(hash[:]) != fixture.Manifest.EnvelopeSHA256 {
		t.Fatal("manifest whole-file golden digest changed")
	}
}

func TestNativeInitialInputCarriesExactBackupFilesAndRejectsPartialGroup(t *testing.T) {
	spec, signer := backupInitialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	input, err := nativeInitialInput(spec, bundle)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeNativeValidationRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	var request nativeValidationRequest
	if err := json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if request.BackupManagedManifest != base64.StdEncoding.EncodeToString(bundle.Members[0].Files[backupManifestName].Contents) ||
		request.BackupS3Config != base64.StdEncoding.EncodeToString(bundle.Members[0].Files[backupConfigName].Contents) ||
		request.Expected.BackupManagedManifestSHA256 != bundle.Members[0].Files[backupManifestName].SHA256 ||
		request.Expected.BackupS3ConfigSHA256 != bundle.Members[0].Files[backupConfigName].SHA256 ||
		request.Expected.BackupTargetDigest != input.ExpectedBackupTargetDigest ||
		request.Expected.BackupSet != input.ExpectedBackupSet {
		t.Fatal("native verifier request omitted exact signed backup material")
	}
	partial := input
	partial.BackupS3Config = nil
	if _, err := encodeNativeValidationRequest(partial); err == nil {
		t.Fatal("partial backup native request accepted")
	}
	noBackupSpec, noBackupSigner, _ := initialFixture(t)
	noBackupBundle, err := GenerateInitial(noBackupSpec, noBackupSigner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	noBackupInput, err := nativeInitialInput(noBackupSpec, noBackupBundle)
	if err != nil {
		t.Fatal(err)
	}
	noBackupWire, err := encodeNativeValidationRequest(noBackupInput)
	if err != nil || bytes.Contains(noBackupWire, []byte("backup_")) {
		t.Fatal("no-backup native verifier wire gained backup fields")
	}
}
