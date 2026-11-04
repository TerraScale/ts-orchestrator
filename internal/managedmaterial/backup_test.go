package managedmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
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
