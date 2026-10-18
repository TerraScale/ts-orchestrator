//go:build linux

package managedmaterial

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/tier"
)

const (
	nativeVerifierSHA256Environment       = "TS_TEST_NATIVE_VERIFIER_SHA256"
	nativeVerifierSourceCommitEnvironment = "TS_TEST_NATIVE_VERIFIER_SOURCE_COMMIT"

	admittedNativeVerifierSHA256       = "2891f6e88cb934b737aa29d02114c908f3590faacf2dac7a6781f2276942411d"
	admittedNativeVerifierSourceCommit = "77dbd680504012fcee1ebf489d4813da5104912d"
)

func TestPrepareInitialUsesAdmittedPackagedNativeValidator(t *testing.T) {
	pinnedSHA256, hasSHA256 := os.LookupEnv(nativeVerifierSHA256Environment)
	sourceCommit, hasSourceCommit := os.LookupEnv(nativeVerifierSourceCommitEnvironment)
	if !hasSHA256 && !hasSourceCommit {
		tier.Unavailable(t, "admitted packaged native validator fixture was not requested")
	}
	if !hasSHA256 || !hasSourceCommit || pinnedSHA256 == "" || sourceCommit == "" {
		t.Fatalf("native validator opt-in requires %s and %s together",
			nativeVerifierSHA256Environment, nativeVerifierSourceCommitEnvironment)
	}
	if !lowerHexDigest(pinnedSHA256) {
		t.Fatalf("%s must be a lowercase SHA-256 digest", nativeVerifierSHA256Environment)
	}
	if len(sourceCommit) != 40 || strings.ToLower(sourceCommit) != sourceCommit {
		t.Fatalf("%s must be a lowercase 40-character source commit", nativeVerifierSourceCommitEnvironment)
	}
	if _, err := hex.DecodeString(sourceCommit); err != nil {
		t.Fatalf("%s must be a lowercase 40-character source commit: %v", nativeVerifierSourceCommitEnvironment, err)
	}
	if pinnedSHA256 != admittedNativeVerifierSHA256 || sourceCommit != admittedNativeVerifierSourceCommit {
		t.Fatalf("native validator admission mismatch: got source=%s sha256=%s; want TerraBase source=%s sha256=%s (release ci-77dbd680504012fcee1ebf489d4813da5104912d-run-11534)",
			sourceCommit, pinnedSHA256, admittedNativeVerifierSourceCommit, admittedNativeVerifierSHA256)
	}
	if runtime.GOARCH != "amd64" {
		t.Fatalf("admitted native validator is linux/amd64; test host is %s", runtime.GOARCH)
	}

	service, spec, objects, receipts := preparationFixture(t)
	service.NativeValidator = PackagedNativeMaterialValidator{}
	service.NativeVerifierSHA256 = pinnedSHA256
	now := time.Now().UTC()
	receipt, err := service.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now)
	if err != nil {
		t.Fatalf("prepare initial managed material through the admitted TerraBase validator: %v", err)
	}
	confirmed, bundle, err := service.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatalf("verify committed R3 receipt and exact material object: %v", err)
	}
	if confirmed.Signature != receipt.Signature || confirmed.Object != receipt.Object ||
		objects.putCount != 1 || receipts.commitCount != 1 || receipts.entry == nil ||
		len(confirmed.Object.SpecSHA256) != 64 ||
		receipts.entry.Kind != authority.MutationMaterialReceipt ||
		receipts.entry.SubjectKey != spec.PlacementDatabaseID+"."+spec.PartitionID ||
		receipts.entry.OperationID != "material-g1-"+confirmed.Object.SpecSHA256[:24] ||
		receipts.entry.Epoch != 9 || receipts.entry.Sequence != 11 ||
		objects.name != confirmed.Object.Name || objects.version != confirmed.Object.VersionID ||
		objects.etag != confirmed.Object.ETag || objects.bodySHA != confirmed.Object.SHA256 {
		t.Fatalf("native-validated preparation did not produce exactly one matching object Put and R3 CAS: receipt=%+v entry=%+v puts=%d commits=%d object_name=%s object_version=%s object_etag=%s object_sha256=%s",
			confirmed, receipts.entry, objects.putCount, receipts.commitCount, objects.name, objects.version, objects.etag, objects.bodySHA)
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
	config, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	if request.Version != 1 || request.Mode != "alpha_object_durable" ||
		request.AuthorityCertificate != base64.StdEncoding.EncodeToString(bundle.Authority.Certificate) ||
		request.TrustedKey != base64.StdEncoding.EncodeToString(bundle.Authority.TrustedKey) ||
		request.SignedV2S3Config != base64.StdEncoding.EncodeToString(config) ||
		request.Expected.ConfigurationID != bundle.Authority.ConfigurationID ||
		request.Expected.CertificateSHA256 != sha256Hex(bundle.Authority.Certificate) ||
		request.Expected.TrustedKeySHA256 != sha256Hex(bundle.Authority.TrustedKey) ||
		request.Expected.SignedV2S3ConfigSHA256 != sha256Hex(config) ||
		bytes.Contains(wire, []byte(spec.LiveS3.Credential.SecretOCID)) ||
		bytes.Contains(wire, []byte("secret_access_key")) {
		t.Fatal("native request differs from public produced material or carries a secret reference")
	}
	t.Logf("accepted admitted TerraBase native verifier source=%s sha256=%s",
		sourceCommit, pinnedSHA256)

	if requestPath := os.Getenv("TS_ALPHA_NATIVE_REQUEST_FILE"); requestPath != "" {
		input, err := nativeInitialInput(spec, bundle)
		if err != nil {
			t.Fatalf("rebuild native request from committed initial material: %v", err)
		}
		wire, err := encodeNativeValidationRequest(input)
		if err != nil {
			t.Fatalf("encode native request from committed initial material: %v", err)
		}
		if err := os.WriteFile(requestPath, wire, 0o600); err != nil {
			t.Fatalf("retain producer-derived native request: %v", err)
		}
		t.Logf("producer-derived native request: %s SHA-256 %s", requestPath, sha256Hex(wire))
	}
}
