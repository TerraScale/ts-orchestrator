package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestForgejoDetailMustMatchExactRunSourceJobAndSuccess(t *testing.T) {
	qualification, _, err := release.DecodeQualification(testQualificationBytes())
	if err != nil {
		t.Fatal(err)
	}
	valid := forgejoRunDetail{
		RunID: qualification.Verification.RunID, RunNumber: qualification.Verification.RunNumber,
		HeadSHA: qualification.SourceRevision, Workflow: qualification.Verification.Workflow, Status: "success",
		Jobs: []forgejoJobDetail{{ID: 24140, RunID: qualification.Verification.RunID,
			Name: qualification.Verification.Job, Status: "success", Attempt: 1}},
	}
	for _, test := range []struct {
		name      string
		mutate    func(*forgejoRunDetail)
		wantError bool
	}{
		{"success", func(*forgejoRunDetail) {}, false},
		{"additional configuration check", func(d *forgejoRunDetail) {
			d.Jobs = append([]forgejoJobDetail{{ID: 24139, RunID: d.RunID,
				Name: "Reject new configuration switches", Status: "success", Attempt: 1}}, d.Jobs...)
		}, false},
		{"missing required job", func(d *forgejoRunDetail) { d.Jobs = nil }, true},
		{"other run ID", func(d *forgejoRunDetail) { d.RunID++ }, true},
		{"other run number", func(d *forgejoRunDetail) { d.RunNumber++ }, true},
		{"other full source", func(d *forgejoRunDetail) { d.HeadSHA = qualification.SourceRevision[:10] + strings.Repeat("a", 30) }, true},
		{"other workflow", func(d *forgejoRunDetail) { d.Workflow = "release.yml" }, true},
		{"failed run", func(d *forgejoRunDetail) { d.Status = "failure" }, true},
		{"extra job suffix", func(d *forgejoRunDetail) { d.Jobs[0].Name += " extra" }, true},
		{"failed job", func(d *forgejoRunDetail) { d.Jobs[0].Status = "failure" }, true},
		{"job on another run", func(d *forgejoRunDetail) { d.Jobs[0].RunID++ }, true},
		{"missing job ID", func(d *forgejoRunDetail) { d.Jobs[0].ID = 0 }, true},
		{"missing job attempt", func(d *forgejoRunDetail) { d.Jobs[0].Attempt = 0 }, true},
		{"duplicate job", func(d *forgejoRunDetail) { d.Jobs = append(d.Jobs, d.Jobs[0]) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			detail := valid
			detail.Jobs = append([]forgejoJobDetail(nil), valid.Jobs...)
			test.mutate(&detail)
			wire, err := trust.EncodePayload(detail)
			if err != nil {
				t.Fatal(err)
			}
			job, err := matchForgejoRunDetail(wire, qualification)
			if (err != nil) != test.wantError {
				t.Fatalf("matchForgejoRunDetail() error = %v; wantError=%t", err, test.wantError)
			}
			if err == nil && job.ID != valid.Jobs[0].ID {
				t.Fatalf("selected job ID = %d; want %d", job.ID, valid.Jobs[0].ID)
			}
		})
	}
}

func TestForgejoLogSealsExactRetainedManifest(t *testing.T) {
	qualification, digest, err := release.DecodeQualification(testQualificationBytes())
	if err != nil {
		t.Fatal(err)
	}
	marker := "TS_RELEASE_QUALIFICATION_V1 source_sha=" + qualification.SourceRevision +
		" run_id=4001 run_number=620 manifest_sha256=" + digest
	stamp := "2026-09-26T23:13:24.7600896Z "
	if err := matchForgejoQualificationLog([]byte("build verified\n"+stamp+marker+"\n"), qualification, digest); err != nil {
		t.Fatalf("matchForgejoQualificationLog() rejected exact marker: %v", err)
	}
	for _, logs := range []string{
		"build verified\n",
		stamp + strings.Replace(marker, "run_id=4001", "run_id=4002", 1) + "\n",
		stamp + strings.Replace(marker, digest, strings.Repeat("b", 64), 1) + "\n",
		stamp + marker + "\n" + stamp + marker + "\n",
		marker + "\n",
		"bad-timestamp " + marker + "\n",
	} {
		if err := matchForgejoQualificationLog([]byte(logs), qualification, digest); err == nil {
			t.Fatalf("matchForgejoQualificationLog() accepted missing, altered, or duplicate marker: %q", logs)
		}
	}
}

func TestBinarySigningRejectsLiveCheckFailure(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	directory := filepath.Dir(fixture.rootPath)
	candidate := filepath.Join(directory, "candidate.json")
	writeFixtureFile(t, candidate, mustEncodeBinaryReceipt(t, testBinaryReceipt()), 0o600)
	binary := filepath.Join(directory, "retained-binary")
	writeFixtureFile(t, binary, []byte("static binary"), 0o600)
	output := filepath.Join(directory, "unqualified-signed.json")
	args := []string{
		"--candidate", candidate, "--binary", binary, "--qualification", fixture.qualificationPath,
		"--delegation", fixture.delegationPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--environment", "canary", "--out", output,
	}
	checkFailed := errors.New("run failed independently")
	err := signBinaryWithCheck(args,
		func(release.Qualification, string) error { return checkFailed },
		func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil })
	if !errors.Is(err, checkFailed) {
		t.Fatalf("signBinaryWithCheck() error = %v; want independent check failure", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unqualified receipt was created: %v", err)
	}
}

func TestSignedReceiptRejectsChangedQualificationBytes(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	changedPath := filepath.Join(filepath.Dir(fixture.rootPath), "changed-qualification.json")
	wire := testQualificationBytes()
	changed := strings.Replace(string(wire), `"run_id":4001`, `"run_id":4002`, 1)
	if changed == string(wire) {
		t.Fatal("test did not change qualification run ID")
	}
	writeFixtureFile(t, changedPath, []byte(changed), 0o600)
	binary := filepath.Join(filepath.Dir(fixture.rootPath), "retained-binary")
	writeFixtureFile(t, binary, []byte("static binary"), 0o600)
	err := verifyBinary([]string{
		"--receipt", fixture.receiptPath, "--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath, "--binary", binary,
		"--qualification", changedPath, "--environment", "canary",
	})
	if !errors.Is(err, release.ErrInvalidQualification) {
		t.Fatalf("verifyBinary() error = %v; want changed-manifest rejection", err)
	}
}

func TestVerifyBinaryAcceptsExactQualifiedArtifact(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	binary := filepath.Join(filepath.Dir(fixture.rootPath), "retained-binary")
	writeFixtureFile(t, binary, []byte("static binary"), 0o600)
	err := verifyBinaryWithInspect([]string{
		"--receipt", fixture.receiptPath, "--delegation", fixture.delegationPath,
		"--root-key", fixture.rootPath, "--binary", binary,
		"--qualification", fixture.qualificationPath, "--environment", "canary",
	}, func(string, string, string) (binaryReceipt, error) {
		observed := testBinaryReceipt()
		observed.QualificationSHA256 = ""
		return observed, nil
	})
	if err != nil {
		t.Fatalf("verifyBinaryWithInspect() rejected exact qualified artifact: %v", err)
	}
}

func TestImageSigningRequiresQualifiedBinaryAndLiveCheck(t *testing.T) {
	fixture := newSignedBinaryFixture(t, time.Hour)
	directory := filepath.Dir(fixture.rootPath)
	binary := filepath.Join(directory, "retained-binary")
	writeFixtureFile(t, binary, []byte("static binary"), 0o600)
	imageFile := filepath.Join(directory, "unqualified-image.qcow2")
	baseFile := filepath.Join(directory, "base-image.qcow2")
	kernelFile := filepath.Join(directory, "kernel")
	writeFixtureFile(t, imageFile, []byte("not a QCOW2 image"), 0o600)
	writeFixtureFile(t, baseFile, []byte("not a QCOW2 image"), 0o600)
	writeFixtureFile(t, kernelFile, []byte("kernel"), 0o600)
	candidatePath := filepath.Join(directory, "image-candidate.json")
	image := imageReceipt{
		Schema: imageSchema, SourceRevision: testRevision, GoVersion: defaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: testBinaryReceipt().SHA256,
		QualificationSHA256: testBinaryReceipt().QualificationSHA256,
		BaseImageOCID:       "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU",
		BaseImageSHA256: testBinaryReceipt().SHA256, KernelRelease: "6.1.0-test+1",
		KernelSHA256: testBinaryReceipt().SHA256, ImageFormat: "qcow2", ImageBytes: 1024,
		ImageSHA256:  testBinaryReceipt().SHA256,
		OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.CUSTOM", OCIRegion: "GRU",
	}
	writeImage := func() {
		t.Helper()
		wire, err := trust.EncodePayload(image)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, candidatePath, wire, 0o600)
	}
	writeImage()
	output := filepath.Join(directory, "image-signed.json")
	args := []string{
		"--candidate", candidatePath, "--binary-receipt", fixture.receiptPath,
		"--binary", binary, "--qualification", fixture.qualificationPath,
		"--image-file", imageFile, "--base-image-file", baseFile, "--kernel-file", kernelFile,
		"--delegation", fixture.delegationPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--environment", "canary", "--out", output,
	}
	inspect := func(string, string, string) (binaryReceipt, error) {
		observed := testBinaryReceipt()
		observed.QualificationSHA256 = ""
		return observed, nil
	}
	checkFailure := errors.New("required CI check failed")
	err := signImageWithCheck(args, func(release.Qualification, string) error { return checkFailure }, inspect)
	if !errors.Is(err, checkFailure) {
		t.Fatalf("signImageWithCheck() error = %v; want live check failure", err)
	}
	err = signImageWithCheck(args, func(release.Qualification, string) error { return nil }, inspect)
	if err == nil || !strings.Contains(err.Error(), "QCOW2") {
		t.Fatalf("signImageWithCheck() error = %v; want unverified image rejection", err)
	}
	image.QualificationSHA256 = strings.Repeat("e", 64)
	writeImage()
	err = signImageWithCheck(args, func(release.Qualification, string) error { return nil }, inspect)
	if err == nil || !strings.Contains(err.Error(), "exact qualified binary") {
		t.Fatalf("signImageWithCheck() error = %v; want qualification mismatch", err)
	}
	image.QualificationSHA256 = testBinaryReceipt().QualificationSHA256
	image.BinarySHA256 = strings.Repeat("b", 64)
	writeImage()
	err = signImageWithCheck(args, func(release.Qualification, string) error { return nil }, inspect)
	if err == nil || !strings.Contains(err.Error(), "exact qualified binary") {
		t.Fatalf("signImageWithCheck() error = %v; want binary mismatch", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unqualified image receipt was created: %v", err)
	}
}

func mustEncodeBinaryReceipt(t *testing.T, receipt binaryReceipt) []byte {
	t.Helper()
	wire, err := trust.EncodePayload(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
