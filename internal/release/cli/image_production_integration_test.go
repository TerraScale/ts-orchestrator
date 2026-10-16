package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestFinalImageProductionAdmissionBoundary(t *testing.T) {
	f := newApplyHTTPFixture(t)
	private, err := readDelegatedPrivateKey(f.leafPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	image := testDelegationImageReceipt(f.binary)
	image.SourceRevision = f.binary.SourceRevision
	disk := []byte(imageMagicQcow2 + "test-only final guest runtime bytes")
	sum := sha256.Sum256(disk)
	image.ImageSHA256, image.ImageBytes = hex.EncodeToString(sum[:]), int64(len(disk))
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.ImageScope(image, "production")
	keyID, _ := trust.KeyID(private.Public().(ed25519.PublicKey))
	public, _ := trust.EncodeDelegatedPublicKey(private.Public().(ed25519.PublicKey))
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: public,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}},
		now.Add(-time.Hour), now.Add(48*time.Hour), f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	expected := release.ImageExpectation{Environment: "production", LogicalRegion: image.OCIRegion,
		Architecture: image.Architecture, OCIImageOCID: image.OCIImageOCID}
	for _, failure := range []string{"", "binary proof reused", "changed disk", "wrong source", "wrong manifest", "wrong architecture", "wrong runtime", "wrong cell", "wrong role", "ordinary release signer", "missing proof", "expired", "future", "tampered evidence"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			imageFile := filepath.Join(directory, "final.qcow2")
			writeFixtureFile(t, imageFile, disk, 0o600)
			candidate := productionCandidate(f.binary, image.OCIRegion)
			candidate.ArtifactSHA256 = image.ImageSHA256
			record := writeProductionEvidence(t, directory, candidate)
			signer, issued, expires := f.rootPrivate, now.Add(-time.Minute), now.Add(time.Hour)
			switch failure {
			case "binary proof reused":
				record.Candidate.ArtifactSHA256 = image.BinarySHA256
			case "changed disk":
				writeFixtureFile(t, imageFile, append(append([]byte{}, disk...), 'x'), 0o600)
			case "wrong source":
				record.Candidate.SourceRevision = strings.Repeat("f", 40)
			case "wrong manifest":
				record.Candidate.QualificationSHA256 = strings.Repeat("f", 64)
			case "wrong architecture":
				record.Candidate.Architecture = "arm64"
			case "wrong runtime":
				record.Candidate.Runtime = "old-runtime"
			case "wrong cell":
				record.Candidate.Cell = "SFO"
			case "wrong role":
				record.Candidate.Role = "terrabase"
			case "ordinary release signer":
				signer = private
			case "expired":
				issued, expires = now.Add(-2*time.Hour), now.Add(-time.Hour)
			case "future":
				issued = now.Add(5 * time.Minute)
			case "tampered evidence":
				writeFixtureFile(t, filepath.Join(directory, "objects", record.Evidence[0].SHA256), []byte("changed"), 0o600)
			}
			writeProductionRecord(t, filepath.Join(directory, image.OCIRegion, image.Architecture, "production.json"), record, signer, issued, expires)
			if failure == "ordinary release signer" {
				writeQualificationDelegation(t, filepath.Join(directory, image.OCIRegion, image.Architecture, "delegation.json"), record.Candidate, private, f.rootPrivate, release.ImageDomain)
			}
			if failure == "missing proof" {
				if err := os.Remove(filepath.Join(directory, image.OCIRegion, image.Architecture, "production.json")); err != nil {
					t.Fatal(err)
				}
			}
			cliErr := Run(t.Context(), []string{"verify-image-production", "--image-file", imageFile,
				"--qualification", filepath.Join(f.releaseDir, "qualification.json"), "--root-key", f.rootPath,
				"--cell", image.OCIRegion, "--arch", image.Architecture, "--production-evidence-dir", directory}, io.Discard)
			if (cliErr != nil) != (failure != "") {
				t.Fatalf("pre-import image gate: %v", cliErr)
			}
			if failure == "tampered evidence" {
				return // Retained evidence hashing belongs to the producer boundary.
			}
			current := image
			if failure == "changed disk" {
				current.ImageSHA256, _, err = (command{ctx: t.Context()}).hashQcow2(imageFile)
				if err != nil {
					t.Fatal(err)
				}
			}
			if failure != "missing proof" {
				proof, err := readProductionProof(directory, image.OCIRegion, image.Architecture)
				if err != nil {
					t.Fatal(err)
				}
				current.Production = &proof
			}
			_, signErr := release.SignImageReceipt(current, "production", grant, f.roots, private, now, 24*time.Hour)
			payload, err := trust.EncodePayload(current)
			if err != nil {
				t.Fatal(err)
			}
			// A delegated image signer can bypass producer checks, so test the consumer separately.
			manual, err := trust.Sign(payload, scope, now, now.Add(24*time.Hour), private)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := trust.EncodeEnvelope(manual)
			if err != nil {
				t.Fatal(err)
			}
			verified, consumerErr := release.VerifyImageCurrent(wire, grantWire, f.roots, expected, now)
			if failure != "" {
				if !errors.Is(signErr, release.ErrProductionQualification) || !errors.Is(consumerErr, release.ErrProductionQualification) {
					t.Fatalf("image authority bypass: signing=%v consumer=%v", signErr, consumerErr)
				}
				return
			}
			if signErr != nil || consumerErr != nil || !verified.ExpiresAt().Equal(expires) {
				t.Fatalf("qualified image: signing=%v consumer=%v expiry=%s", signErr, consumerErr, verified.ExpiresAt())
			}
			receiptPath, grantPath := filepath.Join(directory, "image.json"), filepath.Join(directory, "image-delegation.json")
			writeFixtureFile(t, receiptPath, wire, 0o600)
			writeFixtureFile(t, grantPath, grantWire, 0o600)
			for _, pinnedOCID := range []string{image.OCIImageOCID, "ocid1.image.oc1.sa-saopaulo-1.WRONG"} {
				err := Run(t.Context(), []string{"verify-image-production", "--image-file", imageFile,
					"--qualification", filepath.Join(f.releaseDir, "qualification.json"), "--root-key", f.rootPath,
					"--cell", image.OCIRegion, "--arch", image.Architecture, "--production-evidence-dir", directory,
					"--image-receipt", receiptPath, "--delegation", grantPath, "--image-ocid", pinnedOCID}, io.Discard)
				if (err != nil) != (pinnedOCID != image.OCIImageOCID) {
					t.Fatalf("pre-launch exact image %s: %v", pinnedOCID, err)
				}
			}
			copy := verified.Receipt()
			copy.Production.Qualification[0] = 'x'
			if verified.Receipt().Production.Qualification[0] == 'x' {
				t.Fatal("returned image proof aliases verified authority")
			}
			if _, err := release.SignImageReceipt(current, "production", grant, f.roots, private, now, release.MaxReceiptLifetime+time.Second); err == nil {
				t.Fatal("image signer accepted oversized requested lifetime after clamping")
			}
		})
	}
}
