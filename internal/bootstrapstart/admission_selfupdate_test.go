package bootstrapstart

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const selfUpdateUnit = "terrascale-orchestrator-controller.service"

// elfFixture is a minimal amd64 ELF64 header followed by tag, so distinct
// tags are distinct executables that the running-binary check accepts.
func elfFixture(tag string) []byte {
	header := make([]byte, 64)
	copy(header, elf.ELFMAG)
	header[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	header[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	header[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.LittleEndian.PutUint16(header[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(header[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(header[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(header[52:], 64)
	return append(header, tag...)
}

// fileBinaryChecker measures path in place of /proc/self/exe.
type fileBinaryChecker struct{ path string }

func (checker fileBinaryChecker) VerifyCurrent(image release.VerifiedImage) (RunningBinary, error) {
	return verifyBinaryFile(checker.path, image.Receipt())
}

func (checker fileBinaryChecker) VerifyAccepted(pin identityrekey.BinaryPin) (RunningBinary, error) {
	return verifyAcceptedBinaryFile(checker.path, pin)
}

func (checker fileBinaryChecker) VerifySelfUpdated(layout selfupdate.Layout, roots trust.Keyring,
	expected release.UpdateExpectation,
) (RunningBinary, error) {
	return verifySelfUpdatedBinary(checker.path, layout, roots, expected)
}

type acceptedLineage struct{}

func (acceptedLineage) CheckLineage(string, string, string) error { return nil }

// selfUpdateFixture is a node's self-update release root seeded with the
// image-baked binary, and a leaf key the offline root delegates to.
type selfUpdateFixture struct {
	t           *testing.T
	layout      selfupdate.Layout
	roots       trust.Keyring
	rootPrivate ed25519.PrivateKey
	leafPrivate ed25519.PrivateKey
	now         time.Time
}

func newSelfUpdateFixture(t *testing.T, roots trust.Keyring, rootPrivate ed25519.PrivateKey, bakedBinary string,
	now time.Time,
) *selfUpdateFixture {
	t.Helper()
	layout := selfupdate.Layout{Root: filepath.Join(t.TempDir(), "release-root"), Owner: os.Getuid()}
	if _, err := selfupdate.Seed(layout, bakedBinary); err != nil {
		t.Fatal(err)
	}
	_, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &selfUpdateFixture{t: t, layout: layout, roots: roots, rootPrivate: rootPrivate,
		leafPrivate: leafPrivate, now: now}
}

func (f *selfUpdateFixture) leaf() (string, string) {
	f.t.Helper()
	public := f.leafPrivate.Public().(ed25519.PublicKey)
	keyID, err := trust.KeyID(public)
	if err != nil {
		f.t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		f.t.Fatal(err)
	}
	return keyID, encoded
}

func binaryReceiptFor(data []byte, qualification string) release.BinaryReceipt {
	return release.BinaryReceipt{
		Schema: release.BinarySchema, SourceRevision: strings.Repeat("1", 40), GoVersion: release.DefaultGoVersion,
		GOOS: "linux", GOARCH: "amd64", ELFMachine: "Advanced Micro Devices X86-64", Static: true,
		Bytes: int64(len(data)), SHA256: digest(data), QualificationSHA256: qualification,
	}
}

// updateReceipt signs a binary-update receipt for data under a root
// delegation scoped to environment and cell.
func (f *selfUpdateFixture) updateReceipt(data []byte, environment, cell string) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leaf()
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: environment, Architectures: []string{"amd64"},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: strings.Repeat("9", 40),
	}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	sum := digest(data)
	qualification := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: strings.Repeat("1", 40), SourceTree: strings.Repeat("1", 40), GoVersion: release.DefaultGoVersion,
		GoModSHA256: sum, GoSumSHA256: sum,
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: 10, RunNumber: 5, Conclusion: "success"},
		Artifacts: []release.QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: int64(len(data)), SHA256: sum},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: int64(len(data)), SHA256: sum},
		},
	}
	qualificationDigest := digest([]byte("qualification"))
	receipt, err := release.SignBinaryUpdateReceipt(binaryReceiptFor(data, qualificationDigest), qualification,
		qualificationDigest, cell, environment, acceptedLineage{}, delegation, f.roots, f.leafPrivate, f.now, 30*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	qualified := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: strings.Repeat("1", 40), ArtifactSHA256: sum,
			QualificationSHA256: qualificationDigest, Cell: cell, Environment: environment,
			Runtime: release.ProductionRuntime, Architecture: "amd64", Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " evidence")
		qualified.Evidence = append(qualified.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digest(evidence), Bytes: int64(len(evidence)), CompletedAt: f.now.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(qualified)
	if err != nil {
		f.t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(qualified.Candidate), f.now, f.now.Add(30*time.Minute), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err = release.AttachProductionQualification(receipt, release.ProductionProof{Qualification: envelopeWire(f.t, proof)},
		envelopeWire(f.t, delegation), f.roots, f.leafPrivate,
		release.UpdateExpectation{Environment: environment, Cell: cell, Architecture: "amd64"}, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return envelopeWire(f.t, receipt), envelopeWire(f.t, delegation)
}

// perSourceReceipt signs a per-source binary receipt, which is not a
// binary-update receipt.
func (f *selfUpdateFixture) perSourceReceipt(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leaf()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.BinaryDomain, DeploymentID: entityid.Derive("build", strings.Repeat("1", 40)),
			Cell: "BUILD", Environment: "production", Role: "artifact", Slots: []string{"linux-amd64"},
			Actions: []string{"sign"}}},
	}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err := release.SignBinaryReceipt(binaryReceiptFor(data, digest([]byte("q"))), "production", delegation,
		f.roots, f.leafPrivate, f.now, 30*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	return envelopeWire(f.t, receipt), envelopeWire(f.t, delegation)
}

// activate stages data the way a rollout does and makes it current.
func (f *selfUpdateFixture) activate(data, receipt, delegation []byte) string {
	f.t.Helper()
	policy := selfupdate.ReceiptPolicy{Roots: f.roots, Environment: "production", Cell: "GRU", Architecture: "amd64"}
	release, err := selfupdate.Stage(f.layout, bytes.NewReader(data), receipt, delegation, policy, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := selfupdate.Activate(f.layout, release, selfUpdateUnit, f.now, selfupdate.MinProofWindow); err != nil {
		f.t.Fatal(err)
	}
	return release
}

// replace rewrites one root-owned, read-only file of release, as a local
// attacker with write access to the release root would.
func (f *selfUpdateFixture) replace(release, name string, data []byte, mode os.FileMode) {
	f.t.Helper()
	path := filepath.Join(f.layout.ReleaseDir(release), name)
	if err := os.Remove(path); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		f.t.Fatal(err)
	}
}

func TestRestartAdmissionAcceptsSelfUpdatedReleaseAndAcceptedBaseline(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.gate.Binary = fileBinaryChecker{path: fixture.bakedBinary}
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if marker.BinarySHA256 != digest(elfFixture("baked orchestrator")) {
		t.Fatalf("marker binary = %s, want the image receipt binary", marker.BinarySHA256)
	}
	now := *fixture.now
	admit := func(gate Gate) error {
		if _, err := gate.AdmitRestart(t.Context()); err != nil {
			return err
		}
		_, err := gate.AdmitRestartLocal(t.Context())
		return err
	}

	f := newSelfUpdateFixture(t, fixture.gate.Roots, fixture.rootPrivate, fixture.bakedBinary, now)
	gate := fixture.gate
	gate.SelfUpdate = f.layout
	gate.Binary = fileBinaryChecker{path: f.layout.CurrentExecutable()}
	if err := admit(gate); err != nil {
		t.Fatalf("restart on the seeded baked release: %v", err)
	}
	updated := elfFixture("release B")
	receipt, delegation := f.updateReceipt(updated, "production", "GRU")
	f.activate(updated, receipt, delegation)
	if err := admit(gate); err != nil {
		t.Fatalf("restart on self-updated release B: %v", err)
	}
	pinned := gate
	pinned.SelfUpdate = selfupdate.Layout{}
	if _, err := pinned.AdmitRestart(t.Context()); !errors.Is(err, ErrAdmission) {
		t.Fatalf("release B without a self-update root = %v, want admission failure", err)
	}

	// A tampered release fails restart admission, so it never signs a
	// version proof; the watchdog restores the accepted binary baseline.
	f.replace(digest(updated), selfupdate.BinaryName, elfFixture("release B, tampered"), 0o555)
	if err := admit(gate); !errors.Is(err, ErrAdmission) {
		t.Fatalf("restart on tampered release B = %v, want admission failure", err)
	}
	baked := gate
	baked.Binary = fileBinaryChecker{path: fixture.bakedBinary}
	if err := admit(baked); err != nil {
		t.Fatalf("image-installed binary beside a tampered self-update root: %v", err)
	}
	outcome, _, err := selfupdate.Watch(f.layout, selfUpdateUnit, selfupdate.ProofCheck{}, now)
	if err != nil || outcome != selfupdate.OutcomeRolledBack {
		t.Fatalf("watchdog on tampered release = %s, %v", outcome, err)
	}
	if err := admit(gate); err != nil {
		t.Fatalf("restart after rollback to the baked release: %v", err)
	}

	// A second region-qualified successor also restarts and rolls back at its proof deadline.
	unsigned := newSelfUpdateFixture(t, fixture.gate.Roots, fixture.rootPrivate, fixture.bakedBinary, now)
	gate.SelfUpdate = unsigned.layout
	gate.Binary = fileBinaryChecker{path: unsigned.layout.CurrentExecutable()}
	other := elfFixture("release C")
	receipt, delegation = unsigned.updateReceipt(other, "production", "GRU")
	unsigned.activate(other, receipt, delegation)
	if err := admit(gate); err != nil {
		t.Fatalf("restart on region-qualified release C: %v", err)
	}
	outcome, _, err = selfupdate.Watch(unsigned.layout, selfUpdateUnit, selfupdate.ProofCheck{},
		now.Add(selfupdate.MinProofWindow))
	if err != nil || outcome != selfupdate.OutcomeRolledBack {
		t.Fatalf("watchdog at the proof deadline = %s, %v", outcome, err)
	}
	if err := admit(gate); err != nil {
		t.Fatalf("restart after rollback to the baked release: %v", err)
	}
}
