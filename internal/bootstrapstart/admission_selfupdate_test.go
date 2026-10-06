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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
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

func (checker fileBinaryChecker) VerifyHistorical(image release.HistoricalImage) (RunningBinary, error) {
	return verifyBinaryFile(checker.path, image.Receipt())
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
		Environment: environment, Cells: []string{cell}, Architectures: []string{"amd64"},
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
	return envelopeWire(f.t, receipt), envelopeWire(f.t, delegation)
}

// perSourceReceipt signs a per-source binary receipt, which is not a
// binary-update receipt.
func (f *selfUpdateFixture) perSourceReceipt(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leaf()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.BinaryDomain, DeploymentID: strings.Repeat("1", 40),
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
	policy := selfupdate.ReceiptPolicy{Roots: f.roots, Environment: "production", Cell: "GRU", Architecture: "amd64",
		AllowScopedAutoSign: true}
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

func TestSelfUpdatedBinaryNeedsRootVerifiedUpdateReceipt(t *testing.T) {
	// Staged two hours ago under a receipt and delegation that have since
	// expired: a staged release keeps restarting.
	stagedAt := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	baked := filepath.Join(t.TempDir(), "terrascale-orchestrator")
	if err := os.WriteFile(baked, elfFixture("baked orchestrator"), 0o555); err != nil {
		t.Fatal(err)
	}
	f := newSelfUpdateFixture(t, roots, rootPrivate, baked, stagedAt)
	expected := release.UpdateExpectation{Environment: "production", Cell: "GRU", Architecture: "amd64"}
	running := f.layout.CurrentExecutable()
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); !errors.Is(err, ErrRunningBinaryMismatch) ||
		!errors.Is(err, os.ErrNotExist) {
		t.Fatalf("baked release without an update receipt = %v, want missing receipt", err)
	}
	updated := elfFixture("release B")
	receipt, delegation := f.updateReceipt(updated, "production", "GRU")
	digestB := f.activate(updated, receipt, delegation)
	if _, err := release.VerifyBinaryUpdateCurrent(receipt, delegation, roots, expected, time.Now()); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("fixture receipt is still current: %v", err)
	}
	measured, err := verifySelfUpdatedBinary(running, f.layout, roots, expected)
	if err != nil || measured.SHA256 != digestB || measured.Architecture != "amd64" {
		t.Fatalf("self-updated release B = %+v, %v", measured, err)
	}

	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoots, err := trust.ParseKeyring(otherPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		path     string
		roots    trust.Keyring
		expected release.UpdateExpectation
		cause    error
	}{
		{"other environment", running, roots,
			release.UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"}, trust.ErrScopeMismatch},
		{"other cell", running, roots,
			release.UpdateExpectation{Environment: "production", Cell: "SFO", Architecture: "amd64"}, release.ErrExpectationMismatch},
		{"other architecture", running, roots,
			release.UpdateExpectation{Environment: "production", Cell: "GRU", Architecture: "arm64"}, release.ErrExpectationMismatch},
		{"other root", running, otherRoots, expected, trust.ErrUntrustedKey},
		{"executable is not the current release", baked, roots, expected, ErrRunningBinaryMismatch},
	} {
		if _, err := verifySelfUpdatedBinary(tc.path, f.layout, tc.roots, tc.expected); !errors.Is(err, ErrRunningBinaryMismatch) ||
			!errors.Is(err, tc.cause) {
			t.Errorf("%s = %v, want %v", tc.name, err, tc.cause)
		}
	}

	knownBad := filepath.Join(f.layout.Root, "known-bad.json")
	if err := os.WriteFile(knownBad, []byte(`{"digests":["`+digestB+`"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); !errors.Is(err, selfupdate.ErrKnownBad) {
		t.Fatalf("known-bad release = %v, want known bad", err)
	}
	if err := os.Remove(knownBad); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.layout.ReleaseDir(digestB), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); !errors.Is(err, selfupdate.ErrUnsafe) {
		t.Fatalf("group-writable release = %v, want unsafe", err)
	}
	if err := os.Chmod(f.layout.ReleaseDir(digestB), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); err != nil {
		t.Fatalf("restored release = %v", err)
	}
	forger := &selfUpdateFixture{t: t, layout: f.layout, roots: otherRoots, rootPrivate: otherPrivate,
		leafPrivate: f.leafPrivate, now: stagedAt}
	forged, forgedDelegation := forger.updateReceipt(updated, "production", "GRU")
	f.replace(digestB, "receipt.json", forged, 0o444)
	f.replace(digestB, "delegation.json", forgedDelegation, 0o444)
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("receipt from another root = %v, want untrusted key", err)
	}
	f.replace(digestB, "receipt.json", receipt, 0o444)
	f.replace(digestB, "delegation.json", delegation, 0o444)
	f.replace(digestB, selfupdate.BinaryName, elfFixture("release B, tampered"), 0o555)
	if _, err := verifySelfUpdatedBinary(running, f.layout, roots, expected); !errors.Is(err, selfupdate.ErrUnsafe) {
		t.Fatalf("tampered release bytes = %v, want unsafe", err)
	}

	perSource := newSelfUpdateFixture(t, roots, rootPrivate, baked, stagedAt)
	unsigned := elfFixture("release C")
	receipt, delegation = perSource.perSourceReceipt(unsigned)
	perSource.activate(unsigned, receipt, delegation)
	if _, err := verifySelfUpdatedBinary(perSource.layout.CurrentExecutable(), perSource.layout, roots,
		expected); !errors.Is(err, trust.ErrScopeMismatch) {
		t.Fatalf("release without a binary-update receipt = %v, want scope mismatch", err)
	}
}

// TestRestartAdmissionAcceptsSelfUpdatedReleaseAndFallsBackToBaked follows
// the controller unit: the restarted process runs current/terrascale-orchestrator.
func TestRestartAdmissionAcceptsSelfUpdatedReleaseAndFallsBackToBaked(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	fixture.gate.Binary = fileBinaryChecker{path: fixture.bakedBinary}
	marker, err := fixture.gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if marker.BinarySHA256 != digest(elfFixture("baked orchestrator")) {
		t.Fatalf("marker binary = %s, want the image receipt binary", marker.BinarySHA256)
	}
	manifestWire := fixture.ledger.state.ManifestRecord.Bytes
	now := *fixture.now
	admit := func(gate Gate) error {
		if _, err := gate.AdmitRestart(t.Context()); err != nil {
			return err
		}
		_, err := gate.AdmitRestartLocal(t.Context(), manifestWire)
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
	// version proof; the watchdog then restores the baked release, which
	// the image receipt admits again.
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

	// A release staged without a binary-update receipt is refused the same
	// way and rolled back at its proof deadline.
	unsigned := newSelfUpdateFixture(t, fixture.gate.Roots, fixture.rootPrivate, fixture.bakedBinary, now)
	gate.SelfUpdate = unsigned.layout
	gate.Binary = fileBinaryChecker{path: unsigned.layout.CurrentExecutable()}
	other := elfFixture("release C")
	receipt, delegation = unsigned.perSourceReceipt(other)
	unsigned.activate(other, receipt, delegation)
	if err := admit(gate); !errors.Is(err, ErrAdmission) {
		t.Fatalf("restart on release C without a binary-update receipt = %v, want admission failure", err)
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
