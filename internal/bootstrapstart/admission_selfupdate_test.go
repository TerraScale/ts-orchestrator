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
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
			release.UpdateExpectation{Environment: "production", Cell: "SJC", Architecture: "amd64"}, release.ErrExpectationMismatch},
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
	policy := selfupdate.ReceiptPolicy{Roots: roots, Environment: expected.Environment, Cell: expected.Cell, Architecture: expected.Architecture}
	if _, err := selfupdate.Stage(perSource.layout, bytes.NewReader(unsigned), receipt, delegation, policy, stagedAt); !errors.Is(err, release.ErrProductionQualification) {
		t.Fatalf("per-source successor staged without regional qualification: %v", err)
	}
	if current, err := perSource.layout.Current(); err != nil || current != digest(elfFixture("baked orchestrator")) {
		t.Fatalf("rejected per-source successor changed current: %s, %v", current, err)
	}
	if _, err := os.Stat(perSource.layout.ReleaseDir(digest(unsigned))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected per-source successor left release files: %v", err)
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

func TestAcceptedBinaryUsesExactSharedFileMeasurement(t *testing.T) {
	wire := elfFixture("accepted binary")
	path := filepath.Join(t.TempDir(), "orchestrator")
	if err := os.WriteFile(path, wire, 0o555); err != nil {
		t.Fatal(err)
	}
	pin := identityrekey.BinaryPin{SHA256: digest(wire), Size: int64(len(wire)), Architecture: "amd64"}
	got, err := verifyAcceptedBinaryFile(path, pin)
	if err != nil || got.SHA256 != pin.SHA256 || got.Bytes != pin.Size || got.Architecture != pin.Architecture {
		t.Fatalf("accepted file measurement = %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*identityrekey.BinaryPin){
		"zero pin":     func(p *identityrekey.BinaryPin) { *p = identityrekey.BinaryPin{} },
		"hash":         func(p *identityrekey.BinaryPin) { p.SHA256 = digest([]byte("another executable")) },
		"size":         func(p *identityrekey.BinaryPin) { p.Size++ },
		"architecture": func(p *identityrekey.BinaryPin) { p.Architecture = "arm64" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pin
			mutate(&changed)
			if _, err := verifyAcceptedBinaryFile(path, changed); !errors.Is(err, ErrRunningBinaryMismatch) {
				t.Fatalf("invalid pin admitted: %v", err)
			}
		})
	}
}

func TestCompletionRecoveryVerifiesTheRunningSignedPredecessorOnly(t *testing.T) {
	fixture := newAdmissionFlowFixture(t)
	if _, err := fixture.gate.AdmitInitial(t.Context()); err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := newSelfUpdateFixture(t, fixture.gate.Roots, fixture.rootPrivate, fixture.bakedBinary, *fixture.now)
	predecessor := elfFixture("confirmed successor predecessor")
	receipt, delegation := f.updateReceipt(predecessor, accepted.Environment, accepted.Cell)
	previous := f.activate(predecessor, receipt, delegation)
	// Commit the same native known-good link that confirmation publishes.
	if err := os.Symlink("releases/"+previous, filepath.Join(f.layout.Root, "known-good")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.layout.Root, "activation.json")); err != nil {
		t.Fatal(err)
	}
	targetBytes := elfFixture("damaged pending target")
	receipt, delegation = f.updateReceipt(targetBytes, accepted.Environment, accepted.Cell)
	target := f.activate(targetBytes, receipt, delegation)
	path := f.layout.BinaryPath(previous)
	if _, err := verifyRecoveryPredecessor(path, f.layout, f.roots, accepted); err != nil {
		t.Fatalf("recorded predecessor cannot run read-only completion for an incompatible decoder: %v", err)
	}
	if _, err := verifySelfUpdatedBinary(path, f.layout, f.roots, release.UpdateExpectation{Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture}); err == nil {
		t.Fatal("ordinary restart admitted noncurrent predecessor")
	}
	if err := os.WriteFile(filepath.Join(f.layout.Root, "known-bad.json"), []byte(`{"digests":["`+target+`"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecoveryPredecessor(path, f.layout, f.roots, accepted); err != nil {
		t.Fatalf("intact rejected target prevented predecessor recovery: %v", err)
	}
	if err := os.Remove(filepath.Join(f.layout.Root, "known-bad.json")); err != nil {
		t.Fatal(err)
	}

	for _, damage := range []string{"receipt", "delegation", "unreadable", "restore", "restore moved", "unsafe activation", "missing rollback pins"} {
		t.Run(damage, func(t *testing.T) {
			activationFile := filepath.Join(f.layout.Root, "activation.json")
			original, err := os.ReadFile(activationFile)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "receipt":
				if err := os.Remove(filepath.Join(f.layout.ReleaseDir(target), "receipt.json")); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(filepath.Join(f.layout.ReleaseDir(target), "receipt.json"), receipt, 0o444); err != nil {
						t.Fatal(err)
					}
				})
			case "delegation":
				f.replace(target, "delegation.json", []byte(`{}`), 0o444)
				t.Cleanup(func() { f.replace(target, "delegation.json", delegation, 0o444) })
			case "unreadable":
				if err := os.WriteFile(activationFile, bytes.Replace(original, []byte(`"schema"`), []byte(`"unexpected":true,"schema"`), 1), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(activationFile, original, 0o644); err != nil {
						t.Fatal(err)
					}
				})
			case "restore", "restore moved":
				if err := os.Remove(activationFile); err != nil {
					t.Fatal(err)
				}
				if damage == "restore moved" {
					if err := os.Remove(filepath.Join(f.layout.Root, "current")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("releases/"+previous, filepath.Join(f.layout.Root, "current")); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Remove(filepath.Join(f.layout.Root, "current")); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("releases/"+target, filepath.Join(f.layout.Root, "current")); err != nil {
							t.Fatal(err)
						}
					})
				}
				intentPath := filepath.Join(f.layout.Root, "restore-"+selfupdate.ControllerUnit+".json")
				intent, err := protocol.EncodeJSON(selfupdate.RestoreIntent{Schema: "terrascale.orchestrator.restore-intent.v1", Unit: selfupdate.ControllerUnit, Target: previous, Rejected: target})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(intentPath, intent, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.layout.Root, "known-bad.json"), []byte(`{"digests":["`+target+`"]}`), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Remove(intentPath); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(filepath.Join(f.layout.Root, "known-bad.json")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(activationFile, original, 0o644); err != nil {
						t.Fatal(err)
					}
				})
			case "unsafe activation":
				if err := os.Chmod(activationFile, 0o666); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(activationFile, 0o644); err != nil {
						t.Fatal(err)
					}
				})
			case "missing rollback pins":
				if err := os.WriteFile(activationFile, []byte(`{"target":"`+target+`"}`), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(activationFile, original, 0o644); err != nil {
						t.Fatal(err)
					}
				})
			}
			_, err = verifyRecoveryPredecessor(path, f.layout, f.roots, accepted)
			refusal := damage == "unsafe activation" || damage == "missing rollback pins"
			if (err != nil) != refusal {
				t.Fatalf("recovery predecessor: %v, refusal=%v", err, refusal)
			}
			expectedCurrent := target
			if damage == "restore moved" {
				expectedCurrent = previous
			}
			if current, err := f.layout.Current(); err != nil || current != expectedCurrent {
				t.Fatal("read-only admission changed current")
			}
		})
	}
	f.replace(target, selfupdate.BinaryName, elfFixture("corrupt bytes"), 0o555)
	if _, err := verifySelfUpdatedBinary(path, f.layout, f.roots, release.UpdateExpectation{Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture}); err == nil {
		t.Fatal("ordinary restart admitted rollback predecessor")
	}
	measured, err := verifyRecoveryPredecessor(path, f.layout, f.roots, accepted)
	if err != nil || measured.SHA256 != previous {
		t.Fatalf("trusted predecessor = %+v, %v", measured, err)
	}
	for _, fault := range []string{"wrong executable", "wrong environment", "wrong cell", "wrong root", "known bad", "bad predecessor"} {
		t.Run(fault, func(t *testing.T) {
			record, roots, running := accepted.Clone(), f.roots, path
			switch fault {
			case "wrong executable":
				running = fixture.bakedBinary
			case "wrong environment":
				record.Environment = "canary"
			case "wrong cell":
				record.Cell = "SJC"
			case "wrong root":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				roots, err = trust.ParseKeyring(public)
				if err != nil {
					t.Fatal(err)
				}
			case "known bad":
				if err := os.WriteFile(filepath.Join(f.layout.Root, "known-bad.json"), []byte(`{"digests":["`+previous+`"]}`), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(filepath.Join(f.layout.Root, "known-bad.json")) })
			case "bad predecessor":
				f.replace(previous, selfupdate.BinaryName, elfFixture("corrupt predecessor"), 0o555)
			}
			if _, err := verifyRecoveryPredecessor(running, f.layout, roots, record); err == nil {
				t.Fatal("untrusted recovery predecessor admitted")
			}
		})
	}
}
