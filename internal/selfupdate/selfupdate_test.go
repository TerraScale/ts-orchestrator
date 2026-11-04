package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	testSource = "0123456789abcdef0123456789abcdef01234567"
	testUnit   = "terrascale-orchestrator-controller.service"
)

type fixture struct {
	t           *testing.T
	layout      Layout
	baked       string
	now         time.Time
	roots       trust.Keyring
	rootPrivate ed25519.PrivateKey
	leafPublic  ed25519.PublicKey
	leafPrivate ed25519.PrivateKey
	nodePublic  ed25519.PublicKey
	nodePrivate ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, layout: Layout{Root: filepath.Join(dir, "root"), Owner: os.Getuid()},
		baked: filepath.Join(dir, "baked-binary"), now: time.Now().UTC().Truncate(time.Second)}
	if err := os.WriteFile(f.baked, []byte("baked orchestrator"), 0o755); err != nil {
		t.Fatal(err)
	}
	var rootPublic ed25519.PublicKey
	var err error
	rootPublic, f.rootPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.leafPublic, f.leafPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.nodePublic, f.nodePrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.roots, err = trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func binaryReceipt(data []byte, qualification string) release.BinaryReceipt {
	machine := map[string]string{"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}[runtime.GOARCH]
	return release.BinaryReceipt{
		Schema: release.BinarySchema, SourceRevision: testSource, GoVersion: release.DefaultGoVersion,
		GOOS: "linux", GOARCH: runtime.GOARCH, ELFMachine: machine, Static: true,
		Bytes: int64(len(data)), SHA256: digestOf(data), QualificationSHA256: qualification,
	}
}

func (f *fixture) leafIdentity() (string, string) {
	keyID, err := trust.KeyID(f.leafPublic)
	if err != nil {
		f.t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(f.leafPublic)
	if err != nil {
		f.t.Fatal(err)
	}
	return keyID, encoded
}

// legacySigned returns a per-source receipt that runtime admission must refuse.
func (f *fixture) legacySigned(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leafIdentity()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.BinaryDomain, DeploymentID: entityid.Derive("build", testSource), Cell: "BUILD",
			Environment: "canary", Role: "artifact", Slots: []string{"linux-" + runtime.GOARCH}, Actions: []string{"sign"}}},
	}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err := release.SignBinaryReceipt(binaryReceipt(data, digestOf([]byte("q"))), "canary", delegation, f.roots,
		f.leafPrivate, f.now, 30*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.encode(receipt), f.encode(delegation)
}

type anyLineage struct{}

func (anyLineage) CheckLineage(string, string, string) error { return nil }

// signed returns a regional update receipt with independent root qualification.
func (f *fixture) signed(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leafIdentity()
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: "canary", Architectures: []string{runtime.GOARCH},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: strings.Repeat("9", 40),
	}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	digest := digestOf(data)
	qualification := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: testSource, SourceTree: testSource, GoVersion: release.DefaultGoVersion,
		GoModSHA256: digest, GoSumSHA256: digest,
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: 10, RunNumber: 5, Conclusion: "success"},
		Artifacts: []release.QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: int64(len(data)), SHA256: digest},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: int64(len(data)), SHA256: digest},
		},
	}
	qualificationDigest := digestOf([]byte("qualification"))
	receipt, err := release.SignBinaryUpdateReceipt(binaryReceipt(data, qualificationDigest), qualification, qualificationDigest,
		"GRU", "canary", anyLineage{}, delegation, f.roots, f.leafPrivate, f.now, 30*time.Minute)
	if err != nil {
		f.t.Fatal(err)
	}
	qualified := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: testSource, ArtifactSHA256: digest,
			QualificationSHA256: qualificationDigest, Cell: "GRU", Environment: "canary",
			Runtime: release.ProductionRuntime, Architecture: runtime.GOARCH, Role: "orchestrator"}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		evidence := []byte("test-only " + gate + " evidence")
		qualified.Evidence = append(qualified.Evidence, release.ProductionGateEvidence{Gate: gate,
			SHA256: digestOf(evidence), Bytes: int64(len(evidence)), CompletedAt: f.now.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(qualified)
	if err != nil {
		f.t.Fatal(err)
	}
	proof, err := trust.Sign(payload, release.ProductionQualificationScope(qualified.Candidate), f.now, f.now.Add(30*time.Minute), f.rootPrivate)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err = release.AttachProductionQualification(receipt, release.ProductionProof{Qualification: f.encode(proof)},
		f.encode(delegation), f.roots, f.leafPrivate,
		release.UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: runtime.GOARCH}, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.encode(receipt), f.encode(delegation)
}

func (f *fixture) encode(envelope trust.Envelope) []byte {
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		f.t.Fatal(err)
	}
	return wire
}

func (f *fixture) policy() ReceiptPolicy {
	return ReceiptPolicy{Roots: f.roots, Environment: "canary", Cell: "GRU", Architecture: runtime.GOARCH}
}

func (f *fixture) stage(data []byte) string {
	f.t.Helper()
	receipt, delegation := f.signed(data)
	digest, err := Stage(f.layout, bytes.NewReader(data), receipt, delegation, f.policy(), f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return digest
}

func (f *fixture) proof(activation Activation, at time.Time) ProofCheck {
	f.t.Helper()
	wire, err := SignVersionProof(VersionProof{Schema: ProofSchema, ActivationID: activation.ActivationID, Unit: activation.Unit,
		BinarySHA256: activation.Target, ProcessID: int64(os.Getpid()), ObservedAt: at}, f.nodePrivate, at)
	if err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(f.t.TempDir(), "proof.json")
	if err := os.WriteFile(path, wire, 0o644); err != nil {
		f.t.Fatal(err)
	}
	return ProofCheck{File: path, PublicKey: f.nodePublic}
}

func TestSeedStageActivateConfirm(t *testing.T) {
	f := newFixture(t)
	outcome, err := Prepare(f.layout, testUnit, f.baked, ProofCheck{}, f.now)
	if err != nil || outcome != OutcomeIdle {
		t.Fatalf("prepare = %s %v", outcome, err)
	}
	baked, err := f.layout.Current()
	if err != nil || baked != digestOf([]byte("baked orchestrator")) {
		t.Fatalf("seeded current = %q %v", baked, err)
	}
	// The unprivileged controller must traverse to its binary even when the
	// installing unit runs with UMask=0077.
	for _, path := range []string{f.layout.Root, f.layout.releasesPath(), f.layout.ReleaseDir(baked)} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %v %v", path, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.layout.ReleaseDir(baked), bakedMarkerFile)); err != nil {
		t.Fatalf("baked release lacks its marker: %v", err)
	}
	data := []byte("new orchestrator build")
	target := f.stage(data)
	if again := f.stage(data); again != target {
		t.Fatal("staging is not idempotent")
	}
	if info, err := os.Stat(f.layout.BinaryPath(target)); err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("staged binary mode = %v %v", info, err)
	}
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if current, _ := f.layout.Current(); current != target || activation.Previous != baked {
		t.Fatalf("current = %s previous = %s", current, activation.Previous)
	}
	link, err := os.Readlink(filepath.Join(f.layout.Root, "current"))
	if err != nil || link != "releases/"+target {
		t.Fatalf("current link = %q %v", link, err)
	}
	if _, err := Activate(f.layout, baked, testUnit, f.now, time.Minute); err == nil {
		t.Fatal("second activation accepted while one is pending")
	}
	if again, err := Activate(f.layout, target, testUnit, f.now, time.Minute); err != nil || again.ActivationID != activation.ActivationID {
		t.Fatalf("repeated activation is not idempotent: %v", err)
	}
	if outcome, _, err := Watch(f.layout, testUnit, ProofCheck{PublicKey: f.nodePublic}, f.now.Add(time.Second)); err != nil || outcome != OutcomePending {
		t.Fatalf("watch without proof = %s %v", outcome, err)
	}
	outcome, _, err = Watch(f.layout, testUnit, f.proof(activation, f.now.Add(2*time.Second)), f.now.Add(3*time.Second))
	if err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("watch with proof = %s %v", outcome, err)
	}
	if _, pending, _ := f.layout.Pending(); pending {
		t.Fatal("confirmed activation is still pending")
	}
	if current, _ := f.layout.Current(); current != target {
		t.Fatal("confirmation moved the current link")
	}
}

func TestMissedProofDeadlineRollsBackAndMarksKnownBad(t *testing.T) {
	f := newFixture(t)
	baked, err := Seed(f.layout, f.baked)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("bad build")
	target := f.stage(data)
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// A proof for another activation, a stale proof and a proof from another
	// key never confirm.
	other := activation
	other.ActivationID = "0000000000NY47MDQEXMPZDJR7"
	stale := f.proof(activation, f.now.Add(-time.Hour))
	forged := f.proof(activation, f.now.Add(time.Second))
	forged.PublicKey = f.leafPublic
	for name, check := range map[string]ProofCheck{"other activation": f.proof(other, f.now.Add(time.Second)), "stale": stale, "forged": forged} {
		if outcome, _, err := Watch(f.layout, testUnit, check, f.now.Add(2*time.Second)); err != nil || outcome != OutcomePending {
			t.Fatalf("%s proof = %s %v", name, outcome, err)
		}
	}
	outcome, err := Prepare(f.layout, testUnit, f.baked, ProofCheck{}, activation.Deadline)
	if err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("deadline = %s %v", outcome, err)
	}
	if current, _ := f.layout.Current(); current != baked {
		t.Fatalf("current after rollback = %s, want %s", current, baked)
	}
	known, err := f.layout.KnownBad()
	if err != nil || !known[target] {
		t.Fatalf("known bad = %v %v", known, err)
	}
	receipt, delegation := f.signed(data)
	if _, err := Stage(f.layout, bytes.NewReader(data), receipt, delegation, f.policy(), f.now); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad release restaged: %v", err)
	}
	if _, err := Activate(f.layout, target, testUnit, f.now, time.Minute); !errors.Is(err, ErrKnownBad) {
		t.Fatalf("known-bad release reactivated: %v", err)
	}
}

func TestStageRejectsMismatchedBytesAndUnauthorizedReceipts(t *testing.T) {
	f := newFixture(t)
	data := []byte("signed bytes")
	legacy, legacyDelegation := f.legacySigned(data)
	if _, err := Stage(f.layout, bytes.NewReader(data), legacy, legacyDelegation, f.policy(), f.now); !errors.Is(err, release.ErrProductionQualification) {
		t.Fatalf("per-source receipt staged: %v", err)
	}
	if _, err := os.Stat(f.layout.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("per-source rejection created the release root: %v", err)
	}
	receipt, delegation := f.signed(data)
	if _, err := Stage(f.layout, bytes.NewReader([]byte("other bytes!")), receipt, delegation, f.policy(), f.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched bytes staged: %v", err)
	}
	if _, err := Stage(f.layout, bytes.NewReader(append(data, 'x')), receipt, delegation, f.policy(), f.now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized bytes staged: %v", err)
	}
	if entries, _ := os.ReadDir(f.layout.releasesPath()); len(entries) != 0 {
		t.Fatalf("rejected stage left %d entries", len(entries))
	}
	production := f.policy()
	production.Environment = "production"
	if _, err := Stage(f.layout, bytes.NewReader(data), receipt, delegation, production, f.now); err == nil {
		t.Fatal("canary receipt staged in production")
	}
	if _, err := Stage(f.layout, bytes.NewReader(data), receipt, delegation, f.policy(), f.now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired receipt staged")
	}

	auto, autoDelegation := f.signed(data)
	if digest, err := Stage(f.layout, bytes.NewReader(data), auto, autoDelegation, f.policy(), f.now); err != nil || digest != digestOf(data) {
		t.Fatalf("scoped automatic receipt: %s %v", digest, err)
	}
	otherCell := f.policy()
	otherCell.Cell = "FRA"
	if _, err := Stage(f.layout, bytes.NewReader(data), auto, autoDelegation, otherCell, f.now); err == nil {
		t.Fatal("auto-signed receipt accepted outside its cell")
	}
}
