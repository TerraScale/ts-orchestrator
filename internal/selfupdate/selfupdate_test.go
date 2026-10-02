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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
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

// signed returns a per-source receipt and its root delegation.
func (f *fixture) signed(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leafIdentity()
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: release.BinaryDomain, DeploymentID: testSource, Cell: "BUILD",
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

// autoSigned returns an update receipt signed under a scoped delegation.
func (f *fixture) autoSigned(data []byte) ([]byte, []byte) {
	f.t.Helper()
	keyID, encoded := f.leafIdentity()
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: "canary", Cells: []string{"GRU"}, Architectures: []string{runtime.GOARCH},
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
		BinarySHA256: activation.Target, ProcessID: 42, ObservedAt: at}, f.nodePrivate, at)
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
	other.ActivationID = strings.Repeat("0", 32)
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

func TestTamperedTargetRollsBackImmediately(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	target := f.stage([]byte("build to tamper"))
	activation, err := Activate(f.layout, target, testUnit, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	path := f.layout.BinaryPath(target)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("swapped"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o555); err != nil {
		t.Fatal(err)
	}
	outcome, _, err := Watch(f.layout, testUnit, f.proof(activation, f.now.Add(time.Second)), f.now.Add(time.Second))
	if err != nil || outcome != OutcomeRolledBack {
		t.Fatalf("tampered target = %s %v", outcome, err)
	}
	// With no pending activation a tampered current release blocks the start.
	if err := os.Chmod(f.layout.BinaryPath(activation.Previous), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(f.layout, testUnit, f.baked, ProofCheck{}, f.now); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("group-writable current release started: %v", err)
	}
}

func TestStageRejectsMismatchedBytesAndUnauthorizedReceipts(t *testing.T) {
	f := newFixture(t)
	data := []byte("signed bytes")
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

	auto, autoDelegation := f.autoSigned(data)
	if _, err := Stage(f.layout, bytes.NewReader(data), auto, autoDelegation, f.policy(), f.now); err == nil ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("auto-signed receipt staged with the flag off: %v", err)
	}
	enabled := f.policy()
	enabled.AllowScopedAutoSign = true
	if digest, err := Stage(f.layout, bytes.NewReader(data), auto, autoDelegation, enabled, f.now); err != nil || digest != digestOf(data) {
		t.Fatalf("auto-signed receipt with the flag on: %s %v", digest, err)
	}
	otherCell := enabled
	otherCell.Cell = "FRA"
	if _, err := otherCell.Verify(auto, autoDelegation, f.now); err == nil {
		t.Fatal("auto-signed receipt accepted outside its cell")
	}
}

func TestLayoutRejectsForeignOwnersAndLinks(t *testing.T) {
	f := newFixture(t)
	if _, err := Seed(f.layout, f.baked); err != nil {
		t.Fatal(err)
	}
	foreign := f.layout
	foreign.Owner = os.Getuid() + 1
	if _, err := foreign.Current(); err != nil {
		t.Fatalf("reading the link needs no ownership: %v", err)
	}
	current, _ := f.layout.Current()
	if err := foreign.VerifyRelease(current); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("foreign-owned release verified: %v", err)
	}
	if err := os.Remove(filepath.Join(f.layout.Root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin", filepath.Join(f.layout.Root, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.layout.Current(); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("escaping current link accepted: %v", err)
	}
	if _, err := Activate(f.layout, current, "not-a-unit", f.now, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid unit accepted: %v", err)
	}
	if _, err := Activate(f.layout, current, testUnit, f.now, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short proof window accepted: %v", err)
	}
	if err := (Layout{Root: "relative"}).ensureDirs(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relative root accepted: %v", err)
	}
}

func TestStageFromArtifactStoreFetchesVerifiedObject(t *testing.T) {
	f := newFixture(t)
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: "TS_ARTIFACTS"})
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("orchestrator chunk "), 20_000)
	receipt, delegation := f.signed(data)
	if _, err := Stage(f.layout, bytes.NewReader(nil), receipt, delegation, f.policy(), f.now); err == nil {
		t.Fatal("empty source staged")
	}
	if _, err := StageFromArtifactStore(t.Context(), f.layout, js, store, receipt, delegation, f.policy(), f.now); err == nil {
		t.Fatal("missing object staged")
	}
	if _, err := store.PutBytes(t.Context(), "sha256-"+digestOf(data), data); err != nil {
		t.Fatal(err)
	}
	digest, err := StageFromArtifactStore(t.Context(), f.layout, js, store, receipt, delegation, f.policy(), f.now)
	if err != nil || digest != digestOf(data) {
		t.Fatalf("stage from store = %s %v", digest, err)
	}
	if err := f.layout.VerifyRelease(digest); err != nil {
		t.Fatal(err)
	}
}
