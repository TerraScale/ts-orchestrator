package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// releaseSigner is CI's signing side: an offline root, its scoped update
// delegation for GRU and SJC in production, and the online leaf.
type releaseSigner struct {
	roots      trust.Keyring
	delegation trust.Envelope
	root       ed25519.PrivateKey
	leaf       ed25519.PrivateKey
	now        time.Time
}

type anyLineage struct{}

func (anyLineage) CheckLineage(string, string, string) error { return nil }

func newReleaseSigner(t *testing.T) releaseSigner {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encoded,
		Environment: "production", Architectures: []string{"amd64", "arm64"},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: strings.Repeat("9", 40),
	}, now.Add(-time.Minute), now.Add(7*24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return releaseSigner{roots: roots, delegation: delegation, root: rootPrivate, leaf: leafPrivate, now: now}
}

// services is a controller's view of the signer's root.
func (s releaseSigner) services(t *testing.T) *specRegistry {
	t.Helper()
	roots, err := newRootRegistry(s.roots, trust.ChainIdentity{DeploymentID: "0000000000FBPQEED3YHZXX2AS", Cell: "gru",
		Environment: "production"}, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	return &specRegistry{roots: roots, identity: cellspec.Identity{Environment: "production"}}
}

// channel signs binary as CI run run for cell, as ts-orch release deploy
// does: binary is this machine's architecture, the other one differs.
func (s releaseSigner) channel(t *testing.T, cell string, run int64, binary []byte) releasechannel.Channel {
	t.Helper()
	return s.channelWithSequence(t, cell, run, binary, 0, "")
}

func (s releaseSigner) channelSequenced(t *testing.T, cell string, run int64, binary []byte, sequence uint64, migration []byte) releasechannel.Channel {
	t.Helper()
	if sequence == 0 {
		t.Fatal("sequenced channel requires a positive release sequence")
	}
	channel := s.channelWithSequence(t, cell, run, binary, sequence, digestOf(migration))
	channel.ReleaseSequence, channel.SequenceMigration = sequence, bytes.Clone(migration)
	return channel
}

func (s releaseSigner) channelWithSequence(t *testing.T, cell string, run int64, binary []byte, sequence uint64, migrationSHA256 string) releasechannel.Channel {
	t.Helper()
	revision := fmt.Sprintf("%040x", run)
	binaries := map[string][]byte{}
	for _, architecture := range []string{"amd64", "arm64"} {
		binaries[architecture] = append(slices.Clone(binary), []byte("-"+architecture)...)
	}
	binaries[goruntime.GOARCH] = binary
	qualification := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: revision, SourceTree: revision, GoVersion: release.DefaultGoVersion,
		GoModSHA256: digestOf(binary), GoSumSHA256: digestOf(binary),
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: run + 1000, RunNumber: run, Conclusion: "success"},
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		qualification.Artifacts = append(qualification.Artifacts, release.QualifiedArtifact{Architecture: architecture,
			Name: "terrascale-orchestrator-linux-" + architecture, Bytes: int64(len(binaries[architecture])),
			SHA256: digestOf(binaries[architecture])})
	}
	wire, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	qualificationDigest := digestOf(wire)
	delegationWire, err := trust.EncodeEnvelope(s.delegation)
	if err != nil {
		t.Fatal(err)
	}
	channel := releasechannel.Channel{Schema: releasechannel.ChannelSchema, Cell: cell, Environment: "production",
		SourceRevision: revision, RunNumber: run, Delegation: delegationWire}
	machines := map[string]string{"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"}
	for _, architecture := range []string{"amd64", "arm64"} {
		machine := machines[architecture]
		binaryReceipt := release.BinaryReceipt{Schema: release.BinarySchema,
			SourceRevision: revision, GoVersion: release.DefaultGoVersion, GOOS: "linux", GOARCH: architecture,
			ELFMachine: machine, Static: true, Bytes: int64(len(binaries[architecture])),
			SHA256: digestOf(binaries[architecture]), QualificationSHA256: qualificationDigest}
		var receipt trust.Envelope
		if sequence == 0 {
			receipt, err = release.SignBinaryUpdateReceipt(binaryReceipt, qualification,
				qualificationDigest, cell, "production", anyLineage{}, s.delegation, s.roots, s.leaf, s.now, 24*time.Hour)
		} else {
			receipt, err = release.SignBinaryUpdateReceiptSequenced(binaryReceipt, qualification,
				qualificationDigest, cell, "production", anyLineage{}, s.delegation, s.roots, s.leaf, s.now, 24*time.Hour,
				sequence, migrationSHA256)
		}
		if err != nil {
			t.Fatal(err)
		}
		receipt = s.qualify(t, receipt, cell, architecture)
		receiptWire, err := trust.EncodeEnvelope(receipt)
		if err != nil {
			t.Fatal(err)
		}
		channel.Receipts = append(channel.Receipts, receiptWire)
	}
	return channel
}

// qualify binds a separate root signature to retained evidence for this binary.
func (s releaseSigner) qualify(t *testing.T, receipt trust.Envelope, cell, architecture string) trust.Envelope {
	t.Helper()
	// Qualification is already current while release issuance may exercise clock skew.
	qualifiedAt := s.now.Add(-2 * time.Minute)
	var update release.BinaryUpdateReceipt
	if err := json.Unmarshal(receipt.Payload, &update); err != nil {
		t.Fatal(err)
	}
	candidate := release.ProductionExpectation{SourceRevision: update.Binary.SourceRevision,
		ArtifactSHA256: update.Binary.SHA256, QualificationSHA256: update.Binary.QualificationSHA256,
		Cell: cell, Environment: "production", Runtime: release.ProductionRuntime, Architecture: architecture, Role: "orchestrator"}
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate}
	directory := t.TempDir()
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		data, err := json.Marshal(struct {
			Gate      string
			Candidate release.ProductionExpectation
		}{gate, candidate})
		if err != nil {
			t.Fatal(err)
		}
		digest := digestOf(data)
		path := filepath.Join(directory, digest)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		retained, err := os.ReadFile(path)
		if err != nil || len(retained) != len(data) || digestOf(retained) != digest {
			t.Fatalf("retained %s evidence differs from candidate bytes: %v", gate, err)
		}
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{
			Gate: gate, SHA256: digest, Bytes: int64(len(retained)), CompletedAt: qualifiedAt.Add(-time.Second)})
	}
	payload, err := trust.EncodePayload(qualification)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), qualifiedAt, qualifiedAt.Add(24*time.Hour), s.root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(directory, "qualification.json")
	if err := os.WriteFile(proofPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(proofPath)
	if err != nil || !bytes.Equal(retained, wire) {
		t.Fatalf("retained qualification differs from signed proof: %v", err)
	}
	delegation, err := trust.EncodeEnvelope(s.delegation)
	if err != nil {
		t.Fatal(err)
	}
	qualified, err := release.AttachProductionQualification(receipt, release.ProductionProof{Qualification: retained}, delegation,
		s.roots, s.leaf, release.UpdateExpectation{Cell: cell, Environment: "production", Architecture: architecture}, s.now)
	if err != nil {
		t.Fatal(err)
	}
	return qualified
}

// channelBucket is an in-memory head bucket with ETag preconditions.
type channelBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	etags   map[string]string
	version int
	puts    map[string]int
}

func newChannelBucket() *channelBucket {
	return &channelBucket{objects: map[string][]byte{}, etags: map[string]string{}, puts: map[string]int{}}
}

type objectStatus int

func (err objectStatus) Error() string          { return fmt.Sprintf("HTTP %d", int(err)) }
func (err objectStatus) GetHTTPStatusCode() int { return int(err) }
func (objectStatus) GetMessage() string         { return "" }
func (objectStatus) GetCode() string            { return "" }
func (objectStatus) GetOpcRequestID() string    { return "" }

func (b *channelBucket) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.objects[*request.ObjectName]
	if !ok {
		return objectstorage.GetObjectResponse{}, objectStatus(404)
	}
	etag := b.etags[*request.ObjectName]
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(data)), ETag: &etag}, nil
}

func (b *channelBucket) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	data, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	name := *request.ObjectName
	etag, exists := b.etags[name]
	if request.IfNoneMatch != nil && exists || request.IfMatch != nil && *request.IfMatch != etag {
		return objectstorage.PutObjectResponse{}, objectStatus(412)
	}
	b.version++
	b.objects[name], b.etags[name] = data, fmt.Sprintf("etag-%d", b.version)
	b.puts[name]++
	return objectstorage.PutObjectResponse{}, nil
}

func (b *channelBucket) status(t *testing.T) (releasechannel.Status, int) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var status releasechannel.Status
	if data, ok := b.objects[releasechannel.StatusObject]; ok {
		if err := json.Unmarshal(data, &status); err != nil {
			t.Fatal(err)
		}
	}
	return status, b.puts[releasechannel.StatusObject]
}

// proofsOn reports every unit freshly proving one release.
type proofsOn struct{ digest string }

func (p proofsOn) Latest(unit string) (rolloutexec.HealthProof, bool) {
	now := time.Now().UTC()
	return rolloutexec.HealthProof{Unit: unit, BinarySHA256: p.digest, ObservedAt: now, ReceivedAt: now}, true
}

type channelFixture struct {
	js        jetstream.JetStream
	control   *rolloutControl
	store     *rollout.Store
	kv        jetstream.KeyValue
	rolloutKV jetstream.KeyValue
	bucket    *channelBucket
	signer    releaseSigner
	proofs    *proofsOn
}

func newChannelFixture(t *testing.T) *channelFixture {
	t.Helper()
	signer := newReleaseSigner(t)
	js := testRolloutJetStream(t)
	store, err := rollout.OpenStore(t.Context(), js, "gru", 1, rolloutTestFence{epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	kv, err := openChannelBucket(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{NATS: natscell.Config{Cell: "gru"}}
	control, err := newRolloutControl(cfg, signer.services(t), "")
	if err != nil {
		t.Fatal(err)
	}
	bucket := newChannelBucket()
	control.channel = &channelSource{location: &releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}}
	proofs := &proofsOn{digest: strings.Repeat("a", 64)}
	rolloutKV, err := js.KeyValue(t.Context(), rollout.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	control.program = rolloutexec.ReleaseProgram{Store: store, Proofs: proofs,
		Controllers: []rollout.Unit{{ID: "ctl-a", Group: "controllers"}, {ID: "ctl-b", Group: "controllers"}}}
	return &channelFixture{js: js, control: control, store: store, kv: kv, rolloutKV: rolloutKV, bucket: bucket, signer: signer, proofs: proofs}
}

// setChannel announces channel in the cell's bucket, as TS-562 or the CI
// edge does.
func (f *channelFixture) setChannel(t *testing.T, channel releasechannel.Channel) {
	t.Helper()
	wire, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.kv.Put(t.Context(), releasechannel.ChannelKey("GRU"), wire); err != nil {
		t.Fatal(err)
	}
}

// consume runs the leader's consumer once on the announced channel and
// returns the stored report.
func (f *channelFixture) consume(t *testing.T) releasechannel.Status {
	t.Helper()
	entry, err := f.kv.Get(t.Context(), releasechannel.ChannelKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(t.Context(), f.store, f.kv, 7, entry.Value(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	status, _ := f.report(t)
	return status
}

func (f *channelFixture) report(t *testing.T) (releasechannel.Status, uint64) {
	t.Helper()
	entry, err := f.kv.Get(t.Context(), releasechannel.StatusKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	var status releasechannel.Status
	if err := json.Unmarshal(entry.Value(), &status); err != nil {
		t.Fatal(err)
	}
	return status, entry.Revision()
}

func (f *channelFixture) generations(t *testing.T) []rollout.Release {
	t.Helper()
	history, err := f.store.Releases(t.Context(), rollout.ReleaseHistory)
	if err != nil {
		t.Fatal(err)
	}
	return history
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// The leader makes a newer CI run the cell's next generation, reports its
// progress once per change, and reports it complete once every controller
// runs it.
func TestReleaseChannelPublishesANewerRunAndReportsProgress(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
	status := f.consume(t)
	history := f.generations(t)
	if len(history) != 1 || history[0].RunNumber != 620 || history[0].Digest != digestOf([]byte("run 620")) ||
		history[0].Actor != channelActor || len(history[0].Receipt) == 0 || !history[0].CreatedAt.Equal(f.signer.now) {
		t.Fatalf("published generations = %+v", history)
	}
	if status.Cell != "GRU" || status.RunNumber != 620 || status.State != releasechannel.StateRolling ||
		status.SourceRevision != fmt.Sprintf("%040x", 620) {
		t.Fatalf("status = %+v", status)
	}
	_, revision := f.report(t)
	f.consume(t)
	if _, again := f.report(t); again != revision {
		t.Fatal("an unchanged report was written again")
	}
	// A report someone else left (a deposed leader's) is replaced on the
	// next pass.
	forged := status
	forged.State = releasechannel.StateComplete
	wire, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.kv.Put(t.Context(), releasechannel.StatusKey("GRU"), wire); err != nil {
		t.Fatal(err)
	}
	if status := f.consume(t); status.State != releasechannel.StateRolling {
		t.Fatalf("a forged report stayed: %+v", status)
	}
	f.proofs.digest = history[0].Digest
	if status := f.consume(t); status.State != releasechannel.StateComplete {
		t.Fatalf("status once every controller runs it = %+v", status)
	}
	if len(f.generations(t)) != 1 {
		t.Fatal("the same run was published twice")
	}
}

// Until TS-562 announces releases over NATS, the leader copies CI's
// channel.json into the bucket and the bucket's report back to status.json,
// rewriting a report it does not hold and nothing else.
func TestReleaseChannelBridgeCarriesCIsChannelInAndTheReportOut(t *testing.T) {
	f := newChannelFixture(t)
	location := *f.control.channel.location
	if err := releasechannel.Publish(t.Context(), location, f.signer.channel(t, "GRU", 620, []byte("run 620"))); err != nil {
		t.Fatal(err)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	status := f.consume(t)
	if status.RunNumber != 620 || len(f.generations(t)) != 1 {
		t.Fatalf("the bridged channel was not followed: %+v", status)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	if stored, puts := f.bucket.status(t); !sameReport(stored, status) || puts != 1 {
		t.Fatalf("status.json = %+v after %d writes, want %+v", stored, puts, status)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	if _, puts := f.bucket.status(t); puts != 1 {
		t.Fatalf("an unchanged status.json was rewritten (%d writes)", puts)
	}
	forged := status
	forged.State = releasechannel.StateComplete
	if err := releasechannel.WriteStatus(t.Context(), location, forged); err != nil {
		t.Fatal(err)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	if stored, _ := f.bucket.status(t); !sameReport(stored, status) {
		t.Fatalf("a forged status.json stayed: %+v", stored)
	}
}
