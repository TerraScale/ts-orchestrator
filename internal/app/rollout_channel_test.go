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
// delegation for GRU and SFO in production, and the online leaf.
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

func TestReleaseChannelRetriesUntouchedExpiryWithFreshSignedRun(t *testing.T) {
	f := newChannelFixture(t)
	f.control.program.Policy = rollout.DefaultPolicy()
	ctx := t.Context()
	binary := []byte("same binary across qualifying runs")
	old := f.signer.channel(t, "GRU", 620, binary)
	admitted, err := f.control.admitChannel(old, f.signer.now)
	if err != nil {
		t.Fatal(err)
	}
	admitted.Actor = channelActor
	first, err := f.store.PublishRelease(ctx, 7, admitted)
	if err != nil {
		t.Fatal(err)
	}
	at := first.CreatedAt.Add(rollout.ObservationBudget)
	verified, err := f.control.verify(first.Receipt, first.Delegation, at)
	if err != nil || !verified.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("manual admission renewed signed issuance: %+v, %v", verified, err)
	}
	plan, err := f.control.program.Program(ctx)
	if err != nil || len(plan) != 1 {
		t.Fatalf("old plan = %+v, %v", plan, err)
	}
	plan[0].AuthorityEpoch = 7
	record, revision, err := f.store.Begin(ctx, plan[0], at)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := rollout.Apply(record, rollout.Event{Kind: rollout.EventStart, At: at})
	if err != nil || expired.Phase != rollout.PhaseAborted {
		t.Fatalf("old expiry = %+v, %v", expired, err)
	}
	if _, err := f.store.Commit(ctx, revision, expired); err != nil {
		t.Fatal(err)
	}
	freshSigner := f.signer
	freshSigner.now = at
	fresh := freshSigner.channel(t, "GRU", 621, binary)
	f.setChannel(t, fresh)
	entry, err := f.kv.Get(ctx, releasechannel.ChannelKey("GRU"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, entry.Value(), at); err != nil {
		t.Fatal(err)
	}
	status, _ := f.report(t)
	history := f.generations(t)
	if status.State != releasechannel.StateRolling || len(history) != 2 || history[0].Digest != first.Digest ||
		history[0].RunNumber != 621 || !history[0].CreatedAt.Equal(at) || !history[1].CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("fresh signed run = %+v; history %+v", status, history)
	}
	plan, err = f.control.program.Program(ctx)
	if err != nil || len(plan) != 1 || !plan[0].StartedAt.Equal(at) {
		t.Fatalf("fresh plan = %+v, %v", plan, err)
	}
	plan[0].AuthorityEpoch = 7
	if _, _, err := f.store.Begin(ctx, plan[0], at); err != nil {
		t.Fatalf("fresh signed run could not start under the default attempt limit: %v", err)
	}
	// The old wire remains the old failed generation; it cannot reset the new one.
	oldWire, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(ctx, f.store, f.kv, 7, oldWire, at); err != nil {
		t.Fatal(err)
	}
	if desired, _, err := f.store.Desired(ctx); err != nil || desired.Release.Generation != history[0].Generation || !desired.Release.CreatedAt.Equal(at) {
		t.Fatalf("old replay changed the fresh generation: %+v, %v", desired, err)
	}
}

func TestReleaseChannelWaitsForToleratedReceiptClockSkew(t *testing.T) {
	f := newChannelFixture(t)
	f.control.program.Policy = rollout.DefaultPolicy()
	now := f.signer.now
	signer := f.signer
	signer.now = now.Add(time.Minute)
	channel := signer.channel(t, "GRU", 622, []byte("future receipt"))
	admitted, err := f.control.admitChannel(channel, now)
	if err != nil || !admitted.CreatedAt.Equal(signer.now) {
		t.Fatalf("tolerated receipt did not verify with its original issuance: %+v, %v", admitted, err)
	}
	wire, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(t.Context(), f.store, f.kv, 7, wire, now); err != nil {
		t.Fatal(err)
	}
	status, _ := f.report(t)
	if status.State != releasechannel.StateRolling || !strings.Contains(status.Reason, "waiting for the cell clock") || len(f.generations(t)) != 0 {
		t.Fatalf("future receipt was not deferred: %+v", status)
	}
	if cell, _, err := f.store.Cell(t.Context()); err != nil || cell.ActiveRolloutID != "" || len(cell.Attempts) != 0 {
		t.Fatalf("future receipt reserved a rollout: %+v, %v", cell, err)
	}
	if err := f.control.consumeChannel(t.Context(), f.store, f.kv, 7, wire, signer.now); err != nil {
		t.Fatal(err)
	}
	history := f.generations(t)
	if len(history) != 1 || !history[0].CreatedAt.Equal(signer.now) {
		t.Fatalf("admission reset signed issuance: %+v", history)
	}
	plan, err := f.control.program.Program(t.Context())
	if err != nil || len(plan) != 1 || !plan[0].StartedAt.Equal(signer.now) {
		t.Fatalf("observation start = %+v, %v", plan, err)
	}
}

func TestReleaseChannelFailsUntrustedOrExcessivelyFutureReceipt(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprint(tamper), func(t *testing.T) {
			f := newChannelFixture(t)
			signer := f.signer
			signer.now = signer.now.Add(time.Minute + time.Second)
			if tamper {
				signer.now = f.signer.now.Add(30 * time.Second)
			}
			channel := signer.channel(t, "GRU", 622, []byte("refused future receipt"))
			if tamper {
				envelope, err := trust.DecodeEnvelope(channel.Receipts[0])
				if err != nil {
					t.Fatal(err)
				}
				envelope.Scope.Cell = "SFO"
				channel.Receipts[0], err = trust.EncodeEnvelope(envelope)
				if err != nil {
					t.Fatal(err)
				}
			}
			state, reason, err := f.control.channelState(t.Context(), f.store, 7, channel, f.signer.now)
			if err != nil || state != releasechannel.StateFailed || !strings.Contains(reason, "does not verify") || len(f.generations(t)) != 0 {
				t.Fatalf("invalid future receipt was deferred: %s %s, %v", state, reason, err)
			}
		})
	}
}

// Every byte a node acts on is bound by the receipts, so a channel a bucket
// writer altered is reported failed, which stops the fleet rollout, and
// never becomes a generation.
func TestReleaseChannelRefusesATamperedChannel(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, signer releaseSigner) releasechannel.Channel{
		"another cell's receipts": func(t *testing.T, signer releaseSigner) releasechannel.Channel {
			channel := signer.channel(t, "SFO", 620, []byte("run 620"))
			channel.Cell = "GRU"
			return channel
		},
		"a run its receipts do not name": func(t *testing.T, signer releaseSigner) releasechannel.Channel {
			channel := signer.channel(t, "GRU", 620, []byte("run 620"))
			channel.RunNumber = 621
			return channel
		},
		"another environment": func(t *testing.T, signer releaseSigner) releasechannel.Channel {
			channel := signer.channel(t, "GRU", 620, []byte("run 620"))
			channel.Environment = "canary"
			return channel
		},
		"a leaf another root delegated": func(t *testing.T, _ releaseSigner) releasechannel.Channel {
			return newReleaseSigner(t).channel(t, "GRU", 620, []byte("run 620"))
		},
		"a receipt for another binary": func(t *testing.T, signer releaseSigner) releasechannel.Channel {
			channel := signer.channel(t, "GRU", 620, []byte("run 620"))
			other := signer.channel(t, "GRU", 620, []byte("other binary"))
			channel.Receipts = other.Receipts
			channel.SourceRevision = other.SourceRevision
			// Every receipt's signed digest is swapped for this channel's.
			for index, wire := range channel.Receipts {
				envelope, err := trust.DecodeEnvelope(wire)
				if err != nil {
					t.Fatal(err)
				}
				for _, architecture := range []string{"amd64", "arm64"} {
					theirs, ours := []byte("other binary"), []byte("run 620")
					if architecture != goruntime.GOARCH {
						theirs, ours = append(theirs, "-"+architecture...), append(ours, "-"+architecture...)
					}
					envelope.Payload = bytes.ReplaceAll(envelope.Payload, []byte(digestOf(theirs)), []byte(digestOf(ours)))
				}
				if channel.Receipts[index], err = trust.EncodeEnvelope(envelope); err != nil {
					t.Fatal(err)
				}
			}
			return channel
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newChannelFixture(t)
			f.setChannel(t, tamper(t, f.signer))
			if status := f.consume(t); status.State != releasechannel.StateFailed ||
				!strings.Contains(status.Reason, "does not verify") {
				t.Fatalf("status = %+v", status)
			}
			if history := f.generations(t); len(history) != 0 {
				t.Fatalf("a tampered channel published %+v", history)
			}
		})
	}
	f := newChannelFixture(t)
	if _, err := f.kv.Put(t.Context(), releasechannel.ChannelKey("GRU"), []byte(`{"schema":`)); err != nil {
		t.Fatal(err)
	}
	if status := f.consume(t); status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "does not decode") {
		t.Fatalf("status of a channel that does not decode = %+v", status)
	}
}

// A channel never moves the cell backwards: a run older than the cell's
// newest is refused, and after an operator rolls the cell back the channel's
// run is reported failed instead of being published again.
func TestReleaseChannelNeverRepublishesAnOlderOrRolledBackRun(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 619, []byte("run 619")))
	f.consume(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
	f.consume(t)
	if _, err := f.store.RollbackRelease(t.Context(), 7, 1, "ops", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	status := f.consume(t)
	if status.RunNumber != 620 || status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "replaced by generation 3") {
		t.Fatalf("status after an operator rollback = %+v", status)
	}
	if history := f.generations(t); len(history) != 3 || history[0].RollbackOf != 1 {
		t.Fatalf("the rolled back run was published again: %+v", history)
	}
	f.setChannel(t, f.signer.channel(t, "GRU", 618, []byte("run 618")))
	if status := f.consume(t); status.State != releasechannel.StateFailed || !strings.Contains(status.Reason, "already published run 620") {
		t.Fatalf("status of an older run = %+v", status)
	}
	if len(f.generations(t)) != 3 {
		t.Fatal("an older run was published")
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

// proofsBy gives each unit its own release; a unit without one is silent.
type proofsBy map[string]string

func (p proofsBy) Latest(unit string) (rolloutexec.HealthProof, bool) {
	digest, ok := p[unit]
	now := time.Now().UTC()
	return rolloutexec.HealthProof{Unit: unit, BinarySHA256: digest, ObservedAt: now, ReceivedAt: now}, ok
}

// A silent or outdated host cannot make an entire region look deployed.
func TestReleaseChannelWaitsForEveryHost(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
	target := digestOf([]byte("run 620"))
	proofs := proofsBy{"ctl-a": target, "ctl-b": target}
	f.control.program.Proofs = proofs
	f.control.program.Hosts = func(context.Context) ([]rollout.Unit, error) {
		return rolloutexec.HostUnits(map[string][]string{"gru-1-db-1": {"terrabase"}}), nil
	}
	if status := f.consume(t); status.State != releasechannel.StateRolling || !strings.Contains(status.Reason, "health proofs") {
		t.Fatalf("status with a silent host = %+v", status)
	}
	proofs["gru-1-db-1"] = strings.Repeat("a", 64)
	if status := f.consume(t); status.State != releasechannel.StateRolling {
		t.Fatalf("status with a host behind = %+v", status)
	}
	proofs["gru-1-db-1"] = target
	if status := f.consume(t); status.State != releasechannel.StateComplete {
		t.Fatalf("status with every host on the target = %+v", status)
	}
}

func TestReleaseChannelPinsRefreshWithoutProgressChange(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
	first := f.consume(t)
	if first.Pins == nil || !slices.Equal(first.Pins.Rollback, []string{digestOf([]byte("run 620"))}) {
		t.Fatalf("initial pins: %+v", first.Pins)
	}
	_, revision := f.report(t)
	bad := strings.Repeat("e", 64)
	if _, err := f.rolloutKV.Put(t.Context(), "knownbad."+bad, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	updated := f.consume(t)
	_, nextRevision := f.report(t)
	if updated.State != first.State || updated.Reason != first.Reason || nextRevision == revision ||
		!slices.Equal(updated.Pins.KnownBad, []string{bad}) {
		t.Fatalf("pin-only refresh: %+v revision %d -> %d", updated, revision, nextRevision)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	if stored, _ := f.bucket.status(t); !stored.Pins.Equal(updated.Pins) {
		t.Fatalf("head bucket pins: %+v", stored.Pins)
	}
}

func TestReleaseChannelPublishesManualPinsWithoutAChannel(t *testing.T) {
	f := newChannelFixture(t)
	digest := strings.Repeat("a", 64)
	if _, err := f.store.PublishRelease(t.Context(), 7, rollout.Release{Digest: digest, Actor: "ops", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := f.control.consumeChannel(t.Context(), f.store, f.kv, 7, nil, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	if stored, _ := f.bucket.status(t); stored.Pins == nil || !slices.Equal(stored.Pins.Rollback, []string{digest}) {
		t.Fatalf("manual release pins missing: %+v", stored)
	}
}

func TestReleaseChannelPublishesRealDeploymentScopeWithoutAValidChannel(t *testing.T) {
	f := newChannelFixture(t)
	// A bad desired scope cannot replace the running controller's trust scope.
	channel := f.signer.channel(t, "GRU", 620, []byte("run 620"))
	channel.Environment = "canary"
	f.setChannel(t, channel)
	status := f.consume(t)
	if status.State != releasechannel.StateFailed || status.Environment != "production" ||
		!slices.Equal(status.Architectures, []string{goruntime.GOARCH}) {
		t.Fatalf("desired channel changed actual scope: %+v", status)
	}
	if err := f.control.bridgePass(t.Context(), f.kv); err != nil {
		t.Fatal(err)
	}
	stored, _ := f.bucket.status(t)
	if err := stored.ValidateDeploymentScope("GRU", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	changed := stored
	changed.Environment = "canary"
	if sameReport(stored, changed) {
		t.Fatal("environment change suppressed report refresh")
	}
	changed = stored
	changed.Architectures = []string{"amd64", "arm64"}
	if sameReport(stored, changed) {
		t.Fatal("architecture change suppressed report refresh")
	}
}

func TestReleaseChannelWaitsForAPublishedGenerationToBecomeVisible(t *testing.T) {
	f := newChannelFixture(t)
	f.setChannel(t, f.signer.channel(t, "GRU", 620, []byte("run 620")))
	f.consume(t)
	// Model the follower still returning generation 1 immediately after
	// the leader's generation-2 publish succeeded.
	state, reason, err := f.control.generationState(t.Context(), f.store, rollout.Release{Generation: 2, Digest: strings.Repeat("b", 64)})
	if err != nil || state != releasechannel.StateRolling || !strings.Contains(reason, "waiting for generation 2") {
		t.Fatalf("a lagging desired read failed the release: %s %s %v", state, reason, err)
	}
}
