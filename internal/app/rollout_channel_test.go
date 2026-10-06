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
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/releasechannel"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// releaseSigner is CI's signing side: an offline root, its scoped update
// delegation for GRU and SFO in production, and the online leaf.
type releaseSigner struct {
	roots      trust.Keyring
	delegation trust.Envelope
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
		Environment: "production", Cells: []string{"GRU", "SFO"}, Architectures: []string{"amd64", "arm64"},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: strings.Repeat("9", 40),
	}, now.Add(-time.Minute), now.Add(7*24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return releaseSigner{roots: roots, delegation: delegation, leaf: leafPrivate, now: now}
}

// services is a controller's view of the signer's root.
func (s releaseSigner) services(t *testing.T) *specRegistry {
	t.Helper()
	roots, err := newRootRegistry(s.roots, trust.ChainIdentity{DeploymentID: "ts-560-test", Cell: "gru",
		Environment: "production"}, trust.RootChain{}, "")
	if err != nil {
		t.Fatal(err)
	}
	return &specRegistry{roots: roots, identity: cellspec.Identity{Environment: "production"}}
}

// channel signs binary as CI run run for cell, as ts-orch release deploy
// does: binary is this machine's architecture, the other one differs.
func (s releaseSigner) channel(t *testing.T, cell string, run int64, binary []byte) releasechannel.Channel {
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
		receipt, err := release.SignBinaryUpdateReceipt(release.BinaryReceipt{Schema: release.BinarySchema,
			SourceRevision: revision, GoVersion: release.DefaultGoVersion, GOOS: "linux", GOARCH: architecture,
			ELFMachine: machine, Static: true, Bytes: int64(len(binaries[architecture])),
			SHA256: digestOf(binaries[architecture]), QualificationSHA256: qualificationDigest}, qualification,
			qualificationDigest, cell, "production", anyLineage{}, s.delegation, s.roots, s.leaf, s.now, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		receiptWire, err := trust.EncodeEnvelope(receipt)
		if err != nil {
			t.Fatal(err)
		}
		channel.Receipts = append(channel.Receipts, receiptWire)
	}
	return channel
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
	control *rolloutControl
	store   *rollout.Store
	kv      jetstream.KeyValue
	bucket  *channelBucket
	signer  releaseSigner
	proofs  *proofsOn
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
	cfg := Config{NATS: natscell.Config{Cell: "gru", Lab: true}, Controller: ControllerConfig{Rollouts: &RolloutsConfig{
		Enabled: true, Executor: true, AllowScopedAutoSign: true, Channel: true}}}
	control, err := newRolloutControl(cfg, signer.services(t), "")
	if err != nil {
		t.Fatal(err)
	}
	bucket := newChannelBucket()
	control.channel = &channelSource{location: &releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}}
	proofs := &proofsOn{digest: strings.Repeat("a", 64)}
	control.program = rolloutexec.ReleaseProgram{Store: store, Proofs: proofs,
		Controllers: []rollout.Unit{{ID: "ctl-a", Group: "controllers"}, {ID: "ctl-b", Group: "controllers"}}}
	return &channelFixture{control: control, store: store, kv: kv, bucket: bucket, signer: signer, proofs: proofs}
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
		history[0].Actor != channelActor || len(history[0].Receipt) == 0 {
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
