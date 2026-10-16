package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func netbirdStageELF(payload string) []byte {
	wire := make([]byte, 64)
	copy(wire, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(wire[16:], 2)
	binary.LittleEndian.PutUint16(wire[18:], 62)
	binary.LittleEndian.PutUint32(wire[20:], 1)
	binary.LittleEndian.PutUint16(wire[52:], 64)
	return append(wire, payload...)
}

func netbirdStageDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func netbirdStageTestPin(t *testing.T, body []byte) client.Pin {
	t.Helper()
	pin, err := client.LoadPin("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	pin.Archives.AMD64.BinarySHA256 = netbirdStageDigest(body)
	return pin
}

func signedNetbirdStage(t *testing.T, key ed25519.PrivateKey, request netbirdStageRequest, epoch uint64) []byte {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: netbirdStageKind,
		Actor: "ops", OperationID: "6FG8JSQDE0WD6HX997W10WK3DM", Generation: 1, Epoch: epoch}, now, now.Add(time.Minute), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func netbirdStagePolicy(t *testing.T, root string) (signerPolicy, TrustedSignerConfig, ed25519.PrivateKey) {
	t.Helper()
	public, private := testEd25519(t, root, "operator.key")
	grant := TrustedSignerConfig{Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public),
		Roles: []string{"ts-auth"}, Environments: []string{"production"}}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}}})
	if err != nil {
		t.Fatal(err)
	}
	return policy, grant, private
}

func TestNetBirdStageRejectsUnauthorizedRequests(t *testing.T) {
	policy, _, key := netbirdStagePolicy(t, t.TempDir())
	body := netbirdStageELF("authorized agent")
	pin := netbirdStageTestPin(t, body)
	request := netbirdStageRequest{Architecture: "amd64", Digest: netbirdStageDigest(body), Size: int64(len(body))}
	services := &specRegistry{current: cellspec.Spec{NetBird: &cellspec.NetBird{Pin: pin}}}
	fencer := rolloutTestFence{epoch: 3}
	if reply, err := serveNetBirdStage(t.Context(), signedNetbirdStage(t, key, request, 3), policy, fencer, services, nil); err != nil || reply.Digest != request.Digest || reply.Staged {
		t.Fatalf("valid staging preview = %+v, %v", reply, err)
	}
	_, untrusted := testEd25519(t, t.TempDir(), "untrusted.key")
	for _, test := range []struct {
		name     string
		key      ed25519.PrivateKey
		epoch    uint64
		request  netbirdStageRequest
		services *specRegistry
	}{
		{name: "untrusted signer", key: untrusted, epoch: 3, request: request, services: services},
		{name: "stale epoch", key: key, epoch: 2, request: request, services: services},
		{name: "absent pin", key: key, epoch: 3, request: request, services: &specRegistry{}},
		{name: "unrelated digest", key: key, epoch: 3,
			request: netbirdStageRequest{Architecture: "amd64", Digest: strings.Repeat("f", 64), Size: request.Size}, services: services},
		{name: "unsupported architecture", key: key, epoch: 3,
			request: netbirdStageRequest{Architecture: "386", Digest: request.Digest, Size: request.Size}, services: services},
		{name: "unbounded size", key: key, epoch: 3,
			request: netbirdStageRequest{Architecture: "amd64", Digest: request.Digest, Size: client.MaxBinaryBytes + 1}, services: services},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := serveNetBirdStage(t.Context(), signedNetbirdStage(t, test.key, test.request, test.epoch),
				policy, fencer, test.services, nil); err == nil {
				t.Fatal("unauthorized staging preview accepted")
			}
		})
	}
}

func TestSnapshotNetBirdStageRejectsIndirectAndInvalidSources(t *testing.T) {
	root := t.TempDir()
	body := netbirdStageELF("original agent")
	path := filepath.Join(root, "netbird")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, digest, size, err := snapshotNetBirdStage(t.Context(), path, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(snapshot.Name())
	defer snapshot.Close()
	if err := os.WriteFile(path, netbirdStageELF("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	if digest != netbirdStageDigest(body) || size != int64(len(body)) {
		t.Fatalf("snapshot receipt = %s %d", digest, size)
	}
	if err := client.VerifyBinary(snapshot.Name(), digest, "amd64"); err != nil {
		t.Fatalf("source mutation changed upload snapshot: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{link, fifo, root} {
		if _, _, _, err := snapshotNetBirdStage(t.Context(), source, "amd64"); err == nil {
			t.Fatalf("accepted indirect or non-regular source %s", source)
		}
	}
	if _, _, _, err := snapshotNetBirdStage(t.Context(), path, "arm64"); err == nil {
		t.Fatal("wrong ELF architecture accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err := snapshotNetBirdStage(ctx, path, "amd64"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot = %v", err)
	}
}

type netbirdStageFixture struct {
	root     string
	config   string
	broker   *natscell.Runtime
	control  *authority.Runtime
	store    jetstream.ObjectStore
	services *specRegistry
	policy   signerPolicy
	key      ed25519.PrivateKey
	body     []byte
}

func newNetbirdStageFixture(t *testing.T, ctx context.Context) netbirdStageFixture {
	t.Helper()
	f := netbirdStageFixture{root: t.TempDir(), body: netbirdStageELF("pinned upstream agent")}
	_, controllerSeed := testNKey(t)
	_, operatorSeed := testNKey(t)
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "stage-controller", Replicas: 1,
		NKeySeedFile: controllerSeed, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1,
			StoreDir: filepath.Join(f.root, "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	f.broker = broker
	t.Cleanup(func() { _ = broker.Close() })
	if err := broker.WaitForCluster(ctx, 1); err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "739PSJDKA86QX9QSHM4Q778WVM", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.control = control
	t.Cleanup(func() { _ = control.Close() })
	if !control.Current().CanMutate() {
		t.Fatal("regional controller did not acquire authority")
	}
	var grant TrustedSignerConfig
	f.policy, grant, f.key = netbirdStagePolicy(t, f.root)
	f.config = testJSONFile(t, f.root, "operator.json", Config{Version: ConfigVersion,
		NATS: auth.config(t, natscell.Config{Cell: "gru", Instance: "stage-operator", Replicas: 1, ClientRole: "operator",
			URL: broker.URL(), NKeySeedFile: operatorSeed}),
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{grant}},
		Operator:   OperatorConfig{Actor: "ops", SigningKeyFile: filepath.Join(f.root, "operator.key")},
	})
	f.services = &specRegistry{current: cellspec.Spec{NetBird: &cellspec.NetBird{Pin: netbirdStageTestPin(t, f.body)}}}
	f.store, err = broker.JetStream().CreateObjectStore(ctx, jetstream.ObjectStoreConfig{
		Bucket: delivery.ArtifactBucket, MaxBytes: 64 << 10, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := serveHostEnrollment(ctx, broker.Conn(), "gru", f.policy, control, nil, nil, f.services)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := broker.Conn().FlushTimeout(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestOperatorNetBirdStageUsesRestrictedTransportAndPreservesQuota(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newNetbirdStageFixture(t, ctx)
	path := filepath.Join(f.root, "netbird")
	stage := func(body []byte) (netbirdStageReply, error) {
		t.Helper()
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err := Run(ctx, []string{"operator", "netbird-stage", "--config", f.config,
			"--architecture", "amd64", "--file", path}, &output)
		var reply netbirdStageReply
		if err == nil {
			if err := protocol.DecodeStrict(output.Bytes(), &reply, 4096); err != nil {
				t.Fatal(err)
			}
		}
		return reply, err
	}
	reply, err := stage(f.body)
	if err != nil || !reply.Staged || reply.Digest != netbirdStageDigest(f.body) {
		t.Fatalf("restricted operator staging = %+v, %v", reply, err)
	}
	name := "sha256-" + reply.Digest
	read, err := f.store.GetBytes(ctx, name)
	if err != nil || !bytes.Equal(read, f.body) {
		t.Fatalf("stored artifact differs from source: %v", err)
	}
	info, err := f.store.GetInfo(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.broker.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	subject := "$O." + delivery.ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte(name))
	before, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage(f.body); err != nil {
		t.Fatalf("idempotent repeat staging: %v", err)
	}
	after, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(ctx))
	if err != nil || after.Sequence <= before.Sequence {
		t.Fatalf("existing object was not touched: %v", err)
	}
	again, err := f.store.GetInfo(ctx, name)
	if err != nil || again.NUID != info.NUID {
		t.Fatalf("repeat staging rewrote existing chunks: %v", err)
	}
	if _, err := f.broker.JetStream().KeyValue(ctx, delivery.AdmissionBucket); !errors.Is(err, jetstream.ErrBucketNotFound) {
		t.Fatalf("NetBird staging created generic source admission: %v", err)
	}
	large := netbirdStageELF(strings.Repeat("new agent", 16<<10))
	f.services.mu.Lock()
	f.services.current.NetBird = &cellspec.NetBird{Pin: netbirdStageTestPin(t, large)}
	f.services.mu.Unlock()
	if _, err := stage(large); !errors.Is(err, delivery.ErrArtifactStoreFull) {
		t.Fatalf("quota rejection = %v, want ErrArtifactStoreFull", err)
	}
	read, err = f.store.GetBytes(ctx, name)
	if err != nil || !bytes.Equal(read, f.body) {
		t.Fatalf("quota failure evicted previously staged agent: %v", err)
	}
}

func TestNetBirdStageCompletionReverifiesChecksumAndArchitecture(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newNetbirdStageFixture(t, ctx)
	request := netbirdStageRequest{Architecture: "amd64", Digest: netbirdStageDigest(f.body), Size: int64(len(f.body)), Verify: true}
	name := "sha256-" + request.Digest
	if _, err := f.store.PutBytes(ctx, name, netbirdStageELF(strings.Repeat("x", len(f.body)-64))); err != nil {
		t.Fatal(err)
	}
	if _, err := serveNetBirdStage(ctx, signedNetbirdStage(t, f.key, request, f.control.Current().Epoch),
		f.policy, f.control, f.services, f.broker.Conn()); err == nil {
		t.Fatal("object name was trusted without verifying uploaded bytes")
	}
	nonELF := bytes.Repeat([]byte("x"), len(f.body))
	request.Digest = netbirdStageDigest(nonELF)
	f.services.mu.Lock()
	f.services.current.NetBird = &cellspec.NetBird{Pin: netbirdStageTestPin(t, nonELF)}
	f.services.mu.Unlock()
	if _, err := f.store.PutBytes(ctx, "sha256-"+request.Digest, nonELF); err != nil {
		t.Fatal(err)
	}
	if _, err := serveNetBirdStage(ctx, signedNetbirdStage(t, f.key, request, f.control.Current().Epoch),
		f.policy, f.control, f.services, f.broker.Conn()); err == nil {
		t.Fatal("matching checksum admitted a non-ELF binary")
	}
}

func TestOperatorNetBirdStageRepairsInvalidObjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newNetbirdStageFixture(t, ctx)
	path := filepath.Join(f.root, "netbird")
	if err := os.WriteFile(path, f.body, 0600); err != nil {
		t.Fatal(err)
	}
	name := "sha256-" + netbirdStageDigest(f.body)
	legacy, err := f.broker.Conn().JetStream()
	if err != nil {
		t.Fatal(err)
	}
	subject := "$O." + delivery.ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte(name))
	stage := func() error {
		return Run(ctx, []string{"operator", "netbird-stage", "--config", f.config,
			"--architecture", "amd64", "--file", path}, &bytes.Buffer{})
	}
	for _, corruption := range []string{"wrong bytes", "invalid metadata", "malformed metadata", "missing chunks"} {
		t.Run(corruption, func(t *testing.T) {
			body := f.body
			if corruption == "wrong bytes" {
				body = netbirdStageELF(strings.Repeat("x", len(body)-64))
			}
			info, err := f.store.PutBytes(ctx, name, body)
			if err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "invalid metadata", "malformed metadata":
				info.Size++
				wire, err := json.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				if corruption == "malformed metadata" {
					wire = []byte("{")
				}
				message := nats.NewMsg(subject)
				message.Data = wire
				message.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
				if _, err := legacy.PublishMsg(message, nats.Context(ctx)); err != nil {
					t.Fatal(err)
				}
			case "missing chunks":
				if err := legacy.PurgeStream("OBJ_"+delivery.ArtifactBucket,
					&nats.StreamPurgeRequest{Subject: "$O." + delivery.ArtifactBucket + ".C." + info.NUID}, nats.Context(ctx)); err != nil {
					t.Fatal(err)
				}
			}
			if err := stage(); err != nil {
				t.Fatalf("could not repair %s: %v", corruption, err)
			}
			read, err := f.store.GetBytes(ctx, name)
			if err != nil || !bytes.Equal(read, f.body) {
				t.Fatalf("repair did not publish verified local bytes: %v", err)
			}
		})
	}
	chosen, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(ctx))
	if err != nil {
		t.Fatal(err)
	}
	touched := nats.NewMsg(subject)
	touched.Data = chosen.Data
	touched.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
	if _, err := legacy.PublishMsg(touched, nats.Context(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := repairNetBirdStageMetadata(ctx, legacy, chosen, name); err == nil {
		t.Fatal("repair erased a metadata revision published after verification")
	}
	read, err := f.store.GetBytes(ctx, name)
	if err != nil || !bytes.Equal(read, f.body) {
		t.Fatalf("stale repair changed verified bytes: %v", err)
	}
	message := nats.NewMsg(subject)
	message.Data = []byte("{")
	message.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
	if _, err := legacy.PublishMsg(message, nats.Context(ctx)); err != nil {
		t.Fatal(err)
	}
	state, err := legacy.StreamInfo("OBJ_"+delivery.ArtifactBucket, nats.Context(ctx))
	if err != nil {
		t.Fatal(err)
	}
	state.Config.MaxBytes = int64(state.State.Bytes) + int64(len(f.body)) - 1
	if _, err := legacy.UpdateStream(&state.Config, nats.Context(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := stage(); !errors.Is(err, delivery.ErrArtifactStoreFull) {
		t.Fatalf("repair bypassed quota: %v", err)
	}
	meta, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(ctx))
	if err != nil || !bytes.Equal(meta.Data, message.Data) {
		t.Fatalf("quota failure mutated the existing metadata: %v", err)
	}
}
