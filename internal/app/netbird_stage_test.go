package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
