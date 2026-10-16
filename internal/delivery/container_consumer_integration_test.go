package delivery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

// The broker, signed wire, operation CAS and receipt are real. The application
// boundary injects a transient manager failure and checks its durable proof.
func TestContainerIntentSignedBrokerRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	runtime, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true, Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	codec := Ed25519Codec{Cell: "gru", Actor: "release", PrivateKey: private, Trusted: map[string]TrustedSigner{keyID: {Actor: "release", PublicKey: public}}, Lifetime: time.Minute, MaxLifetime: time.Minute}
	service, err := Open(ctx, Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: "gru", Replicas: 1, Signer: codec, Verifier: codec, Authorize: func(_ context.Context, actor string, _ Intent) error {
		if actor != "release" {
			return ErrUnauthorized
		}
		return nil
	}, Fencer: testFence{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/terrascale/auth@sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("b", 40), SourceRepository: "https://github.com/TerraScale/ts-auth", SourceTreeSHA256: strings.Repeat("e", 64), Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64", ReleaseSequence: 101, SequenceMigrationSHA256: strings.Repeat("c", 64), QualificationSHA256: strings.Repeat("d", 64)}
	payload, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: claim.Cell, Environment: claim.Environment, Role: claim.Role, Architecture: claim.Architecture}), now, now.Add(time.Hour), private)
	if err != nil {
		t.Fatal(err)
	}
	claimWire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	intent := Intent{SchemaVersion: SchemaVersion, OperationID: entityid.Derive("container-test", "recovery"), Source: ArtifactSource{Repository: "https://github.com/TerraScale/ts-auth", Commit: claim.SourceRevision, TreeDigest: strings.Repeat("e", 64)}, Cell: "gru", Role: claim.Role, Environment: claim.Environment, Generation: 1, DesiredReplicas: 2, ConfigDigest: ConfigDigestOf(nil, nil, nil), AuthorityEpoch: 1, Container: &release.ContainerBundle{Claim: claimWire}}
	calls := 0
	service.config.ContainerApply = func(ctx context.Context, admitted Intent) error {
		calls++
		retained, err := service.ContainerIntent(ctx, admitted.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(retained.Container.Claim, claimWire) {
			t.Fatal("runtime lost admitted claim")
		}
		admitted.Container.Claim[0] = '!'
		retained.Container.Claim[0] = '!'
		retained, err = service.ContainerIntent(ctx, intent.OperationID)
		if err != nil || !bytes.Equal(retained.Container.Claim, claimWire) {
			t.Fatal("callback mutated retained proof", err)
		}
		if calls == 1 {
			return errors.New("manager unavailable")
		}
		return nil
	}
	if err := service.Submit(ctx, intent); err != nil {
		t.Fatal(err)
	}
	fetch, err := service.consumer.Fetch(1, jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var wire []byte
	for msg := range fetch.Messages() {
		wire = bytes.Clone(msg.Data())
		if err := msg.Ack(); err != nil {
			t.Fatal(err)
		}
	}
	if fetch.Error() != nil || len(wire) == 0 {
		t.Fatal("missing signed broker intent", fetch.Error())
	}
	terminal, err := service.process(ctx, wire)
	if terminal || err == nil || calls != 1 {
		t.Fatalf("failed manager: terminal=%v calls=%d err=%v", terminal, calls, err)
	}
	if _, err := service.Status(ctx, intent.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("pending receipt: %v", err)
	}
	terminal, err = service.process(ctx, wire)
	if !terminal || err != nil || calls != 2 {
		t.Fatalf("retry: terminal=%v calls=%d err=%v", terminal, calls, err)
	}
	receipt, err := service.StatusFor(ctx, intent)
	if err != nil || receipt.Status != "accepted" {
		t.Fatal("receipt", receipt, err)
	}
	if terminal, err := service.process(ctx, wire); !terminal || err != nil || calls != 2 {
		t.Fatal("completed replay reapplied container", err)
	}
	changed := intent.Clone()
	changed.DesiredReplicas++
	if err := service.Submit(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation identity drift: %v", err)
	}
	for name, change := range map[string]func(*Intent){
		"native-digest": func(i *Intent) { i.ArtifactDigest = strings.Repeat("a", 64) },
		"source":        func(i *Intent) { i.Source.Commit = strings.Repeat("f", 40) },
		"scope":         func(i *Intent) { i.Role = "ts-other" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := intent.Clone()
			change(&bad)
			if err := service.Submit(ctx, bad); err == nil {
				t.Fatal("invalid typed arm published")
			}
		})
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)/2] ^= 1
	if terminal, err := service.process(ctx, tampered); !terminal || err != nil || calls != 2 {
		t.Fatal("tampered signature reached runtime", err)
	}
	// Fencing an already-retained pending operation produces a durable hold.
	fence := &containerTestFence{}
	service.config.Fencer = fence
	pending := intent.Clone()
	pending.OperationID = entityid.Derive("container-test", "fenced-pending")
	pendingPayload, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	pendingWire, err := codec.Sign(ctx, pendingPayload)
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	service.config.ContainerApply = func(context.Context, Intent) error { attempts++; return errors.New("manager unavailable") }
	if terminal, err := service.process(ctx, pendingWire); terminal || err == nil || attempts != 1 {
		t.Fatal("pending fixture", err)
	}
	fence.fenced = true
	if terminal, err := service.process(ctx, pendingWire); !terminal || err != nil || attempts != 1 {
		t.Fatal("fenced pending re-applied", err)
	}
	held, err := service.Status(ctx, pending.OperationID)
	if err != nil || held.Status != "held" {
		t.Fatal("fenced pending not held", held, err)
	}
	fence.fenced = false
	// A second controller instance recovers proof and receipt from the same store.
	recovered, err := Open(ctx, service.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovered.ContainerIntent(ctx, intent.OperationID); err != nil {
		t.Fatal("proof recovery", err)
	}
	if terminal, err := recovered.process(ctx, wire); !terminal || err != nil || calls != 2 {
		t.Fatal("restart lost completion", err)
	}
}

type containerTestFence struct {
	testFence
	fenced bool
}

func (f *containerTestFence) Guard(ctx context.Context, epoch uint64) error {
	if f.fenced {
		return authority.ErrFenced
	}
	return f.testFence.Guard(ctx, epoch)
}
