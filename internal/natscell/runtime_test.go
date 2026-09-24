package natscell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestEmbeddedSingleNodeDurableRestart(t *testing.T) {
	cfg := Config{
		Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := r.JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: "LAB_EVENTS", Subjects: []string{"lab.events"}, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.JetStream().Publish(ctx, "lab.events", []byte("persisted")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	r, err = Start(ctx, cfg)
	if err != nil {
		t.Fatal("restart:", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	stream, err = r.JetStream().Stream(ctx, stream.CachedInfo().Config.Name)
	if err != nil {
		t.Fatal(err)
	}
	message, err := stream.GetMsg(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data) != "persisted" {
		t.Fatalf("durable message = %q", message.Data)
	}
}

func TestHostNKeyCannotCrossNodeOrUseJetStream(t *testing.T) {
	controllerPublic, controllerSeed := newUserIdentity(t)
	hostPublic, hostSeed := newUserIdentity(t)
	otherPublic, _ := newUserIdentity(t)
	serverConfig := Config{
		Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		NKeySeedFile: controllerSeed,
		Embedded: &Embedded{
			Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "store"),
			Users: []NKeyGrant{
				{PublicKey: controllerPublic, Role: "controller"},
				{PublicKey: hostPublic, Role: "host", Node: "node-one"},
				{PublicKey: otherPublic, Role: "host", Node: "node-two"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	controller, err := Start(ctx, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	host, err := Start(ctx, Config{Cell: "lab", Instance: "host-one", Replicas: 1, Lab: true,
		URL: controller.URL(), NKeySeedFile: hostSeed, ClientRole: "host"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	observations, err := controller.Conn().SubscribeSync("ts.orch.v1.lab.agent.*.observation.*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observations.Unsubscribe() })
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("node-one"))
	allowed := "ts.orch.v1.lab.agent." + hex.EncodeToString(hash[:]) + ".observation.report"
	if err := host.Conn().Publish(allowed, []byte("own")); err != nil {
		t.Fatal(err)
	}
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	message, err := observations.NextMsg(time.Second)
	if err != nil || string(message.Data) != "own" {
		t.Fatalf("own observation was not delivered: %v %v", message, err)
	}
	hash = sha256.Sum256([]byte("node-two"))
	forbidden := "ts.orch.v1.lab.agent." + hex.EncodeToString(hash[:]) + ".observation.report"
	_ = host.Conn().Publish(forbidden, []byte("spoof"))
	_ = host.Conn().FlushTimeout(time.Second)
	if _, err := observations.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host published another node's observation: %v", err)
	}
	otherInbox, err := host.Conn().SubscribeSync(inboxPrefix("lab", otherPublic) + ".probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherInbox.Unsubscribe() })
	if err := host.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().Publish(inboxPrefix("lab", otherPublic)+".probe", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := controller.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := otherInbox.NextMsg(300 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("host subscribed to another node's replies: %v", err)
	}
	probeCtx, probeCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer probeCancel()
	if _, err := host.JetStream().AccountInfo(probeCtx); err == nil {
		t.Fatal("host accessed JetStream account API")
	}
}

func newUserIdentity(t *testing.T) (string, string) {
	t.Helper()
	pair, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pair.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	path := filepath.Join(t.TempDir(), "user.nk")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return public, path
}
