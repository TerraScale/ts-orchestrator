package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rolloutexec"
	"github.com/nats-io/nats.go/jetstream"
)

type readyRolloutWatch struct {
	jetstream.KeyValue
	ready chan struct{}
}

func (kv readyRolloutWatch) WatchAll(ctx context.Context, opts ...jetstream.WatchOpt) (jetstream.KeyWatcher, error) {
	w, err := kv.KeyValue.WatchAll(ctx, opts...)
	if err == nil {
		select {
		case kv.ready <- struct{}{}:
		default:
		}
	}
	return w, err
}

func TestRolloutWatcherSeesULIDRepliesAndSkipsStepPosts(t *testing.T) {
	js := testRolloutJetStream(t)
	board, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: rollout.Bucket})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wake, ready, done := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{})
	go func() {
		defer close(done)
		wakeOnRolloutChanges(ctx, readyRolloutWatch{KeyValue: board, ready: ready}, wake)
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("rollout watcher did not start")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command := rolloutexec.StepCommand{Schema: rolloutexec.StepSchema, Cell: "gru", Unit: "controller-a",
		RolloutID: entityid.New(), OperationID: entityid.New(), Kind: rollout.KindController,
		Action: rolloutexec.StepPrepare, Digest: strings.Repeat("a", 64), Replaces: strings.Repeat("b", 64),
		Epoch: 1, ProofWindowSeconds: 30}
	wire, err := rolloutexec.SignStepCommand(command, key, time.Now(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := board.Put(ctx, rolloutexec.StepKey(command.Unit), wire); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
		t.Fatal("leader's own step woke the executor")
	case <-time.After(100 * time.Millisecond):
	}
	for _, address := range []string{rolloutexec.ReplyKey(command.Unit), command.RolloutID, "release.desired", "cell"} {
		if _, err := board.Put(ctx, address, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-wake:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not wake the executor", address)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rollout watcher did not stop")
	}
}
