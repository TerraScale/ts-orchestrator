package regionsuggest

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

// fencer passes every guard, or refuses them all when refuse is set.
type fencer struct{ refuse bool }

func (f fencer) Current() authority.Snapshot {
	return authority.Snapshot{Leader: true, Ready: true, Epoch: 1}
}

func (f fencer) Guard(context.Context, uint64) error {
	if f.refuse {
		return authority.ErrNotLeader
	}
	return nil
}

func newTestJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream"),
	})
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
	return js
}

func TestStateRoundTripsAndRefusesStaleWrites(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, err := OpenStore(ctx, newTestJetStream(t), 1, fencer{})
	if err != nil {
		t.Fatal(err)
	}
	if state, revision, err := store.Load(ctx); err != nil || revision != 0 || !reflect.DeepEqual(state, State{}) {
		t.Fatalf("empty store = %+v, %d, %v", state, revision, err)
	}
	if _, ok, err := store.Suggestion(ctx); err != nil || ok {
		t.Fatalf("empty store has a suggestion: %v, %v", ok, err)
	}
	saved := State{
		Memory:     Memory{IdleSince: map[string]time.Time{"sjc": testNow}},
		Suggestion: Suggestion{Action: ActionNone, Reason: "every region is within its load band", At: testNow},
	}
	revision, err := store.Save(ctx, 1, saved, 0)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.Load(ctx)
	if err != nil || found != revision || !reflect.DeepEqual(loaded, saved) {
		t.Fatalf("loaded %+v at %d, %v; want %+v at %d", loaded, found, err, saved, revision)
	}
	if suggestion, ok, err := store.Suggestion(ctx); err != nil || !ok || suggestion != saved.Suggestion {
		t.Fatalf("suggestion = %+v, %v, %v", suggestion, ok, err)
	}
	if _, err := store.Save(ctx, 1, saved, revision+1); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("stale revision = %v, want ErrStateChanged", err)
	}
	if _, err := store.Save(ctx, 0, saved, revision); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("epoch 0 = %v, want ErrFenced", err)
	}
}

func TestStateIsNotWrittenWithoutTheLease(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	js := newTestJetStream(t)
	store, err := OpenStore(ctx, js, 1, fencer{refuse: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(ctx, 1, State{Suggestion: Suggestion{Action: ActionNone, Reason: "x", At: testNow}}, 0); err == nil {
		t.Fatal("a refused lease wrote the suggester state")
	}
	if _, revision, err := store.Load(ctx); err != nil || revision != 0 {
		t.Fatalf("refused write left state at %d, %v", revision, err)
	}
}
