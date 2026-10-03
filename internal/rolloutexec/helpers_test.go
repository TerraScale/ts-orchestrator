package rolloutexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var (
	fromDigest = strings.Repeat("a", 64)
	toDigest   = strings.Repeat("b", 64)
	otherBad   = strings.Repeat("c", 64)
	testStart  = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
)

// epochFence is a controllable authority lease.
type epochFence struct {
	epoch  atomic.Uint64
	leader atomic.Bool
}

func newFence(epoch uint64) *epochFence {
	fence := &epochFence{}
	fence.epoch.Store(epoch)
	fence.leader.Store(true)
	return fence
}

func (fence *epochFence) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: fence.leader.Load(), Epoch: fence.epoch.Load(), Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}
}

func (fence *epochFence) Guard(_ context.Context, epoch uint64) error {
	if !fence.leader.Load() || epoch == 0 || epoch != fence.epoch.Load() {
		return authority.ErrFenced
	}
	return nil
}

func testNATS(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
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
	return conn, js
}

func testStore(t *testing.T, fence *epochFence) *rollout.Store {
	t.Helper()
	_, js := testNATS(t)
	store, err := rollout.OpenStore(t.Context(), js, "gru", 1, fence)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testKey(t *testing.T) (ed25519.PrivateKey, trust.Keyring) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	return private, keys
}

func testPolicy() rollout.Policy {
	return rollout.Policy{CanaryUnits: 1, BatchSize: 1, CanarySoakSeconds: 60, BatchSoakSeconds: 30,
		MinHealthyReports: 2, ProofDeadlineSeconds: 600, RollbackDeadlineSeconds: 600, PreflightSeconds: 300,
		MaxAttempts: 1, MaxRollbackRetries: 1}
}

// clock is a manually advanced test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
