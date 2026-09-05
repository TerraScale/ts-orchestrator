package authority

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestGlobalAuthorityRenewsAcrossSiblingStreamWrites(t *testing.T) {
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS startup timed out")
	}
	nc, err := nats.Connect(broker.ClientURL(), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: jetstream.FileStorage, History: 1})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := RegionalAuthorityCoordinatorStartGlobalAsync(ctx, kv, "gru", "revision-test")
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Dispose()
	initial := coordinator.Snapshot()
	if !initial.IsLeader {
		t.Fatalf("initial authority: %+v", initial)
	}
	entry, err := kv.Get(ctx, "authority.global")
	if err != nil {
		t.Fatal(err)
	}
	var original RegionalAuthorityLeaseDocument
	if err := json.Unmarshal(entry.Value(), &original); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"root.workers.barrier", "security.rotation.barrier", "restore.drill.barrier"} {
		if _, err := kv.Put(ctx, key, []byte("sibling write")); err != nil {
			t.Fatal(err)
		}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		current := coordinator.Snapshot()
		if current.KvRevision > initial.KvRevision {
			if !current.IsLeader || current.State != "leader" || current.Epoch != initial.Epoch || current.KvRevision <= initial.KvRevision+1 {
				t.Fatalf("sibling writes fenced renewal: %+v", current)
			}
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("renewal timed out: %+v", current)
		}
	}
	if _, err := kv.Update(ctx, "authority.global", entry.Value(), entry.Revision()); err == nil {
		t.Fatal("stale lease revision overwrote renewal")
	}
	renewed, err := kv.Get(ctx, "authority.global")
	if err != nil {
		t.Fatal(err)
	}
	var lease RegionalAuthorityLeaseDocument
	if err := json.Unmarshal(renewed.Value(), &lease); err != nil {
		t.Fatal(err)
	}
	if lease.LeaseId != original.LeaseId || lease.CandidateId != original.CandidateId || lease.Epoch != original.Epoch {
		t.Fatal("renewal changed authority identity")
	}
	lease.CandidateId = "global-controller-gru-successor"
	lease.LeaseId = "successor-lease"
	lease.Epoch++
	lease.IssuedAt = time.Now().UTC()
	wire, _ := json.Marshal(lease)
	if _, err := kv.Update(ctx, "authority.global", wire, renewed.Revision()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if coordinator.Snapshot().IsLeader {
		t.Fatal("conflicting renewal retained authority")
	}
	actual, err := kv.Get(ctx, "authority.global")
	if err != nil || string(actual.Value()) != string(wire) {
		t.Fatal("old coordinator overwrote successor lease")
	}
}
