package reaper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

func TestNATSReaperActualStoreWithRestrictedGlobalR3Authority(t *testing.T) {
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := messaging.GlobalNatsPermissionsCreate("gru", messaging.GlobalNatsRoleGlobalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	cluster := newReaperStateCluster(t, &natsserver.NkeyUser{Nkey: public, Permissions: &natsserver.Permissions{
		Publish:   &natsserver.SubjectPermission{Allow: permissions.Publish},
		Subscribe: &natsserver.SubjectPermission{Allow: permissions.Subscribe},
	}})
	owner := cluster.connect(t)
	kv := openReaperTestLeaseStore(t, t.Context(), owner, true)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	ownerJS, err := jetstream.New(owner)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := ownerJS.Stream(ctx, reaperStream)
	if err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config := info.Config
	config.MaxMsgsPerSubject = 5 // Canonical global lease bucket history.
	if _, err := ownerJS.UpdateStream(ctx, config); err != nil {
		t.Fatal(err)
	}
	lease := reaperTestLease(1, "global-controller-gru-restricted")
	putReaperTestLease(t, ctx, kv, lease)
	denied := make(chan error, 32)
	connection, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[0].Port),
		nats.Secure(cluster.tls.Clone()), nats.Nkey(public, key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	store := newReaperTestSession(t, connection, lease)
	if state, err := store.Load(ctx); err != nil || len(state.Entries) != 0 {
		t.Fatalf("restricted initial load: %+v %v", state, err)
	}
	state := reaperTestState()
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("restricted state save: %v", err)
	}
	entry := state.Entries["db-1"]
	started := time.Now().UTC()
	entry.Operations["pause/snapshot"] = Operation{Status: operationStarted, Attempts: 1, StartedAt: started}
	state.Entries["db-1"] = entry
	state.Version++
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("restricted intent save: %v", err)
	}
	entry.Operations["pause/snapshot"] = Operation{Status: operationDone, Attempts: 1, StartedAt: started, CompletedAt: started.Add(time.Millisecond)}
	state.Entries["db-1"] = entry
	state.Version++
	if err := store.Save(ctx, state); err != nil {
		t.Fatalf("restricted receipt save: %v", err)
	}
	reopened := newReaperTestSession(t, connection, lease)
	loaded, err := reopened.Load(ctx)
	if err != nil || !sameReaperStateBytes(t, loaded, state) {
		t.Fatalf("restricted receipt recovery mismatch: %v", err)
	}
	if err := reopened.Save(ctx, loaded); err != nil {
		t.Fatalf("restricted identical save barrier: %v", err)
	}

	for _, subject := range []string{
		"$JS.API.STREAM.CREATE.UNADMITTED", "$JS.API.STREAM.UPDATE.KV_ORCH_LEADERS",
		"$JS.API.STREAM.DELETE.KV_ORCH_LEADERS", "$JS.API.STREAM.PURGE.KV_ORCH_LEADERS",
		"$JS.API.CONSUMER.CREATE.KV_ORCH_LEADERS.unadmitted", "$JS.API.CONSUMER.DELETE.KV_ORCH_LEADERS.unadmitted",
		"$KV.ORCH_LEADERS.reaper.other", "$KV.ORCH_LEADERS.reaper.state.extra", "$KV.ORCH_LEADERS.reaper.barrier.extra",
		"$KV.ORCH_LEADERS.authority.regional", "$KV.GLOBAL_CELLS.cell.gru", "$KV.UNADMITTED.reaper.state",
	} {
		if err := connection.Publish(subject, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := connection.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatalf("%s rejected for wrong reason: %v", subject, err)
			}
		case <-ctx.Done():
			t.Fatalf("forbidden subject was not denied: %s", subject)
		}
	}
	// Denied writes neither alter the authoritative receipt nor poison valid use.
	loaded, err = reopened.Load(ctx)
	if err != nil || !sameReaperStateBytes(t, loaded, state) {
		t.Fatalf("denied mutation changed durable state: %v", err)
	}
	lease.LeaseId = "replacement-lease"
	putReaperTestLease(t, ctx, kv, lease)
	if err := reopened.Save(ctx, loaded); !errors.Is(err, ErrStateFenced) {
		t.Fatalf("restricted stale authority save: %v", err)
	}
	successor := newReaperTestSession(t, connection, lease)
	loaded, err = successor.Load(ctx)
	if err != nil || !sameReaperStateBytes(t, loaded, state) {
		t.Fatalf("restricted successor lost durable receipts: %v", err)
	}
}

func sameReaperStateBytes(t *testing.T, actual, expected State) bool {
	t.Helper()
	a, err := reaperStateBytes(&actual)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reaperStateBytes(&expected)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(a, b)
}
