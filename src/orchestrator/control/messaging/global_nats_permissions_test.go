package messaging

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func TestGlobalAuthorityScopedStateAndDirectoryPermissions(t *testing.T) {
	permissions, err := GlobalNatsPermissionsCreate("gru", GlobalNatsRoleGlobalAuthority)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Wipe()
	authority, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Wipe()
	adminPublic, _ := admin.PublicKey()
	authorityPublic, _ := authority.PublicKey()
	account := server.NewAccount("GLOBAL")
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, JetStream: true, StoreDir: t.TempDir(), Accounts: []*server.Account{account}, Nkeys: []*server.NkeyUser{{Nkey: adminPublic, Account: account}, {Nkey: authorityPublic, Account: account, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: permissions.Publish}, Subscribe: &server.SubjectPermission{Allow: permissions.Subscribe}}}}})
	if err != nil {
		t.Fatal(err)
	}

	broker.Start()
	defer func() { broker.Shutdown(); broker.WaitForShutdown() }()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker unavailable")
	}
	registered, err := broker.LookupAccount("GLOBAL")
	if err != nil {
		t.Fatal(err)
	}
	if err := registered.EnableJetStream(nil, nil); err != nil {
		t.Fatal(err)
	}
	owner, err := nats.Connect(broker.ClientURL(), nats.Nkey(adminPublic, admin.Sign), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	js, err := jetstream.New(owner)
	if err != nil {
		t.Fatal(err)
	}
	// One file-backed server isolates ACL behavior; this does not prove global R3.
	cells, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: GlobalNatsTopologyCellsBucket, Storage: jetstream.FileStorage, History: 16})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cells.Put(ctx, "cell.gru", []byte("admitted-directory-state")); err != nil {
		t.Fatal(err)
	}
	leaders, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "ORCH_LEADERS", Storage: jetstream.FileStorage, History: 5, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	denied := make(chan error, 4)
	controller, err := nats.Connect(broker.ClientURL(), nats.Nkey(authorityPublic, authority.Sign), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	controllerJS, err := jetstream.New(controller)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controllerJS.KeyValue(ctx, GlobalNatsTopologyCellsBucket); err != nil {
		t.Fatalf("global admission cannot open directory bucket: %v", err)
	}
	stream, err := controllerJS.Stream(ctx, "KV_"+GlobalNatsTopologyCellsBucket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Info(ctx); err != nil {
		t.Fatalf("global admission cannot inspect directory profile: %v", err)
	}

	controllerLeaders, err := controllerJS.KeyValue(ctx, "ORCH_LEADERS")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"security.rotation.state", "security.rotation.barrier", "restore.drill.state", "restore.drill.barrier", "reaper.state", "reaper.barrier"} {
		revision, err := controllerLeaders.Create(ctx, key, []byte("first"))
		if err != nil {
			t.Fatalf("state create %s: %v", key, err)
		}
		if _, err := controllerLeaders.Update(ctx, key, []byte("durable-state"), revision); err != nil {
			t.Fatalf("state CAS %s: %v", key, err)
		}
		request, _ := json.Marshal(map[string]string{"last_by_subj": "$KV.ORCH_LEADERS." + key})
		response, err := controller.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET.KV_ORCH_LEADERS", request)
		if err != nil {
			t.Fatalf("leader read %s: %v", key, err)
		}
		var document struct {
			Message struct {
				Data []byte `json:"data"`
			} `json:"message"`
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(response.Data, &document) != nil || len(document.Error) != 0 || string(document.Message.Data) != "durable-state" {
			t.Fatalf("leader readback differs for %s", key)
		}
		entry, err := leaders.Get(ctx, key)
		if err != nil || string(entry.Value()) != "durable-state" {
			t.Fatalf("admin readback differs for %s", key)
		}
	}
	for _, subject := range []string{"$KV.GLOBAL_CELLS.cell.gru", "$JS.API.STREAM.UPDATE.KV_GLOBAL_CELLS", "$JS.API.STREAM.CREATE.KV_GLOBAL_CELLS", "$KV.ORCH_LEADERS.security.rotation.other", "$KV.ORCH_LEADERS.security.rotation.state.extra", "$KV.ORCH_LEADERS.restore.drill.other", "$KV.ORCH_LEADERS.restore.drill.barrier.extra", "$KV.ORCH_LEADERS.authority.regional", "$KV.ORCH_LEADERS.reaper.other", "$KV.ORCH_LEADERS.reaper.state.extra", "$KV.ORCH_LEADERS.reaper.barrier.extra"} {
		if err := controller.Publish(subject, []byte("unauthorized")); err != nil {
			t.Fatal(err)
		}
		if err := controller.Flush(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatalf("unexpected rejection: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("out-of-scope mutation was not denied: %s", subject)
		}
	}
	entry, err := cells.Get(ctx, "cell.gru")
	if err != nil || string(entry.Value()) != "admitted-directory-state" {
		t.Fatal("authority identity changed directory state")
	}
}
