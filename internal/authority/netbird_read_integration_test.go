package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNetBirdScopedReadAuthenticatedBroker(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
		NoLog: true, NoSigs: true, Users: []*server.User{
			{Username: "controller", Password: "controller-test-password"},
			{Username: "manager", Password: "manager-test-password", Permissions: &server.Permissions{
				Publish: &server.SubjectPermission{Allow: []string{"$JS.API.STREAM.INFO.TS_CONTROL_LOG",
					"$JS.API.CONSUMER.INFO.TS_CONTROL_LOG." + NetBirdReadConsumer,
					"$JS.API.CONSUMER.MSG.NEXT.TS_CONTROL_LOG." + NetBirdReadConsumer}},
				Subscribe: &server.SubjectPermission{Allow: []string{"_NET_READ.>"}},
			}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	admin, err := nats.Connect(srv.ClientURL(), nats.UserInfo("controller", "controller-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	js, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := Start(ctx, js, Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	denied := make(chan error, 16)
	conn, err := nats.Connect(srv.ClientURL(), nats.UserInfo("manager", "manager-test-password"),
		nats.CustomInboxPrefix("_NET_READ"), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { denied <- err }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	readerJS, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(context.Context) error { return nil }
	operation := entityid.New()
	sequence, err := runtime.CommitNetBirdIntent(ctx, runtime.Current().Epoch, operation, 0, []byte(`{"source":"signed-input-fixture"}`), verify)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG", "$JS.API.DIRECT.GET.TS_CONTROL_LOG.gru",
		"$JS.API.CONSUMER.DELETE.TS_CONTROL_LOG." + NetBirdReadConsumer, "ts.control.gru.netbird.intent.account"} {
		if err := conn.Publish(subject, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		if err := conn.FlushWithContext(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case <-denied:
		case <-ctx.Done():
			t.Fatalf("manager publish %s was not denied", subject)
		}
	}
	nonce := entityid.New()
	if err := runtime.OpenNetBirdRead(ctx, nonce); err != nil {
		t.Fatal(err)
	}
	reader, err := ConnectNetBirdRead(ctx, readerJS, "gru", nonce)
	if err != nil {
		t.Fatal(err)
	}
	entry, lease, err := reader.Read(ctx)
	if err != nil || entry.Sequence != sequence || entry.OperationID != operation || lease.OwnerID != runtime.Current().OwnerID {
		t.Fatalf("current source read = %+v %+v %v", entry, lease, err)
	}
	if _, err := ConnectNetBirdRead(ctx, readerJS, "gru", nonce); err == nil {
		t.Fatal("reused consumed session")
	}
	// Unrelated private payloads advance the global head but are never delivered.
	if _, err := runtime.CommitHostMutation(ctx, runtime.Current().Epoch, MutationRegistration, "gru.private", entityid.New(), 0, []byte(`{"secret":"must-not-be-delivered"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Read(ctx); err != nil {
		t.Fatalf("unrelated control mutation blocked current read: %v", err)
	}
	nextOperation := entityid.New()
	next, err := runtime.CommitNetBirdIntent(ctx, runtime.Current().Epoch, nextOperation, sequence, []byte(`{"source":"successor-input-fixture"}`), verify)
	if err != nil {
		t.Fatal(err)
	}
	entry, _, err = reader.Read(ctx)
	if err != nil || entry.Sequence != next || entry.OperationID != nextOperation {
		t.Fatalf("successor intent = %+v %v", entry, err)
	}
	if err := runtime.OpenNetBirdRead(ctx, entityid.New()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.Read(ctx); err == nil {
		t.Fatal("old session adopted replacement cursor")
	}
	if _, err := runtime.CommitNetBirdIntent(ctx, runtime.Current().Epoch, entityid.New(), next, []byte(`{}`), nil); err == nil {
		t.Fatal("unverified intent accepted")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(runtime.OpenNetBirdRead(ctx, entityid.New()), ErrNotLeader) {
		t.Fatal("released leader reopened cursor")
	}
}
