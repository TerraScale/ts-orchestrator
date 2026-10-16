package host

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestReaderLeaderStateWithDirectGetDenied(t *testing.T) {
	const stream = "KV_" + stateBucket
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: t.TempDir(), Users: []*server.User{
			{Username: "admin", Password: "admin-secret"},
			{Username: "reader", Password: "reader-secret", Permissions: &server.Permissions{
				Publish: &server.SubjectPermission{Allow: []string{
					"$JS.API.STREAM.INFO." + stream,
					"$JS.API.STREAM.MSG.GET." + stream,
				}},
				Subscribe: &server.SubjectPermission{Allow: []string{"_INBOX.>"}},
			}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	admin, err := nats.Connect(srv.ClientURL(), nats.UserInfo("admin", "admin-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	adminJS, err := jetstream.New(admin)
	if err != nil {
		t.Fatal(err)
	}
	state, err := adminJS.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: stateBucket, History: 2})
	if err != nil {
		t.Fatal(err)
	}
	controlLog, err := adminJS.CreateStream(t.Context(), jetstream.StreamConfig{Name: "TS_CONTROL_LOG", Subjects: []string{"ts.control.gru.>"}})
	if err != nil {
		t.Fatal(err)
	}
	key := reportKey("gru", "node-a", "terrabase")
	value, err := json.Marshal(Report{Cell: "gru", Node: "node-a", Role: "terrabase", State: "running"})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := state.Put(t.Context(), key, value)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(srv.ClientURL(), nats.UserInfo("reader", "reader-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	restrictedJS, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	restrictedState, err := restrictedJS.KeyValue(t.Context(), stateBucket)
	if err != nil {
		t.Fatal(err)
	}
	directCtx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := restrictedState.Get(directCtx, key); err == nil {
		t.Fatal("direct KV GET unexpectedly succeeded without its publish grant")
	}
	reader, err := NewReader(t.Context(), ReaderConfig{Cell: "gru", Conn: conn, State: state,
		StateReplicas: 1, ControlLog: controlLog, HostMutations: &memoryMutations{entries: map[string]authority.LogEntry{}}})
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	gotRevision, exists, err := reader.controller.get(t.Context(), key, &report)
	if err != nil || !exists || gotRevision != revision || report.State != "running" {
		t.Fatalf("reader leader report: revision=%d exists=%t report=%+v err=%v", gotRevision, exists, report, err)
	}
	if err := state.Delete(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	_, exists, err = reader.controller.get(t.Context(), key, &report)
	if err != nil || exists {
		t.Fatalf("reader tombstone: exists=%t err=%v", exists, err)
	}
	if _, exists, err := reader.controller.get(t.Context(), reportKey("gru", "missing", "terrabase"), &report); err != nil || exists {
		t.Fatalf("reader missing state: exists=%t err=%v", exists, err)
	}
}
