package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestOperationLeaderReadWithDirectGetDenied(t *testing.T) {
	const stream = "KV_" + OperationBucket
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
	kv, err := adminJS.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: OperationBucket, History: 4})
	if err != nil {
		t.Fatal(err)
	}
	key := operationKey("leader-test")
	revision, err := kv.Put(t.Context(), key, []byte(`{"state":"accepted"}`))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := nats.Connect(srv.ClientURL(), nats.UserInfo("reader", "reader-secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	readerJS, err := jetstream.New(reader)
	if err != nil {
		t.Fatal(err)
	}
	readerKV, err := readerJS.KeyValue(t.Context(), OperationBucket)
	if err != nil {
		t.Fatal(err)
	}
	directCtx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := readerKV.Get(directCtx, key); err == nil {
		t.Fatal("direct KV GET unexpectedly succeeded without its publish grant")
	}
	s := &Service{config: Config{Conn: reader}}
	entry, err := s.getOperation(t.Context(), key)
	if err != nil || entry.Revision() != revision || string(entry.Value()) != `{"state":"accepted"}` {
		t.Fatalf("leader read: entry=%+v err=%v", entry, err)
	}
	if _, err := s.getOperation(t.Context(), operationKey("missing")); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("missing key = %v, want key not found", err)
	}
	if err := kv.Delete(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.getOperation(t.Context(), key); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("tombstone = %v, want key not found", err)
	}
}

func TestOperationLeaderReadRejectsInvalidMessage(t *testing.T) {
	const subject = "$KV." + OperationBucket + ".o_valid"
	for _, test := range []struct {
		name string
		msg  *nats.RawStreamMsg
	}{
		{"nil", nil},
		{"wrong subject", &nats.RawStreamMsg{Subject: subject + ".other", Sequence: 1, Data: []byte("{}")}},
		{"zero sequence", &nats.RawStreamMsg{Subject: subject, Data: []byte("{}")}},
		{"empty body", &nats.RawStreamMsg{Subject: subject, Sequence: 1}},
		{"unknown operation", &nats.RawStreamMsg{Subject: subject, Sequence: 1, Data: []byte("{}"), Header: nats.Header{"KV-Operation": []string{"UNKNOWN"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := operationValueFromMsg(subject, test.msg); err == nil || errors.Is(err, jetstream.ErrKeyNotFound) {
				t.Fatalf("invalid message returned %v", err)
			}
		})
	}
}
