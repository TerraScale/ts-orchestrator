package delivery

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type deliveryTestBroker struct {
	conn *nats.Conn
	js   jetstream.JetStream
}

func (broker *deliveryTestBroker) Conn() *nats.Conn               { return broker.conn }
func (broker *deliveryTestBroker) JetStream() jetstream.JetStream { return broker.js }
func (broker *deliveryTestBroker) Close() error                   { broker.conn.Close(); return nil }

// Delivery tests exercise the real broker with challenge-authenticated clients.
func startDeliveryTestBroker(t *testing.T, ctx context.Context) *deliveryTestBroker {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(user.Wipe)
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), Nkeys: []*server.NkeyUser{{Nkey: public}}})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("authenticated delivery broker did not start")
	}
	conn, err := nats.Connect(broker.ClientURL(), nats.Nkey(public, user.Sign))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return &deliveryTestBroker{conn: conn, js: js}
}
