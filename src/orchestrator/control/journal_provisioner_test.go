package control

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestProvisionControllerTopologyIsIdempotentAndExact(t *testing.T) {
	serverOptions := &server.Options{
		Host:      "127.0.0.1",
		Port:      -1,
		JetStream: true,
		StoreDir:  t.TempDir(),
	}
	instance, err := server.NewServer(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() {
		instance.Shutdown()
		instance.WaitForShutdown()
	})
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server did not become ready")
	}

	client, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	topology := NewNatsTopology("gru", 1, "controller-1")

	for attempt := 0; attempt < 2; attempt++ {
		if err := NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
			context.Background(), client, js, topology); err != nil {
			t.Fatalf("attempt %d: %v", attempt+1, err)
		}
	}
}
