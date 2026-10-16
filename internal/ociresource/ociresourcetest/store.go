package ociresourcetest

import (
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Store opens the production OCI store against an isolated authenticated,
// persistent NATS server. It belongs only in integration test binaries.
func Store(t *testing.T) *ociresource.KVStore {
	t.Helper()
	token := rand.Text()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream"), Authorization: token})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("OCI integration broker did not become ready")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.Token(token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ociresource.OpenKVStore(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
