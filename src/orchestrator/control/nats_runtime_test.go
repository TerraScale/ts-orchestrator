package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestNatsRuntimeCheckFailsClosedWhenInfrastructureJournalIsMissing(t *testing.T) {
	client, topology, cleanup := natsRuntimeTestServer(t)
	defer cleanup()
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(context.Background(), client, js, topology); err != nil {
		t.Fatal(err)
	}
	options := &OrchestratorOptions{Command: OrchestratorCommandCheck, Cell: topology.Cell, NatsURL: client.ConnectedUrl(), Replicas: topology.Replicas, Instance: topology.Instance}
	if err := NatsRuntimeCheck(context.Background(), options); err == nil {
		t.Fatal("check accepted a topology without infrastructure-provisioned journal stores")
	}
}

func TestNatsRuntimeValidationRejectsPartialControllerCredentialsAndCancellation(t *testing.T) {
	options := &OrchestratorOptions{Command: OrchestratorCommandCheck, Cell: "gru", NatsURL: "nats://127.0.0.1:4222", Replicas: 1, Instance: "one", NatsNKeyFile: stringPtrForRuntimeTest("seed")}
	if err := NatsRuntimeCheck(context.Background(), options); err == nil {
		t.Fatal("partial controller credentials were accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	options.NatsNKeyFile = nil
	if err := NatsRuntimeCheck(ctx, options); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestNatsRuntimeValidationRequiresProductionCommandAdmission(t *testing.T) {
	options := &OrchestratorOptions{
		Command: OrchestratorCommandRun, Cell: "gru", NatsURL: "tls://127.0.0.1:4222",
		Replicas: 1, Instance: "one", NatsNKeyFile: stringPtrForRuntimeTest("seed"),
		NatsTls: &NatsTlsFiles{CaFile: "ca", CertificateFile: "cert", KeyFile: "key"},
	}
	err := validateNatsRuntimeInputs(context.Background(), options, OrchestratorCommandRun)
	if err == nil || !strings.Contains(err.Error(), "command signing and trust") {
		t.Fatalf("missing command admission credentials were accepted: %v", err)
	}
}

func TestNatsRuntimeCloseIsIdempotentAndCompletes(t *testing.T) {
	called := 0
	runtime := &NatsRuntime{completion: make(chan struct{}), cancel: func() { called++ }}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.Completion():
	default:
		t.Fatal("completion did not close")
	}
	if called != 1 {
		t.Fatalf("cancel called %d times", called)
	}
}

func TestNatsRuntimeReadinessIncludesMembershipLoopFailure(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(time.Minute)
	runtime := &NatsRuntime{
		authority: &RegionalAuthorityCoordinator{snapshot: RegionalAuthoritySnapshot{
			State: "leader", ObservedAt: now, LeaseExpiresAt: &expires,
		}},
		membership: &RegionalRuntimeMembership{},
	}
	if !runtime.ready() {
		t.Fatal("healthy authority and membership should be ready")
	}
	runtime.membership.heartbeatFailure.Store(&errorBox{err: errors.New("heartbeat failed")})
	if runtime.ready() {
		t.Fatal("a terminal membership heartbeat failure must make the runtime not ready")
	}
}

func natsRuntimeTestServer(t *testing.T) (*nats.Conn, *NatsTopology, func()) {
	t.Helper()
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	if !instance.ReadyForConnections(5 * time.Second) {
		instance.Shutdown()
		t.Fatal("test NATS server did not become ready")
	}
	client, err := nats.Connect(instance.ClientURL(), nats.MaxReconnects(0))
	if err != nil {
		instance.Shutdown()
		t.Fatal(err)
	}
	topology := NewNatsTopology("runtime-test", 1, "one")
	return client, topology, func() {
		client.Close()
		instance.Shutdown()
		instance.WaitForShutdown()
	}
}

func stringPtrForRuntimeTest(value string) *string { return &value }
