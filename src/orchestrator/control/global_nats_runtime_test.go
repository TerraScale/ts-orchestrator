package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestGlobalNatsRuntimeRequiresCompleteGRUConfiguration(t *testing.T) {
	if _, err := GlobalNatsRuntimeStartAsync(context.Background(), nil); err == nil {
		t.Fatal("nil configuration was accepted")
	}
	configuration := &GlobalNatsRuntimeConfiguration{
		Authority: &GlobalAuthorityNatsConfiguration{
			Url: "tls://127.0.0.1:4222", Authentication: &NatsAuthenticationFiles{PublicKey: "UA"},
			Tls: &NatsTlsFiles{CaFile: "ca", CertificateFile: "authority", KeyFile: "key"}, Replicas: 3, Cell: "gru",
		},
		Cell: "sfo", Instance: "one",
	}
	if _, err := GlobalNatsRuntimeStartAsync(context.Background(), configuration); err == nil {
		t.Fatal("non-GRU authority configuration was accepted")
	}
}

func TestGlobalNatsRuntimeOpenAndValidateRequiresPreProvisionedGlobalState(t *testing.T) {
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server did not become ready")
	}
	client, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	topology, err := NewGlobalNatsTopology(3)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := globalNatsRuntimeOpenAndValidate(ctx, client, topology, false, "gru"); err == nil {
		t.Fatal("global runtime accepted a topology that was not provisioned")
	}
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(ctx, GlobalNatsTopologyCellSpecStream); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("validation created a stream: %v", err)
	}
}

func TestGlobalNatsRuntimeOpenAndValidateFullyProvisionedTopology(t *testing.T) {
	instance, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
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

	// The production constructor requires R3. A single-node topology exercises
	// the same server normalization and validation paths without weakening the
	// production admission boundary.
	topology := &GlobalNatsTopology{Replicas: 1}
	cellSpecConsumer, err := topology.CellSpecConsumer("gru")
	if err != nil {
		t.Fatal(err)
	}
	ciJobConsumer, err := topology.CiJobConsumer("trusted-build", "runner-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, configuration := range []jetstream.ConsumerConfig{
		topology.CiConsumer(), topology.CiRuntimeProofConsumer(), cellSpecConsumer, ciJobConsumer,
	} {
		if configuration.Name == "" || configuration.Durable != configuration.Name {
			t.Fatalf("global consumer is not durable: %#v", configuration)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, configuration := range topology.Streams() {
		if _, err := js.CreateStream(ctx, configuration); err != nil {
			t.Fatalf("create stream %s: %v", configuration.Name, err)
		}
	}
	for _, configuration := range []jetstream.KeyValueConfig{
		topology.Leaders(), topology.Cells(), topology.Releases(), topology.RunnerJobs(),
	} {
		if _, err := js.CreateKeyValue(ctx, configuration); err != nil {
			t.Fatalf("create KV %s: %v", configuration.Bucket, err)
		}
	}
	for _, configuration := range []jetstream.ObjectStoreConfig{
		topology.Bundles(), topology.RunnerBundles(),
	} {
		if _, err := js.CreateObjectStore(ctx, configuration); err != nil {
			t.Fatalf("create object store %s: %v", configuration.Bucket, err)
		}
	}
	ciStream, err := js.Stream(ctx, GlobalNatsTopologyCiStream)
	if err != nil {
		t.Fatal(err)
	}
	for _, configuration := range []jetstream.ConsumerConfig{
		topology.CiConsumer(), topology.CiRuntimeProofConsumer(),
	} {
		consumer, err := ciStream.CreateOrUpdateConsumer(ctx, configuration)
		if err != nil {
			t.Fatalf("create consumer %s: %v", configuration.Name, err)
		}
		info, err := consumer.Info(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !CiRunnerConsumerReconcilerMatches(info, configuration, GlobalNatsTopologyCiStream) {
			t.Fatalf("consumer %s normalized unexpectedly: actual=%#v expected=%#v",
				configuration.Name, info.Config, configuration)
		}
	}

	state, err := globalNatsRuntimeOpenAndValidate(ctx, client, topology, false, "gru")
	if err != nil {
		t.Fatalf("fully provisioned global topology rejected: %v", err)
	}
	if state.cells == nil || state.runnerBundles == nil || state.runtimeProof == nil {
		t.Fatal("fully provisioned global topology returned incomplete state")
	}

	cellsStream, err := js.Stream(ctx, "KV_"+GlobalNatsTopologyCellsBucket)
	if err != nil {
		t.Fatal(err)
	}
	info, err := cellsStream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	drifted := info.Config
	drifted.MaxBytes--
	if _, err := js.UpdateStream(ctx, drifted); err != nil {
		t.Fatalf("drift global cells KV: %v", err)
	}
	if _, err := globalNatsRuntimeOpenAndValidate(ctx, client, topology, false, "gru"); err == nil {
		t.Fatal("global runtime accepted a drifted global KV configuration")
	}
}

func TestGlobalNatsRuntimeConnectHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	configuration := &GlobalAuthorityNatsConfiguration{
		Url: "tls://127.0.0.1:1", Authentication: &NatsAuthenticationFiles{PublicKey: "UA"},
		Tls: &NatsTlsFiles{CaFile: "ca", CertificateFile: "authority", KeyFile: "key"}, Replicas: 3, Cell: "gru",
	}
	runtimeConfiguration := &GlobalNatsRuntimeConfiguration{Authority: configuration, Cell: "gru", Instance: "one"}
	_, err := GlobalNatsRuntimeStartAsync(ctx, runtimeConfiguration)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

type globalRuntimeTestComponent struct {
	done  chan struct{}
	close func()
}

func (c *globalRuntimeTestComponent) Completion() <-chan struct{} { return c.done }
func (c *globalRuntimeTestComponent) Close() error {
	if c.close != nil {
		c.close()
	}
	return nil
}

func TestGlobalNatsRuntimeCloseIsIdempotentAndReverseOrdered(t *testing.T) {
	order := []string{}
	ci := &globalRuntimeTestComponent{done: make(chan struct{}), close: func() { order = append(order, "ci") }}
	delivery := &globalRuntimeTestComponent{done: make(chan struct{}), close: func() { order = append(order, "delivery") }}
	runtime := &GlobalNatsRuntime{ciRuntime: ci, delivery: delivery, complete: make(chan struct{})}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "delivery" || order[1] != "ci" {
		t.Fatalf("close order = %#v", order)
	}
	select {
	case <-runtime.Completion():
	default:
		t.Fatal("completion did not close")
	}
}
