package natscell

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats.go/jetstream"
)

func TestObserveReportsEmbeddedJetStreamHealth(t *testing.T) {
	cfg := productionTestConfig(t, "lab", "one")
	cfg.Embedded.StoreMaxBytes = 1 << 30
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	runtime, err := openTestBroker(t, ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	stream, err := runtime.JetStream().CreateStream(ctx, jetstream.StreamConfig{
		Name: "LAB_OBSERVED", Subjects: []string{"lab.observed"}, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := runtime.JetStream().Publish(ctx, "lab.observed", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{Durable: "LAB_WORKER",
		AckPolicy: jetstream.AckExplicitPolicy}); err != nil {
		t.Fatal(err)
	}
	view, err := runtime.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.ServerName != "lab-one" || view.Connections < 1 || !view.IsMetaLeader || view.ClusterPeers != 1 ||
		view.StoreLimitBytes != 1<<30 || view.StoreUsedBytes == 0 {
		t.Fatalf("view = %+v", view)
	}
	index := slices.IndexFunc(view.Streams, func(stream observability.StreamView) bool { return stream.Name == "LAB_OBSERVED" })
	if index < 0 || view.Streams[index].Messages != 3 || view.Streams[index].Replicas != 1 {
		t.Fatalf("streams = %+v", view.Streams)
	}
	consumer := slices.IndexFunc(view.Consumers, func(consumer observability.ConsumerView) bool { return consumer.Name == "LAB_WORKER" })
	if consumer < 0 || view.Consumers[consumer].NumPending != 3 || view.Consumers[consumer].Stream != "LAB_OBSERVED" {
		t.Fatalf("consumers = %+v", view.Consumers)
	}
	var stopped *Runtime
	if _, err := stopped.Observe(ctx); err == nil {
		t.Fatal("a nil runtime reported NATS health")
	}
}

func TestObservabilityTelemetryIsControllerOnly(t *testing.T) {
	public, _ := newUserIdentity(t)
	controller, err := userPermissions("lab", NKeyGrant{PublicKey: public, Role: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(controller.Subscribe.Allow, "ts.orch.v1.lab.obs.>") {
		t.Fatal("controller cannot answer observability snapshot requests")
	}
	operator, err := userPermissions("lab", NKeyGrant{PublicKey: public, Role: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(operator.Publish.Allow, "ts.orch.v1.lab.obs.snapshot") || slices.Contains(BrokerOperatorPublishPermissions("lab"), "ts.orch.v1.lab.obs.>") {
		t.Fatal("operator may request member telemetry")
	}
}
