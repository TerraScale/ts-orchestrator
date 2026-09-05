package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

func TestControlConsumerPromotionPreservesDurableCheckpointAfterSourceLoss(t *testing.T) {
	cluster := newControlMutationStateCluster(t)
	nc := cluster.connect(t)
	kv := openControlMutationTestLeaseStore(t, t.Context(), nc, true)
	lease := controlMutationTestLease(7, "global-controller-gru-one")
	putControlMutationTestLease(t, t.Context(), kv, lease)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := messaging.NewGlobalNatsTopology(3)
	if err != nil {
		t.Fatal(err)
	}
	streamConfig := topology.Streams()[0]
	streamConfig.Replicas = 1
	stream, err := js.CreateStream(ctx, streamConfig)
	if err != nil {
		t.Fatal(err)
	}
	config, err := topology.CellSpecConsumer("gru")
	if err != nil {
		t.Fatal(err)
	}
	target := config
	config.Replicas = 1
	consumer, err := stream.CreateConsumer(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"acked", "pending"} {
		if _, err := js.Publish(ctx, config.FilterSubject, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := message.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Cluster == nil {
		t.Fatal("R1 cluster identity absent")
	}
	source := before.Cluster.Leader
	pins := []controlMutationPin{{store: "global", check: ControlStoreCheck{AuthorityID: "global", LeaseKey: "authority.global", AuthorityTerm: uint64(lease.Epoch), AuthorityCandidateID: lease.CandidateId, AuthorityLeaseID: lease.LeaseId, Streams: []ControlStreamAssignment{{Name: "GLOBAL_SPEC", Replicas: 3, Servers: []string{"controlMutation-0", "controlMutation-1", "controlMutation-2"}}}}}}
	update := ControlReplicaPlan{Store: "global", Streams: []string{streamConfig.Name}, Replicas: 3, Consumers: []ControlConsumerReplicaPlan{{Stream: streamConfig.Name, Config: target}}}
	if err := validateControlConsumerReplicas(update); err != nil {
		t.Fatal(err)
	}
	if err := updateControlReplicaStreams(ctx, js, update, pins); err != nil {
		t.Fatal(err)
	}
	if err := updateControlReplicaStreams(ctx, js, update, pins); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	after, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.AckFloor.Consumer != before.AckFloor.Consumer || after.AckFloor.Stream != before.AckFloor.Stream || !after.Created.Equal(before.Created) {
		t.Fatal("promotion reset checkpoint")
	}
	survivor := -1
	for i, server := range cluster.servers {
		if server.Name() == source {
			server.Shutdown()
			server.WaitForShutdown()
		} else {
			survivor = i
		}
	}
	if survivor < 0 {
		t.Fatal("no survivor")
	}
	live, err := nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", cluster.options[survivor].Port), nats.Secure(cluster.tls.Clone()), nats.Nkey(cluster.public, cluster.key.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1))
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	survivorJS, err := jetstream.New(live)
	if err != nil {
		t.Fatal(err)
	}
	var recovered jetstream.Consumer
	for ctx.Err() == nil {
		attempt, stopAttempt := context.WithTimeout(ctx, time.Second)
		recovered, err = survivorJS.Consumer(attempt, streamConfig.Name, config.Name)
		stopAttempt()
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := recovered.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.Replicas != 3 || info.AckFloor.Stream != before.AckFloor.Stream || info.AckFloor.Consumer != before.AckFloor.Consumer || !info.Created.Equal(before.Created) {
		t.Fatal("source loss reset durable checkpoint")
	}
	message, err = recovered.Next(jetstream.FetchMaxWait(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data()) != "pending" {
		t.Fatal("acked prefix replayed")
	}
	if err := message.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestControlConsumerPromotionDeclarationIsClosed(t *testing.T) {
	topology, _ := messaging.NewGlobalNatsTopology(3)
	config, _ := topology.CellSpecConsumer("gru")
	makePlan := func() ControlReplicaPlan {
		return ControlReplicaPlan{Store: "global", Streams: []string{"GLOBAL_SPEC"}, Replicas: 3, Consumers: []ControlConsumerReplicaPlan{{Stream: "GLOBAL_SPEC", Config: config}}}
	}
	for _, edit := range []func(*ControlReplicaPlan){
		func(p *ControlReplicaPlan) { p.Consumers = nil },
		func(p *ControlReplicaPlan) { p.Consumers[0].Stream = "FOREIGN" },
		func(p *ControlReplicaPlan) { p.Consumers[0].Config.Durable = "" },
		func(p *ControlReplicaPlan) { p.Consumers[0].Config.Replicas = 1 },
		func(p *ControlReplicaPlan) { p.Consumers = append(p.Consumers, p.Consumers[0]) },
	} {
		p := makePlan()
		edit(&p)
		if validateControlConsumerReplicas(p) == nil {
			t.Fatal("unadmitted consumer mutation accepted")
		}
	}
}

func TestControlConsumerPromotionFencesBetweenUpdatesAndRetry(t *testing.T) {
	r, nc, kv, lease, plan := mutationTestRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	topology, _ := messaging.NewGlobalNatsTopology(3)
	config := topology.Streams()[0]
	config.Replicas = 1
	stream, err := js.CreateStream(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	update := ControlReplicaPlan{Store: "target", Streams: []string{config.Name}, Replicas: 3}
	for _, cell := range []string{"gru", "sfo"} {
		c, _ := topology.CellSpecConsumer(cell)
		update.Consumers = append(update.Consumers, ControlConsumerReplicaPlan{Stream: config.Name, Config: c})
		c.Replicas = 1
		if _, err := stream.CreateConsumer(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	plan.ReplicaUpdates = []ControlReplicaPlan{update}
	plan.Checks[0].Streams = []ControlStreamAssignment{{Name: "GLOBAL_SPEC", Replicas: 3, Servers: []string{"controlMutation-0", "controlMutation-1", "controlMutation-2"}}}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	traced, err := jetstream.New(nc, jetstream.WithClientTrace(&jetstream.ClientTrace{ResponseReceived: func(subject string, _ []byte, _ nats.Header) {
		if strings.Contains(subject, "CONSUMER.CREATE.GLOBAL_SPEC.global_cell_spec_gru") && !changed {
			changed = true
			lease.LeaseId = "replacement-after-consumer"
			putControlMutationTestLease(t, ctx, kv, lease)
		}
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := updateControlReplicaStreams(ctx, traced, update, pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("replacement between consumers: %v", err)
	}
	if !changed {
		t.Fatal("actual consumer update was not observed")
	}
	second, err := js.Consumer(ctx, config.Name, "global_cell_spec_sfo")
	if err != nil {
		t.Fatal(err)
	}
	info, err := second.Info(ctx)
	if err != nil || info.Config.Replicas != 1 {
		t.Fatalf("unadmitted second update: %v", err)
	}
	if err := updateControlReplicaStreams(ctx, js, update, pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("replacement retry: %v", err)
	}
}

func TestControlConsumerInventoryMismatchRefusesBeforeStreamMutation(t *testing.T) {
	r, nc, _, _, plan := mutationTestRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	topology, _ := messaging.NewGlobalNatsTopology(3)
	cfg := topology.Streams()[0]
	cfg.Replicas = 1
	stream, err := js.CreateStream(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := topology.CellSpecConsumer("gru")
	original.Replicas = 1
	other, _ := topology.CellSpecConsumer("sfo")
	other.Replicas = 1
	for _, config := range []jetstream.ConsumerConfig{original, other} {
		if _, err := stream.CreateConsumer(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	plan.Checks[0].Streams = []ControlStreamAssignment{{Name: cfg.Name, Replicas: 3, Servers: []string{"controlMutation-0", "controlMutation-1", "controlMutation-2"}}}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		t.Fatal(err)
	}
	original.Replicas = 3
	other.Replicas = 3
	for _, declared := range [][]ControlConsumerReplicaPlan{
		{{Stream: cfg.Name, Config: other}},    // A different admitted consumer cannot hide the original.
		{{Stream: cfg.Name, Config: original}}, // Undeclared extra actual consumer must also refuse.
	} {
		update := ControlReplicaPlan{Store: "target", Streams: []string{cfg.Name}, Replicas: 3, Consumers: declared}
		if err := updateControlReplicaStreams(ctx, js, update, pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
			t.Fatalf("incomplete actual inventory: %v", err)
		}
		info, err := stream.Info(ctx)
		if err != nil || info.Config.Replicas != 1 {
			t.Fatal("inventory refusal mutated stream")
		}
	}
	if err := stream.DeleteConsumer(ctx, other.Name); err != nil {
		t.Fatal(err)
	}
	update := ControlReplicaPlan{Store: "target", Streams: []string{cfg.Name}, Replicas: 3, Consumers: []ControlConsumerReplicaPlan{{Stream: cfg.Name, Config: original}, {Stream: cfg.Name, Config: other}}}
	if err := updateControlReplicaStreams(ctx, js, update, pins); !errors.Is(err, ErrControlRuntimeUnavailable) {
		t.Fatalf("missing declared consumer: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil || info.Config.Replicas != 1 {
		t.Fatal("missing-consumer refusal mutated stream")
	}
}

func TestControlConsumerReplicaAssignmentRejectsForeignServer(t *testing.T) {
	servers := []string{"gru", "sfo", "fra"}
	valid := &jetstream.ClusterInfo{Leader: "gru", Replicas: []*jetstream.PeerInfo{{Name: "sfo", Current: true}, {Name: "fra", Current: true}}}
	if !controlConsumerReplicaAssignment(valid, servers) {
		t.Fatal("exact replica assignment refused")
	}
	valid.Replicas[1].Name = "foreign"
	if controlConsumerReplicaAssignment(valid, servers) {
		t.Fatal("foreign replica admitted by count")
	}
	valid.Replicas[1].Name = "sfo"
	if controlConsumerReplicaAssignment(valid, servers) {
		t.Fatal("duplicate replica admitted")
	}
}
