package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
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
		diagnostic, stopDiagnostic := context.WithTimeout(t.Context(), 3*time.Second)
		defer stopDiagnostic()
		if info, readErr := stream.Info(diagnostic); readErr == nil {
			cluster, _ := json.Marshal(info.Cluster)
			t.Logf("stream replicas=%d cluster=%s", info.Config.Replicas, cluster)
		} else {
			t.Logf("stream observation: %v", readErr)
		}
		if info, readErr := consumer.Info(diagnostic); readErr == nil {
			cluster, _ := json.Marshal(info.Cluster)
			t.Logf("consumer replicas=%d created=%s ack=%+v delivered=%+v cluster=%s", info.Config.Replicas, info.Created, info.AckFloor, info.Delivered, cluster)
		} else {
			t.Logf("consumer observation: %v", readErr)
		}
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

func TestControlConsumerPromotionWaitsForStreamReplicasBeforeConsumerEffect(t *testing.T) {
	t.Run("resume-after-lost-observation", func(t *testing.T) { testControlConsumerStreamReadiness(t, false) })
	t.Run("lease-replaced-after-lost-observation", func(t *testing.T) { testControlConsumerStreamReadiness(t, true) })
}

func testControlConsumerStreamReadiness(t *testing.T, replaceLease bool) {
	t.Helper()
	cluster := newControlMutationStateCluster(t)
	nc := cluster.connect(t)
	kv := openControlMutationTestLeaseStore(t, t.Context(), nc, true)
	lease := controlMutationTestLease(7, "global-controller-gru-one")
	putControlMutationTestLease(t, t.Context(), kv, lease)
	// This verifies ordering and retained state, not a ten-second SLO. NATS
	// elections use 4–9s timers and promotion forms two successive Raft groups.
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	topology, _ := messaging.NewGlobalNatsTopology(3)
	streamConfig := topology.Streams()[0]
	streamConfig.Replicas = 1
	stream, err := js.CreateStream(ctx, streamConfig)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := topology.CellSpecConsumer("gru")
	target := config
	config.Replicas = 1
	consumer, err := stream.CreateConsumer(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, config.FilterSubject, []byte("acknowledged before promotion")); err != nil {
		t.Fatal(err)
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := message.DoubleAck(ctx); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pins := []controlMutationPin{{store: "global", check: ControlStoreCheck{AuthorityID: "global", LeaseKey: "authority.global", AuthorityTerm: uint64(lease.Epoch), AuthorityCandidateID: lease.CandidateId, AuthorityLeaseID: lease.LeaseId, Streams: []ControlStreamAssignment{{Name: "GLOBAL_SPEC", Replicas: 3, Servers: []string{"controlMutation-0", "controlMutation-1", "controlMutation-2"}}}}}}
	update := ControlReplicaPlan{Store: "global", Streams: []string{streamConfig.Name}, Replicas: 3, Consumers: []ControlConsumerReplicaPlan{{Stream: streamConfig.Name, Config: target}}}
	// Keep the actual broker and all updates, but withhold one replica's
	// current observation until the caller has demonstrably checked it.
	// This controls the observation order without racing a wall-clock sleep.
	observed := &withheldStreamReadiness{JetStream: js, waiting: make(chan struct{}, 1), consumerEffect: make(chan struct{}, 1)}
	if replaceLease {
		observed.afterLostObservation = func() {
			lease.LeaseId = "replacement-after-lost-observation"
			putControlMutationTestLease(t, t.Context(), kv, lease)
		}
	}
	observed.hold.Store(true)
	promotionStarted := time.Now()
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		done <- updateControlReplicaStreams(ctx, observed, update, pins)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("promotion did not stop after cancellation")
		}
		if updates := observed.consumerUpdates.Load(); updates != 1 {
			t.Errorf("consumer update count=%d, want exactly one", updates)
		}
	})
	select {
	case <-observed.waiting:
	case <-observed.consumerEffect:
		t.Fatal("consumer update began before all declared stream peers were current")
	case err := <-done:
		t.Fatalf("promotion stopped before consulting stream readiness: %v", err)
	case <-ctx.Done():
		t.Fatal("promotion did not consult stream readiness")
	}
	select {
	case <-observed.consumerEffect:
		t.Fatal("consumer update began while stream readiness was withheld")
	default:
	}
	blocked, err := consumer.Info(ctx)
	if err != nil || blocked.Config.Replicas != 1 || blocked.AckFloor.Consumer != checkpoint.AckFloor.Consumer || blocked.AckFloor.Stream != checkpoint.AckFloor.Stream {
		t.Fatalf("consumer changed while stream readiness was withheld: %+v %v", blocked, err)
	}
	observed.hold.Store(false)
	releasedAt := time.Now()
	select {
	case err := <-done:
		if replaceLease {
			if !errors.Is(err, ErrControlRuntimeUnavailable) {
				t.Fatalf("replacement lease allowed another readiness read: %v", err)
			}
			if observed.resumedReads.Load() != 0 {
				t.Fatal("readiness read resumed after the admitted lease changed")
			}
			return
		}
		if err != nil {
			logControlPromotionState(t, stream, consumer)
			t.Fatal(err)
		}
	case <-ctx.Done():
		// Cancellation can win this select while the producer is returning
		// the error that identifies the failed RPC or replica wait.
		var result error
		select {
		case result = <-done:
		case <-time.After(3 * time.Second):
			result = errors.New("promotion did not return after cancellation")
		}
		logControlPromotionState(t, stream, consumer)
		t.Fatalf("promotion did not resume after readiness release: total=%s after-release=%s result=%v context=%v", time.Since(promotionStarted), time.Since(releasedAt), result, ctx.Err())
	}
	select {
	case <-observed.consumerEffect:
	default:
		t.Fatal("promotion never updated the real consumer")
	}
	promoted, err := consumer.Info(ctx)
	if err != nil || promoted.Config.Replicas != 3 || !promoted.Created.Equal(checkpoint.Created) || promoted.AckFloor.Consumer != checkpoint.AckFloor.Consumer || promoted.AckFloor.Stream != checkpoint.AckFloor.Stream || promoted.Delivered.Consumer != checkpoint.Delivered.Consumer || promoted.Delivered.Stream != checkpoint.Delivered.Stream {
		t.Fatalf("promotion changed the retained consumer checkpoint: %+v %v", promoted, err)
	}
}

func logControlPromotionState(t *testing.T, stream jetstream.Stream, consumer jetstream.Consumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if info, err := stream.Info(ctx); err == nil {
		cluster, _ := json.Marshal(info.Cluster)
		t.Logf("fresh stream replicas=%d cluster=%s", info.Config.Replicas, cluster)
	} else {
		t.Logf("fresh stream observation: %v", err)
	}
	if info, err := consumer.Info(ctx); err == nil {
		cluster, _ := json.Marshal(info.Cluster)
		t.Logf("fresh consumer replicas=%d created=%s ack=%+v delivered=%+v cluster=%s", info.Config.Replicas, info.Created, info.AckFloor, info.Delivered, cluster)
	} else {
		t.Logf("fresh consumer observation: %v", err)
	}
}

type withheldStreamReadiness struct {
	jetstream.JetStream
	hold                    atomic.Bool
	waiting, consumerEffect chan struct{}
	afterLostObservation    func()
	resumedReads            atomic.Int32
	consumerUpdates         atomic.Int32
}

func (w *withheldStreamReadiness) Stream(ctx context.Context, name string) (jetstream.Stream, error) {
	stream, err := w.JetStream.Stream(ctx, name)
	if err != nil {
		return nil, err
	}
	return withheldStreamObservation{Stream: stream, owner: w}, nil
}

func (w *withheldStreamReadiness) UpdateConsumer(ctx context.Context, stream string, config jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	w.consumerUpdates.Add(1)
	select {
	case w.consumerEffect <- struct{}{}:
	default:
	}
	consumer, err := w.JetStream.UpdateConsumer(ctx, stream, config)
	if err != nil {
		return nil, err
	}
	return &unansweredFirstConsumerObservation{Consumer: consumer, owner: w}, nil
}

// A consumer-info request sent during election can go unanswered despite
// subsequent healthy leadership. The production poll must retry a bounded
// read while its original action context and authority lease remain valid.
type unansweredFirstConsumerObservation struct {
	jetstream.Consumer
	dropped atomic.Bool
	owner   *withheldStreamReadiness
}

func (c *unansweredFirstConsumerObservation) Info(ctx context.Context) (*jetstream.ConsumerInfo, error) {
	if c.dropped.CompareAndSwap(false, true) {
		<-ctx.Done()
		if c.owner.afterLostObservation != nil {
			c.owner.afterLostObservation()
		}
		return nil, ctx.Err()
	}
	c.owner.resumedReads.Add(1)
	return c.Consumer.Info(ctx)
}

type withheldStreamObservation struct {
	jetstream.Stream
	owner *withheldStreamReadiness
}

func (w withheldStreamObservation) Info(ctx context.Context, opts ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
	info, err := w.Stream.Info(ctx, opts...)
	if err != nil || info.Config.Replicas != 3 || info.Cluster == nil || len(info.Cluster.Replicas) == 0 || !w.owner.hold.Load() {
		return info, err
	}
	// A detached observation avoids changing nats.go's cached response.
	copyInfo := *info
	copyCluster := *info.Cluster
	copyCluster.Replicas = append([]*jetstream.PeerInfo(nil), info.Cluster.Replicas...)
	copyPeer := *copyCluster.Replicas[0]
	copyPeer.Current = false
	copyCluster.Replicas[0] = &copyPeer
	copyInfo.Cluster = &copyCluster
	select {
	case w.owner.waiting <- struct{}{}:
	default:
	}
	return &copyInfo, nil
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
