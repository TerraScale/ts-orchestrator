package placement

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/lifecycle"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestVolumeDeadlineJetStreamControllerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "js")})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	nc, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := authority.Start(ctx, js, authority.Config{Scope: "gru", Replicas: 1, DeploymentID: entityid.Derive("deployment", t.Name()), CandidateID: entityid.Derive("candidate", t.Name())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fence.Close() })
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fence.CommitPlacementIntent(ctx, fence.Current().Epoch, intent.DatabaseID, intent.PartitionID, intent.OperationID(), 0, payload); err != nil {
		t.Fatal(err)
	}
	reader, err := NewAuthorityIntentReader(fence, "gru", oci.RegionGRU)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewJetStreamStore(ctx, js, "gru", 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	for _, member := range newPlacementMemoryStore(t, intent).members {
		state := member.State
		state.Stage, state.UpdatedAt, state.AttachRequestedAt = StageAwaitingAttach, base, base
		if _, err := store.CompareAndSwap(ctx, 0, state); err != nil {
			t.Fatal(err)
		}
	}
	instances := attachedInstances(t, intent)
	for i := range instances {
		instances[i].Attachments[0].State = "ATTACHING"
	}
	fleet := &placementTestFleet{instances: instances}
	hosts := &placementTestHosts{statuses: admittedStatuses(t, intent)}
	var holds []string
	controller := startTestPlacementController(t, store, fleet, hosts, func(reason string) { holds = append(holds, reason) })
	controller.fencer = fence
	assertWaiting := func(now time.Time, wantStuck bool) {
		t.Helper()
		before, err := controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			t.Fatal(err)
		}
		controller.now = func() time.Time { return now }
		holds = nil
		if err := controller.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		stuck := false
		for _, reason := range holds {
			stuck = stuck || strings.Contains(reason, "stuck ATTACHING") && strings.Contains(reason, "force-detach-retry")
		}
		if stuck != wantStuck {
			t.Fatalf("stalled attachment=%t, want %t: %v", stuck, wantStuck, holds)
		}
		after, err := controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("reobservation reset durable deadline or member revision: before=%+v after=%+v err=%v", before, after, err)
		}
		if fleet.attachCalls+fleet.cordonCalls+fleet.terminateCalls+fleet.ensureCalls+fleet.volumeCalls+hosts.desiredWrites != 0 {
			t.Fatal("attachment timeout authorized a cloud or workload effect")
		}
	}
	assertWaiting(base.Add(9*time.Minute), false)
	assertWaiting(base.Add(10*time.Minute), true)
	// Open an independent client/store; the waiting phase must retain its deadline.
	reopened, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	otherJS, err := jetstream.New(reopened)
	if err != nil {
		t.Fatal(err)
	}
	controller.store, err = NewJetStreamStore(ctx, otherJS, "gru", 1, reader)
	if err != nil {
		t.Fatal(err)
	}
	assertWaiting(base.Add(11*time.Minute), true)
	for _, skew := range []time.Duration{2 * time.Minute, 30 * time.Second} {
		members, err := controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range members {
			state := member.State
			state.AttachRequestedAt = base.Add(skew)
			if _, err := controller.store.CompareAndSwap(ctx, member.Revision, state); err != nil {
				t.Fatal(err)
			}
		}
		assertWaiting(base, skew > time.Minute)
	}
	for _, invalid := range []lifecycle.Deadlines{{Attaching: -time.Second}, {Deleting: 48 * time.Hour}, {MaxAttachRetries: 11}} {
		config := controller.config
		config.VolumeDeadlines = invalid
		if _, err := StartController(ctx, config, store, fence, fleet, hosts, hosts, controller.resolveArtifact); err == nil {
			t.Fatalf("invalid lifecycle policy admitted by actual controller: %+v", invalid)
		}
	}
	controller.config.VolumeDeadlines.Attaching = time.Minute
	assertWaiting(base.Add(2*time.Minute), true)
	members, err := controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	invalid := members[0].State
	invalid.UpdatedAt = time.Time{}
	if _, err := controller.store.CompareAndSwap(ctx, members[0].Revision, invalid); err == nil {
		t.Fatal("missing phase start entered durable production member state")
	}
	// A late positive OCI observation records progress instead of timing out again.
	for i := range fleet.instances {
		fleet.instances[i].Attachments[0].State = "ATTACHED"
	}
	for range len(fleet.instances) {
		if err := controller.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	members, err = controller.store.ListMembers(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		if member.State.Stage != StageAwaitingRuntimeContract || !member.State.AttachRequestedAt.IsZero() || member.State.HostAttempt != 1 {
			t.Fatalf("late attachment did not preserve the host and advance durable state: %+v", member)
		}
	}
	assertWaiting(base.Add(1000*time.Hour), false)
}
