package mesh

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutmaintenance"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

type bootstrapApplierFixture struct{ fakeApplier }

func (*bootstrapApplierFixture) ReadyWorkers(context.Context) (map[string]bool, error) {
	return map[string]bool{"gru-2": true}, nil
}

func TestBootstrapStagesOnlyTheRetainedReleaseWithBothExactFences(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	state := t.TempDir()
	store, err := rolloutmaintenance.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := DeriveCA(bytes.Repeat([]byte{57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2)
	applier := &bootstrapApplierFixture{fakeApplier{running: map[string]int64{}}}
	n, err := start(config{region: "gru", server: "gru-1", dir: state, clusterHost: "127.0.0.1", clusterPort: ports[0], localPort: ports[1], ca: ca, terrabaseToken: testTerraBaseToken,
		applier: applier, maintenance: store, peersDir: t.TempDir(), peersEvery: 20 * time.Millisecond, address: func() (string, error) { return "10.200.0.1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	spec := swarmruntime.ServiceSpec{Name: "terrabase", Image: "ghcr.io/terrascale/terrabase@sha256:" + strings.Repeat("a", 64), Port: 8090, ReadyPath: "/readyz", Replicas: 2, MilliCPU: 500, MemoryMiB: 2048}
	if _, err := n.apply(ctx, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 10, Spec: &spec}}); err != nil {
		t.Fatal(err)
	}
	image := repository(spec.Image) + "@sha256:" + strings.Repeat("c", 64)
	j := rolloutmaintenance.Job{ID: "gru-owner", Member: "gru-1", Owner: "gru-1", Epoch: 7,
		Source: rolloutmaintenance.Pin{Node: "node1", Service: "terrabase", Task: "old1", Fingerprint: strings.Repeat("a", 64), Image: spec.Image},
		Target: rolloutmaintenance.Pin{Node: "node1", Service: "terrabase", Image: image}, Process: rolloutmaintenance.Process{PID: 1, Start: 1}}
	if err := store.Arm(ctx, j); err != nil {
		t.Fatal(err)
	}
	retained, err := store.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	j = *retained
	// The real protected NATS handler answers the founder. A contract peer
	// represents the worker's durable fence; its missing/mismatched answers
	// must prevent publication before the normal applier sees any candidate.
	var workerMu sync.Mutex
	var workerJob *rolloutmaintenance.Job
	sub, err := n.conn.Subscribe(protocol.MeshDrainPrefix+"gru.gru-2.fence", func(m *nats.Msg) {
		workerMu.Lock()
		defer workerMu.Unlock()
		n.respond(m, bootstrapFenceReply{Job: workerJob})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := n.conn.FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	n.recordWorker(&nats.Msg{Data: []byte(`{"node":"gru-2","address":"10.200.0.2"}`)})
	n.setJoined(ctx)
	if len(n.RegionalNodes()) != 2 {
		t.Fatal("worker was not admitted")
	}
	claims := releasepush.Claims{Repository: "TerraScale/terrascale", RunID: "100", RunAttempt: "1", SHA: strings.Repeat("b", 40)}
	if body, err := Release(state)(ctx, "terrabase", image, claims, unreported{}); err != nil || !strings.Contains(string(body), `"held":true`) {
		t.Fatalf("authenticated release was not retained: %s %v", body, err)
	}
	if applier.appliedImage("terrabase") != spec.Image {
		t.Fatal("retaining the release published an intent")
	}
	if err := n.stageBootstrap("stage", j); err == nil {
		t.Fatal("missing worker fence admitted publication")
	}
	worker := j
	worker.ID, worker.Member = "gru-follower", "gru-2"
	worker.Source.Node, worker.Target.Node, worker.Source.Task = "node2", "node2", "old2"
	worker.Epoch++
	workerMu.Lock()
	workerJob = &worker
	workerMu.Unlock()
	if err := n.stageBootstrap("stage", j); err == nil {
		t.Fatal("mismatched worker epoch admitted publication")
	}
	workerMu.Lock()
	matched := worker
	matched.Epoch = j.Epoch
	workerJob = &matched
	workerMu.Unlock()
	if err := n.stageBootstrap("stage", j); err != nil {
		t.Fatal(err)
	}
	if err := n.stageBootstrap("staged", j); err != nil {
		t.Fatal(err)
	}
	if applier.appliedImage("terrabase") != image {
		t.Fatal("exact candidate was not applied through normal admission")
	}
	// The private staging context is not retained in an ordinary replay.
	n.mu.Lock()
	_, err = n.reconcile(ctx, "terrabase", n.desired["terrabase"])
	n.mu.Unlock()
	if err == nil {
		t.Fatal("ordinary reconcile escaped the retained fence")
	}
	t.Log(fmt.Sprintf("retained_release=%s missing_peer_fenced=true wrong_epoch_fenced=true normal_replay_fenced=true", image))
}
