package integration

import (
	"context"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
)

func TestRegionalDeploymentFenceKeepsR3PeersConnected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cluster := newRegionalCluster(t, ctx)
	if err := cluster.startAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cluster.waitForPeers(ctx); err != nil {
		t.Fatal(err)
	}
	config := authority.Config{Scope: "r3-integration", DeploymentID: entityid.Derive("test-deployment", "r3"),
		CandidateID: entityid.Derive("test-controller", "original"), Replicas: regionalPeers}
	leader, err := startAuthorityWithRetry(ctx, cluster.nodes[0].JetStream(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leader.Close() })
	if err := leader.Close(); err != nil {
		t.Fatal(err)
	}
	js := cluster.nodes[0].JetStream()
	stream, err := js.Stream(ctx, authority.ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	subject := "ts.control.r3-integration.lease"
	entry, err := stream.GetLastMsgForSubject(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	var lease map[string]any
	if err := json.Unmarshal(entry.Data, &lease); err != nil {
		t.Fatal(err)
	}
	for _, deploymentID := range []string{"", entityid.Derive("test-deployment", "foreign")} {
		lease["deployment_id"] = deploymentID
		if deploymentID == "" {
			delete(lease, "deployment_id")
		}
		wire, err := json.Marshal(lease)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(ctx, subject, wire, jetstream.WithExpectLastSequence(entry.Sequence))
		if err != nil {
			t.Fatal(err)
		}
		for i, node := range cluster.nodes {
			config.CandidateID = entityid.Derive("test-controller", cluster.configs[i].Instance)
			fenced, err := startAuthorityWithRetry(ctx, node.JetStream(), config)
			if err != nil {
				t.Fatalf("start fenced peer %d: %v", i, err)
			}
			if current := fenced.Current(); current.Ready || current.CanMutate() {
				t.Fatalf("peer %d admitted deployment %q: %+v", i, deploymentID, current)
			}
			if !node.Ready() || !node.Conn().IsConnected() || !node.FullClusterReady(regionalPeers) {
				t.Fatalf("authority fence disconnected embedded peer %d", i)
			}
			if err := fenced.Close(); err != nil {
				t.Fatal(err)
			}
		}
		info, err := stream.Info(ctx)
		if err != nil || info.State.LastSeq != ack.Sequence {
			t.Fatalf("fenced peers changed the control log: %+v, %v", info, err)
		}
		entry, err = stream.GetLastMsgForSubject(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
	}
}
