//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestLocalManagementObservationIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := (*Node)(nil).LocalManagementObservation(ctx, "test"); err == nil {
		t.Fatal("nil manager acquired local observation")
	}
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region = "sa-saopaulo-1"
	node := nodeFixtureStart(t, ctx, cfg)
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.LocalManagementObservation(ctx, "test"); err == nil {
		t.Fatal("manager without accepted region identity acquired observation")
	}
	if _, err := node.ReadOnlyControlClient(ctx); err == nil {
		t.Fatal("manager without accepted region identity acquired readonly control")
	}
	if _, err := AdmitNode(ctx, client, node.ID(), cfg.Admission); err != nil {
		t.Fatal(err)
	}
	if _, err := node.LocalManagementObservation(ctx, ""); err == nil {
		t.Fatal("empty environment acquired local observation")
	}
	observer, err := node.LocalManagementObservation(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	originalReader, err := node.ReadOnlyControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateSecret(ctx, &api.CreateSecretRequest{Spec: &api.SecretSpec{Annotations: api.Annotations{Name: "local-private"}, Data: []byte("test-only")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: "foreign"}, Data: []byte("outside-scope")}}); err != nil {
		t.Fatal(err)
	}
	liveCtx, stopLive := context.WithCancel(ctx)
	defer stopLive()
	live, err := observer.Observe(liveCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := live.Recv()
	if err != nil || initial.Snapshot == nil || initial.Cursor.NodeID != node.ID() || len(initial.Snapshot.Nodes) != 1 || len(initial.Snapshot.Secrets)+len(initial.Snapshot.Configs)+len(initial.Snapshot.Clusters)+len(initial.Snapshot.Networks)+len(initial.Snapshot.Volumes) != 0 {
		t.Fatalf("local scoped snapshot differs from real manager: %+v %v", initial, err)
	}
	if ready, err := live.Recv(); err != nil || ready.ReplayThrough == nil || ready.ReplayThrough.Index != initial.Cursor.Version {
		t.Fatalf("local quiet snapshot has no exact through: %+v %v", ready, err)
	}
	digest := sha256.Sum256([]byte("test/sa-saopaulo-1/api"))
	spec := &api.ConfigSpec{Annotations: api.Annotations{Name: fmt.Sprintf("ts-release-%x", digest[:16]), Labels: map[string]string{
		LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: cfg.Admission.Region, LabelEnvironment: "test", "terrascale.release-sequence": "2",
	}}, Data: []byte("local-test-floor")}
	created, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: created.Config.ID}); err != nil {
		t.Fatal(err)
	}
	actions := map[api.WatchActionKind]int{}
	for actions[api.WatchActionKindRemove] == 0 {
		message, err := live.Recv()
		if err != nil || message.Transaction == nil {
			t.Fatalf("local live transaction unavailable: %+v %v", message, err)
		}
		for _, event := range message.Transaction.Events {
			if config := event.Object.GetConfig(); config != nil && config.ID == created.Config.ID {
				actions[event.Action]++
			}
		}
	}
	if actions[api.WatchActionKindCreate] != 1 || actions[api.WatchActionKindRemove] != 1 {
		t.Fatalf("local live stream lost or duplicated changes: %v", actions)
	}
	stopLive()
	resumeCtx, stopResume := context.WithCancel(ctx)
	defer stopResume()
	resumed, err := observer.Observe(resumeCtx, &initial.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint, err := resumed.Recv(); err != nil || endpoint.Snapshot == nil || len(endpoint.Snapshot.Configs) != 0 {
		t.Fatalf("local resume endpoint: %+v %v", endpoint, err)
	}
	actions = map[api.WatchActionKind]int{}
	for {
		message, err := resumed.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if message.ReplayThrough != nil {
			break
		}
		if message.Transaction == nil {
			t.Fatal("local replay has no transaction")
		}
		for _, event := range message.Transaction.Events {
			if config := event.Object.GetConfig(); config != nil && config.ID == created.Config.ID {
				actions[event.Action]++
			}
		}
	}
	if actions[api.WatchActionKindCreate] != 1 || actions[api.WatchActionKindRemove] != 1 {
		t.Fatalf("equal local snapshots hid changes: %v", actions)
	}
	stopResume()
	drifted, err := observer.Observe(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Recv(); err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Recv(); err != nil {
		t.Fatal(err)
	}
	self, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil {
		t.Fatal(err)
	}
	original := self.Node.Spec.Copy()
	changed := original.Copy()
	changed.Annotations.Labels[LabelInstanceID] = "different-instance"
	updated, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID(), NodeVersion: &self.Node.Meta.Version, Spec: changed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Recv(); err == nil {
		t.Fatal("local source continued through admitted manager identity drift")
	}
	if _, err := node.LocalManagementObservation(ctx, "test"); err == nil {
		t.Fatal("new observer adopted identity different from original Node admission")
	}
	if _, err := originalReader.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()}); err == nil {
		t.Fatal("readonly source continued through admitted manager identity drift")
	}
	if _, err := node.ReadOnlyControlClient(ctx); err == nil {
		t.Fatal("new readonly source adopted changed manager identity")
	}
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID(), NodeVersion: &updated.Node.Meta.Version, Spec: original}); err != nil {
		t.Fatal(err)
	}
	reader := testLocalControlSocketIndependence(t, ctx, node, client)
	if _, err := node.LocalManagementObservation(ctx, "test"); err != nil {
		t.Fatalf("new local observer depended on closed socket: %v", err)
	}
	stalled, err := observer.Observe(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := stalled.stream.(*localManagementObservationStream)
	nodeFixtureStop(t, node)
	select {
	case <-local.done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopped manager retained local source or blocked sender")
	}
	if _, err := stalled.Recv(); err == nil {
		t.Fatal("stopped local source delivered buffered observation as valid")
	}
	if _, err := reader.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()}); err == nil {
		t.Fatal("readonly source survived original manager lifetime")
	}
	if _, err := reader.ClusterIdentity(ctx); err == nil {
		t.Fatal("readonly cluster identity survived original manager lifetime")
	}
	if _, err := observer.Observe(ctx, nil); err == nil {
		t.Fatal("local observer survived original manager lifetime")
	}
}
