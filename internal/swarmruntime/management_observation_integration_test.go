//go:build linux

package swarmruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Real persistent Raft and the authenticated Unix stream cover both sides of
// the snapshot/watch handoff; no executor, native runtime or provider is used.
func TestManagementObservationIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cfg := nodeFixtureConfig(t, "founder", "manager")
	cfg.Admission.Region = "sa-saopaulo-1"
	node := nodeFixtureStart(t, ctx, cfg)
	upstream, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cgroupWire, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.Split(strings.TrimSpace(string(cgroupWire)), "\n")[0], ":", 3)
	if len(parts) != 3 {
		t.Fatal("missing process cgroup")
	}
	path := filepath.Join(t.TempDir(), "observation.sock")
	var revoked atomic.Bool
	refresh := func(context.Context) error {
		if revoked.Load() {
			return errors.New("revoked current authority")
		}
		return nil
	}
	server, err := startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), parts[2], "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	_, _, conn, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "accepted-current")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	observer := ManagementObservationClient{conn: conn}
	wrong, err := observer.Observe(metadata.AppendToOutgoingContext(ctx, managementBinding, "wrong-accepted-identity"), nil)
	if err == nil {
		_, err = wrong.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stream accepted the wrong binding: %v", err)
	}
	broad, err := api.NewWatchClient(conn).Watch(ctx, &api.WatchRequest{})
	if err == nil {
		_, err = broad.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unrestricted upstream Watch became reachable: %v", err)
	}
	if _, err := upstream.CreateSecret(ctx, &api.CreateSecretRequest{Spec: &api.SecretSpec{Annotations: api.Annotations{Name: "observation-private-proof"}, Data: []byte("test-only-private-proof")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: "foreign-config"}, Data: []byte("outside-scope")}}); err != nil {
		t.Fatal(err)
	}
	liveCtx, stopLive := context.WithCancel(ctx)
	defer stopLive()
	live, err := observer.Observe(liveCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := live.Recv()
	if err != nil || initial.Snapshot == nil || len(initial.Snapshot.Nodes) != 1 || initial.Cursor.NodeID != node.ID() || len(initial.Snapshot.Clusters)+len(initial.Snapshot.Secrets)+len(initial.Snapshot.Networks)+len(initial.Snapshot.Volumes)+len(initial.Snapshot.Configs) != 0 {
		t.Fatalf("atomic scoped snapshot: %+v %v", initial, err)
	}
	ready, err := live.Recv()
	if err != nil || ready.ReplayThrough == nil || ready.ReplayThrough.Index != initial.Cursor.Version {
		t.Fatalf("quiet initial replay-through handshake: %+v %v", ready, err)
	}
	// The first subscription is already captured before these commits. Its
	// snapshot has no config and the later snapshot has no config either.
	identity := sha256.Sum256([]byte("test/sa-saopaulo-1/api"))
	spec := &api.ConfigSpec{Annotations: api.Annotations{Name: fmt.Sprintf("ts-release-%x", identity[:16]), Labels: map[string]string{
		LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", LabelRole: "api", LabelRegion: "sa-saopaulo-1", LabelEnvironment: "test",
		"terrascale.release-sequence": "2", "terrascale.release-fingerprint": "signed-release",
	}}, Data: []byte("signed-floor")}
	created, err := upstream.CreateConfig(ctx, &api.CreateConfigRequest{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	changed := spec.Copy()
	changed.Annotations.Labels["terrascale.release-sequence"] = "3"
	if _, err := upstream.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: created.Config.ID, ConfigVersion: &created.Config.Meta.Version, Spec: changed}); err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: created.Config.ID}); err != nil {
		t.Fatal(err)
	}
	liveActions := map[api.WatchActionKind]int{}
	for liveActions[api.WatchActionKindRemove] == 0 {
		message, err := live.Recv()
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range message.Transaction.Events {
			if config := event.Object.GetConfig(); config != nil && config.ID == created.Config.ID {
				liveActions[event.Action]++
				if event.Action == api.WatchActionKindUpdate && (event.OldObject.GetConfig() == nil || event.OldObject.GetConfig().Spec.Annotations.Labels["terrascale.release-sequence"] != "2") {
					t.Fatal("live config update lost its actual old object")
				}
			}
		}
	}
	for _, action := range []api.WatchActionKind{api.WatchActionKindCreate, api.WatchActionKindUpdate, api.WatchActionKindRemove} {
		if liveActions[action] != 1 {
			t.Fatalf("live handoff lost or duplicated action %v: %v", action, liveActions)
		}
	}
	stopLive()
	resumeCtx, stopResume := context.WithCancel(ctx)
	defer stopResume()
	resumed, err := observer.Observe(resumeCtx, &initial.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resumed.Recv()
	if err != nil || endpoint.Snapshot == nil || len(endpoint.Snapshot.Configs) != 0 {
		t.Fatalf("resumed endpoint snapshot: %+v %v", endpoint, err)
	}
	replayed := map[api.WatchActionKind]int{}
	var through ManagementObservationCursor
	for {
		message, err := resumed.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if message.ReplayThrough != nil {
			through = message.Cursor
			break
		}
		for _, event := range message.Transaction.Events {
			if config := event.Object.GetConfig(); config != nil && config.ID == created.Config.ID {
				replayed[event.Action]++
				if event.Action == api.WatchActionKindUpdate && event.OldObject != nil {
					t.Fatal("WAL replay invented an unavailable old object")
				}
			}
		}
	}
	for _, action := range []api.WatchActionKind{api.WatchActionKindCreate, api.WatchActionKindUpdate, api.WatchActionKindRemove} {
		if replayed[action] != 1 {
			t.Fatalf("identical snapshots hid intervening action %v: %v", action, replayed)
		}
	}
	stopResume()
	// A same-source quiet resume must explicitly reach its selected watermark.
	quietCtx, stopQuiet := context.WithCancel(ctx)
	quiet, err := observer.Observe(quietCtx, &through)
	if err != nil {
		t.Fatal(err)
	}
	if first, err := quiet.Recv(); err != nil || first.Snapshot == nil {
		t.Fatalf("quiet resume snapshot: %v", err)
	}
	for {
		message, err := quiet.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if message.ReplayThrough != nil {
			through = message.Cursor
			break
		}
		for _, event := range message.Transaction.Events {
			if event.Object.GetConfig() != nil {
				t.Fatal("quiet resume replayed an already delivered config action")
			}
		}
	}
	stopQuiet()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	nodeFixtureStop(t, node)
	node = nodeFixtureStart(t, ctx, cfg)
	upstream, err = node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server, err = startManagementAt(ctx, path, uint32(os.Getuid()), uint32(os.Getgid()), parts[2], "accepted-current", node, "sa-saopaulo-1", "test", upstream, refresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, restartedConn, err := dialManagementAt(ctx, path, uint32(os.Getuid()), "accepted-current")
	if err != nil {
		t.Fatal(err)
	}
	defer restartedConn.Close()
	restarted := ManagementObservationClient{conn: restartedConn}
	stale, err := restarted.Observe(ctx, &through)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.Recv(); err == nil {
		t.Fatal("restart accepted an old source lifetime as continuous")
	}
	freshCtx, stopFresh := context.WithCancel(ctx)
	defer stopFresh()
	fresh, err := restarted.Observe(freshCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	freshSnapshot, err := fresh.Recv()
	if err != nil || freshSnapshot.Snapshot == nil || freshSnapshot.Cursor.NodeID != through.NodeID || freshSnapshot.Cursor.ClusterID != through.ClusterID || freshSnapshot.Cursor.ServerEpoch == through.ServerEpoch {
		t.Fatalf("fresh restarted persistent manager snapshot: %+v %v", freshSnapshot, err)
	}
	if message, err := fresh.Recv(); err != nil || message.ReplayThrough == nil {
		t.Fatalf("fresh restart did not reach exact watermark: %+v %v", message, err)
	}
	revoked.Store(true)
	if _, err := upstream.CreateConfig(ctx, &api.CreateConfigRequest{Spec: spec}); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked stream delivered a new observation: %v", err)
	}
}
