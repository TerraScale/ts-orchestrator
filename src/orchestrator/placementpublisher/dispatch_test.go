package placementpublisher

import (
	"context"
	"encoding/json/v2"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthenticatedHostDispatch(t *testing.T) {
	cluster := newPlacementJournalCluster(t)
	connection := cluster.connect(t)
	target := newFakeTarget()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	bridge, err := StartHostBridge(ctx, connection, target)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	remote, err := NewRemoteTarget(connection, target.ServerIdentity(), target.Principal(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := remote.Stage(ctx, "op-1", testRequest())
	if err != nil || response.Revision != 1 || target.effects != 1 {
		t.Fatalf("dispatch result=%v error=%v", response, err)
	}
	response, err = remote.Stage(ctx, "op-1", testRequest())
	if err != nil || response.Revision != 1 || target.effects != 1 {
		t.Fatal("retry duplicated pending operation")
	}
	foreign, err := NewRemoteTarget(connection, target.ServerIdentity(), "spiffe://terrascale.tech/production/orchestrator/foreign", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Stage(ctx, "op-2", testRequest()); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("foreign principal accepted: %v", err)
	}
	forged, _ := NewRecord("op-2", "spiffe://terrascale.tech/production/terrabase/foreign", target.Principal(), testRequest())
	data, _ := json.Marshal(forged)
	message, err := connection.RequestWithContext(ctx, remote.subject, data)
	if err != nil {
		t.Fatal(err)
	}
	var reply dispatchReply
	if json.Unmarshal(message.Data, &reply) != nil || reply.Code != int32(codes.InvalidArgument) {
		t.Fatal("foreign target accepted")
	}
	if target.effects != 1 {
		t.Fatal("invalid request reached local engine")
	}
	publish, subscribe, err := HostPermissions(target.ServerIdentity())
	if err != nil || len(publish) != 1 || publish[0] != "_INBOX.>" || len(subscribe) != 1 || subscribe[0] != remote.subject {
		t.Fatal("host grants are not exact")
	}
}
