package authbootstrap

import (
	"context"
	"encoding/json/v2"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestAuthenticatedHostDispatchBindsBothIdentities(t *testing.T) {
	cluster := newAuthJournalCluster(t)
	connection := cluster.connect(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	grant := testGrant()
	grant.AuthorityRevision = 8
	for _, v := range grant.Voters {
		v.StorageIncarnation = v.Member
	}
	target := &fakeTarget{grant: grant, voter: grant.Voters[0]}
	bridge, err := StartHostBridge(ctx, connection, target)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	remote, err := NewRemoteTarget(connection, target.ServerIdentity(), target.Principal(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := remote.Identity(ctx)
	if err != nil || identity.Member != target.voter.Member {
		t.Fatal("identity dispatch failed", err)
	}
	request := &pb.AuthGroupBootstrapServiceBootstrapRequest{OperationId: grant.GroupId, Grant: grant}
	for range 2 {
		receipt, err := remote.Bootstrap(ctx, request)
		if err != nil || receipt.AuthorityRevision != 8 {
			t.Fatal("bootstrap dispatch failed", err)
		}
	}
	if target.effects != 1 {
		t.Fatal("retry repeated genesis")
	}
	identitySubject, _, _ := HostSubjects(target.ServerIdentity())
	for _, forged := range []dispatchRequest{{ServerIdentity: target.ServerIdentity(), Principal: "spiffe://terrascale.tech/production/foreign"}, {ServerIdentity: "spiffe://terrascale.tech/production/foreign", Principal: target.Principal()}} {
		data, _ := json.Marshal(forged)
		response, err := connection.RequestWithContext(ctx, identitySubject, data)
		if err != nil {
			t.Fatal(err)
		}
		var reply dispatchReply
		if json.Unmarshal(response.Data, &reply) != nil || reply.Code != int32(codes.InvalidArgument) {
			t.Fatal("cross-host or forged-principal request accepted")
		}
	}
	if target.identities != 1 {
		t.Fatal("forged request reached engine")
	}
}
