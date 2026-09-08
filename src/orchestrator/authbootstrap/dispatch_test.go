package authbootstrap

import (
	"context"
	"encoding/json/v2"
	"testing"

	"terrascale.tech/orchestrator/internal/testnats"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func TestAuthenticatedHostDispatchBindsBothIdentities(t *testing.T) {
	cluster := testnats.New(t)
	connection := cluster.Connect(t)
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
	request := &pb.AuthGroupBootstrapRequest{OperationId: grant.GroupId, Grant: grant}
	for range 2 {
		receipt, err := remote.Bootstrap(ctx, request)
		if err != nil || receipt.AuthorityRevision != 8 {
			t.Fatal("bootstrap dispatch failed", err)
		}
	}
	if target.effects != 1 {
		t.Fatal("retry repeated genesis")
	}
	identitySubject, bootstrapSubject, _ := HostSubjects(target.ServerIdentity())
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
	malformed, _ := json.Marshal(dispatchRequest{ServerIdentity: target.ServerIdentity(), Principal: target.Principal(), Request: []byte{0xff}})
	response, err := connection.RequestWithContext(ctx, bootstrapSubject, malformed)
	if err != nil {
		t.Fatal(err)
	}
	var reply dispatchReply
	if json.Unmarshal(response.Data, &reply) != nil || reply.Code != int32(codes.InvalidArgument) {
		t.Fatal("malformed bootstrap reached engine")
	}
	if target.effects != 1 {
		t.Fatalf("malformed bootstrap changed effects: %d", target.effects)
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, 0xa0, 0x06, 0x01) // unknown field 100
	unknown, _ := json.Marshal(dispatchRequest{ServerIdentity: target.ServerIdentity(), Principal: target.Principal(), Request: encoded})
	response, err = connection.RequestWithContext(ctx, bootstrapSubject, unknown)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(response.Data, &reply) != nil || reply.Code != int32(codes.InvalidArgument) {
		t.Fatal("unknown protobuf field reached engine")
	}
	if target.effects != 1 {
		t.Fatalf("unknown protobuf field changed effects: %d", target.effects)
	}
}

func TestAuthenticatedHostDispatchReplaysDurableBootstrapAfterDroppedReply(t *testing.T) {
	cluster := testnats.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	connection := cluster.Connect(t)
	store := testnats.OpenLeaseStore(t, ctx, connection, true)
	candidate := "global-controller-gru-one"
	testnats.PutLease(t, ctx, store, testnats.Lease(1, candidate))

	grant := testGrant()
	var targets []Target
	var bridges []*HostBridge
	var engines []*fakeTarget
	for _, voter := range grant.Voters {
		target := &fakeTarget{grant: grant, voter: voter, unknown: true}
		engines = append(engines, target)
		bridge, err := StartHostBridge(ctx, connection, target)
		if err != nil {
			t.Fatal(err)
		}
		bridges = append(bridges, bridge)
		remote, err := NewRemoteTarget(connection, target.ServerIdentity(), target.Principal(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, remote)
	}
	defer func() {
		for _, bridge := range bridges {
			_ = bridge.Close()
		}
	}()

	journal, err := NewJournal(authorityjournal.Config{Connection: connection, CandidateID: candidate, AuthorityEpoch: 1, LeaseID: "lease-1"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(journal, targets, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(ctx, grant); err == nil {
		t.Fatal("dropped dispatch replies were treated as success")
	}
	if err := service.Reconcile(ctx, grant); err != nil {
		t.Fatal(err)
	}
	record, err := journal.Load(ctx, grant.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Receipts) != len(grant.Voters) {
		t.Fatalf("receipts=%d, want %d", len(record.Receipts), len(grant.Voters))
	}
	for _, engine := range engines {
		if engine.effects != 1 {
			t.Fatalf("bootstrap effects=%d, want one after dropped reply", engine.effects)
		}
	}
	if err := service.Reconcile(ctx, grant); err != nil {
		t.Fatalf("duplicate dispatch replay failed: %v", err)
	}
}
