package authbootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

func testGrant() *pb.AuthGroupBootstrapGrant {
	grant := &pb.AuthGroupBootstrapGrant{Environment: "production", Cluster: "01ARZ3NDEKTSV4RRFFQ69G5FA0", GroupId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", Tenant: "01ARZ3NDEKTSV4RRFFQ69G5FA2", Project: "01ARZ3NDEKTSV4RRFFQ69G5FA3", Database: "01ARZ3NDEKTSV4RRFFQ69G5FA4", Generation: 1, Regions: []string{"FRA", "GRU", "SFO"}, GenesisNode: 1}
	for i := range 6 {
		region := grant.Regions[i/2]
		member := "01ARZ3NDEKTSV4RRFFQ69G5F" + string(rune('A'+i)) + "5"
		grant.Voters = append(grant.Voters, &pb.AuthGroupVoter{NodeId: uint64(i + 1), Member: member, SpiffeUri: "spiffe://terrascale.tech/" + grant.Environment + "/terrabase-member/" + grant.Cluster + "/" + member, Region: region})
	}

	return grant
}

type fakeTarget struct {
	grant               *pb.AuthGroupBootstrapGrant
	voter               *pb.AuthGroupVoter
	receipt             *pb.AuthGroupBootstrapServiceBootstrapResponse
	effects, identities int
	unknown             bool
	lostDisk            bool
}

func (target *fakeTarget) Principal() string {
	return "spiffe://terrascale.tech/production/orchestrator/" + target.voter.Region
}
func (target *fakeTarget) ServerIdentity() string { return target.voter.SpiffeUri }
func (target *fakeTarget) Identity(context.Context) (*pb.AuthGroupBootstrapServiceIdentityResponse, error) {
	target.identities++
	return &pb.AuthGroupBootstrapServiceIdentityResponse{Environment: target.grant.Environment, Cluster: target.grant.Cluster, Member: target.voter.Member, StorageIncarnation: target.voter.Member}, nil
}
func (target *fakeTarget) Bootstrap(_ context.Context, request *pb.AuthGroupBootstrapServiceBootstrapRequest) (*pb.AuthGroupBootstrapServiceBootstrapResponse, error) {
	if target.lostDisk {
		return nil, ErrConflict
	}
	if target.receipt == nil {
		target.effects++
		target.receipt = &pb.AuthGroupBootstrapServiceBootstrapResponse{GroupId: request.Grant.GroupId, Generation: 1, AuthorityRevision: request.Grant.AuthorityRevision, StorageIncarnation: target.voter.Member, Status: 1, Grant: proto.Clone(request.Grant).(*pb.AuthGroupBootstrapGrant), OperationId: request.OperationId}
	}
	if target.unknown {
		target.unknown = false
		return nil, errors.New("response lost after persist")
	}
	return target.receipt, nil
}

type uncertainAccept struct {
	Durable
	lost bool
}

func (j *uncertainAccept) Accept(ctx context.Context, grant *pb.AuthGroupBootstrapGrant) error {
	if err := j.Durable.Accept(ctx, grant); err != nil {
		return err
	}
	if !j.lost {
		j.lost = true
		return errors.New("accept response lost")
	}
	return nil
}
func TestR3GrantRestartUnknownOutcomeAndAuthorityConflict(t *testing.T) {
	cluster := newAuthJournalCluster(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()
	connection := cluster.connect(t)
	store := openAuthLeaseStore(t, ctx, connection, true)
	candidate := "global-controller-gru-one"
	putAuthLease(t, ctx, store, authLease(1, candidate))
	newJournal := func(epoch uint64, candidate string) *Journal {
		j, err := NewJournal(authorityjournal.Config{Connection: connection, CandidateID: candidate, AuthorityEpoch: epoch, LeaseID: "lease-" + string(rune('0'+epoch))})
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	grant := testGrant()
	var targets []Target
	for _, voter := range grant.Voters {
		targets = append(targets, &fakeTarget{grant: grant, voter: voter, unknown: true})
	}
	journal := newJournal(1, candidate)
	service, err := New(&uncertainAccept{Durable: journal}, targets, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Reconcile(ctx, grant); err == nil {
		t.Fatal("unknown journal acceptance treated as success")
	}
	for _, target := range targets {
		if target.(*fakeTarget).effects != 0 {
			t.Fatal("dispatched without known committed acceptance")
		}
	}
	if err := service.Reconcile(ctx, grant); err == nil {
		t.Fatal("unknown dispatch treated as receipt")
	}
	accepted, err := journal.Load(ctx, grant.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	request, err := decode(accepted)
	if err != nil || request.Grant.AuthorityRevision == 0 {
		t.Fatal("missing committed revision", err)
	}
	stored, err := store.Get(ctx, "auth.bootstrap.state")
	if err != nil || stored.Revision() != request.Grant.AuthorityRevision {
		t.Fatal("grant did not bind exact committed R3 sequence", err)
	}
	for _, target := range targets {
		if target.(*fakeTarget).effects != 1 {
			t.Fatal("grant did not reach initial voter")
		}
	}
	connection.Close()
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAuthLeaseStore(t, ctx, connection, false)
	journal = newJournal(1, candidate)
	service, _ = New(journal, targets, func(context.Context) error { return nil })
	if err := service.Reconcile(ctx, grant); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		actual := target.(*fakeTarget)
		if actual.effects != 1 || actual.identities != 1 {
			t.Fatal("restart rediscovered storage or repeated genesis")
		}
	}
	conflict := proto.Clone(request.Grant).(*pb.AuthGroupBootstrapGrant)
	conflict.AuthorityRevision = 0
	conflict.Voters[0].StorageIncarnation = "01ARZ3NDEKTSV4RRFFQ69G5FB0"
	if err := journal.Accept(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatal("disk replacement reissued genesis", err)
	}
	conflict = proto.Clone(request.Grant).(*pb.AuthGroupBootstrapGrant)
	conflict.AuthorityRevision = 0
	conflict.GroupId = "01ARZ3NDEKTSV4RRFFQ69G5FB1"
	if err := journal.Accept(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatal("same database got a second group", err)
	}
	putAuthLease(t, ctx, store, authLease(2, "global-controller-gru-two"))
	if err := service.Reconcile(ctx, grant); !errors.Is(err, authorityjournal.ErrFenced) {
		t.Fatal("old controller remained authoritative", err)
	}
	journal = newJournal(2, "global-controller-gru-two")
	service, _ = New(journal, targets, func(context.Context) error { return nil })
	if err := service.Reconcile(ctx, grant); err != nil {
		t.Fatal(err)
	}
	reloaded, err := journal.Load(ctx, grant.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := decode(reloaded)
	if err != nil || !proto.Equal(request, resolved) {
		t.Fatal("authority successor changed genesis request", err)
	}
	for _, server := range cluster.servers[1:] {
		server.Shutdown()
		server.WaitForShutdown()
	}
	outage, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	defer stop()
	if _, err := journal.Load(outage, grant.GroupId); err == nil {
		t.Fatal("minority read grants authority")
	}
}
func TestGrantValidationRejectsUnsafeTopology(t *testing.T) {
	for name, mutate := range map[string]func(*pb.AuthGroupBootstrapGrant){
		"database identity": func(g *pb.AuthGroupBootstrapGrant) { g.Database = "other" },
		"duplicate voter":   func(g *pb.AuthGroupBootstrapGrant) { g.Voters[1].NodeId = g.Voters[0].NodeId },
		"foreign residency": func(g *pb.AuthGroupBootstrapGrant) { g.Voters[0].Region = "other" },
		"uri query":         func(g *pb.AuthGroupBootstrapGrant) { g.Voters[0].SpiffeUri += "?x=y" },
		"new generation":    func(g *pb.AuthGroupBootstrapGrant) { g.Generation = 2 },
		"missing genesis":   func(g *pb.AuthGroupBootstrapGrant) { g.GenesisNode = 10 },
		"incarnation":       func(g *pb.AuthGroupBootstrapGrant) { g.Voters[0].StorageIncarnation = strings.Repeat("x", 26) },
	} {
		t.Run(name, func(t *testing.T) {
			g := testGrant()
			mutate(g)
			if _, err := CanonicalGrant(g, true); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
}
