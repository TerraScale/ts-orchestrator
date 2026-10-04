package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type membershipCluster struct {
	ids         []string
	configs     []natscell.Config
	runtimes    []*natscell.Runtime
	membership  []string
	root        string
	mu          sync.Mutex
	restartRoot int
}

// startMembershipCluster starts three production-mode JWT brokers with the
// production route shape (no self route) and a scoped membership user each.
func startMembershipCluster(t *testing.T, ctx context.Context) *membershipCluster {
	t.Helper()
	root := t.TempDir()
	tlsFiles, routePassword := testR3TLSMaterial(t, root)
	opKey, _ := nkeys.CreateOperator()
	sysKey, _ := nkeys.CreateAccount()
	cellKey, _ := nkeys.CreateAccount()
	opID, _ := opKey.PublicKey()
	sysID, _ := sysKey.PublicKey()
	cellID, _ := cellKey.PublicKey()
	op := jwt.NewOperatorClaims(opID)
	op.SystemAccount = sysID
	opRaw, err := op.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	sysRaw, err := jwt.NewAccountClaims(sysID).Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	cell := jwt.NewAccountClaims(cellID)
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 512 << 20, Streams: 10, Consumer: 10}
	cellRaw, err := cell.Encode(opKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, raw string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	opFile, sysFile, cellFile := write("operator.jwt", opRaw), write("system.jwt", sysRaw), write("cell.jwt", cellRaw)
	ticketPub, _ := testEd25519(t, root, "membership-ticket.key")
	ticketFile := write("membership-ticket.pub", base64.StdEncoding.EncodeToString(ticketPub))
	ids := []string{"broker-a", "broker-b", "broker-c"}
	ports := reserveControllerPorts(t, 2*len(ids))
	clientPorts, routePorts := ports[:len(ids)], ports[len(ids):]
	cluster := &membershipCluster{ids: ids, root: root, configs: make([]natscell.Config, len(ids)),
		runtimes: make([]*natscell.Runtime, len(ids)), membership: make([]string, len(ids))}
	for index, id := range ids {
		var routes []string
		for peer, port := range routePorts {
			if peer != index {
				routes = append(routes, fmt.Sprintf("nats-route://127.0.0.1:%d", port))
			}
		}
		controllerPub, controllerCreds := testBrokerJWTUser(t, root, id+"-controller.creds", cellKey, cellID,
			[]string{"$JS.API.>", "$JS.ACK.>", "ts.membership.>"}, nil)
		controllerClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, controllerCreds))
		if err != nil {
			t.Fatal(err)
		}
		controllerClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + controllerPub + ".>"}
		controllerCreds = testBrokerJWTUserWithClaim(t, root, id+"-controller.creds", cellKey, controllerClaim)
		systemPub, systemCreds := testBrokerJWTUser(t, root, id+"-system.creds", sysKey, sysID,
			[]string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}, nil)
		systemClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, systemCreds))
		if err != nil {
			t.Fatal(err)
		}
		systemClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + systemPub + ".>"}
		systemCreds = testBrokerJWTUserWithClaim(t, root, id+"-system.creds", sysKey, systemClaim)
		memberPub, memberCreds := testBrokerJWTUser(t, root, id+"-membership.creds", sysKey, sysID,
			[]string{natscell.MembershipServerRemoveSubject, natscell.MembershipMetaStepdownSubject}, nil)
		memberClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, memberCreds))
		if err != nil {
			t.Fatal(err)
		}
		memberClaim.Sub.Allow = jwt.StringList{"ts.orch.v1.gru.inbox." + memberPub + ".>"}
		cluster.membership[index] = testBrokerJWTUserWithClaim(t, root, id+"-membership.creds", sysKey, memberClaim)
		cluster.configs[index] = natscell.Config{Cell: "gru", Instance: id, Replicas: 3,
			CredentialsFile: controllerCreds, TLS: tlsFiles,
			Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: clientPorts[index], RouteHost: "127.0.0.1",
				RoutePort: routePorts[index], Routes: routes, StoreDir: filepath.Join(root, id),
				StoreMaxBytes: 1 << 30, TLS: tlsFiles, RouteTLS: tlsFiles, RouteUser: "membership-route",
				RoutePasswordFile: routePassword, OperatorJWTFile: opFile, SystemJWTFile: sysFile,
				CellJWTFile: cellFile, SystemCredentialsFile: systemCreds,
				TicketPublicKeyFile: ticketFile, MembershipCredentialsFile: cluster.membership[index],
				BrokerIDs: ids}}
	}
	errs := make([]error, len(ids))
	var starts sync.WaitGroup
	for index := range ids {
		starts.Go(func() { cluster.runtimes[index], errs[index] = natscell.Start(ctx, cluster.configs[index]) })
	}
	starts.Wait()
	t.Cleanup(func() {
		cluster.mu.Lock()
		defer cluster.mu.Unlock()
		for _, runtime := range cluster.runtimes {
			if runtime != nil {
				_ = runtime.Close()
			}
		}
	})
	for index, err := range errs {
		if err != nil {
			t.Fatalf("start %s: %v", ids[index], err)
		}
	}
	for _, runtime := range cluster.runtimes {
		if err := runtime.WaitForCluster(ctx, 3); err != nil {
			t.Fatal(err)
		}
	}
	waitMembership(t, ctx, "full R3 readiness", func() bool {
		for _, runtime := range cluster.runtimes {
			if !runtime.FullClusterReady(3) {
				return false
			}
		}
		return true
	})
	return cluster
}

func (cluster *membershipCluster) runtime(index int) *natscell.Runtime {
	cluster.mu.Lock()
	defer cluster.mu.Unlock()
	return cluster.runtimes[index]
}

// relaunch restarts a slot's broker under the same server name with a new,
// empty store, as a replacement instance would boot.
func (cluster *membershipCluster) relaunch(ctx context.Context, index int) error {
	cluster.mu.Lock()
	cluster.restartRoot++
	cfg := cluster.configs[index]
	embedded := *cfg.Embedded
	embedded.StoreDir = filepath.Join(cluster.root, fmt.Sprintf("%s-replacement-%d", cluster.ids[index], cluster.restartRoot))
	cfg.Embedded = &embedded
	cluster.mu.Unlock()
	runtime, err := natscell.Start(ctx, cfg)
	if err != nil {
		return err
	}
	cluster.mu.Lock()
	cluster.runtimes[index] = runtime
	cluster.mu.Unlock()
	return nil
}

func waitMembership(t *testing.T, ctx context.Context, what string, ready func() bool) {
	t.Helper()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", what, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type staticLeadership struct{ epoch uint64 }

func (leader staticLeadership) Current() authority.Snapshot {
	return authority.Snapshot{Ready: true, Leader: true, Epoch: leader.epoch, Revision: 1,
		ExpiresAt: time.Now().Add(time.Hour)}
}

func (staticLeadership) Guard(context.Context, uint64) error { return nil }

// fakeSlotOCI stands in for the bootstrap ledger, OCI lifecycle reads,
// retirement evidence and the founder replacer.
type fakeSlotOCI struct {
	mu        sync.Mutex
	ledger    map[string]membership.LedgerSlot
	lifecycle map[string]string
	evidence  map[string]membership.Evidence
	relaunch  func(context.Context, membership.Action) (string, error)
	replaced  []membership.Action
}

func (fake *fakeSlotOCI) Slots(_ context.Context, slots []string) (map[string]membership.LedgerSlot, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	out := make(map[string]membership.LedgerSlot, len(slots))
	for _, slot := range slots {
		out[slot] = fake.ledger[slot]
	}
	return out, nil
}

func (fake *fakeSlotOCI) Lifecycle(_ context.Context, instance string) (string, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if state, ok := fake.lifecycle[instance]; ok {
		return state, nil
	}
	return "", fmt.Errorf("instance %s not found", instance)
}

func (fake *fakeSlotOCI) Evidence(context.Context) (map[string]membership.Evidence, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return copyEvidence(fake.evidence), nil
}

func copyEvidence(in map[string]membership.Evidence) map[string]membership.Evidence {
	out := make(map[string]membership.Evidence, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (fake *fakeSlotOCI) Replace(ctx context.Context, action membership.Action) error {
	fake.mu.Lock()
	fake.replaced = append(fake.replaced, action)
	relaunch := fake.relaunch
	fake.mu.Unlock()
	instance, err := relaunch(ctx, action)
	if err != nil {
		return err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.ledger[action.Slot] = membership.LedgerSlot{Attempt: action.PreviousAttempt + 1, InstanceOCID: instance,
		Complete: true, Retirement: action.Retirement.Digest}
	fake.lifecycle[instance] = membership.LifecycleRunning
	return nil
}

func TestMembershipReplacesTerminatedControllerUnderSameServerName(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cluster := startMembershipCluster(t, ctx)
	seed := cluster.runtime(0)
	peers := natsMembershipPeers{runtime: seed}
	waitMembership(t, ctx, "all metadata peers online", func() bool {
		meta, err := peers.Meta(ctx)
		return err == nil && meta.Leader != "" && len(meta.Peers) == 2 &&
			!slices.ContainsFunc(meta.Peers, func(peer membership.Peer) bool { return !peer.Online })
	})

	// The claim-update system user cannot administer metadata membership.
	if _, err := seed.OpenMembershipAdmin(cluster.configs[0].Embedded.SystemCredentialsFile); err == nil {
		t.Fatal("claim-update system credentials opened membership administration")
	}
	// The scoped user steps the metadata leader down.
	var leaderIndex int
	var leaderName string
	waitMembership(t, ctx, "metadata leader", func() bool {
		for index := range cluster.ids {
			view, err := cluster.runtime(index).Meta()
			if err == nil && view.Leader != "" && view.Leader == view.Self {
				leaderIndex, leaderName = index, view.Self
				return true
			}
		}
		return false
	})
	admin, err := cluster.runtime(leaderIndex).OpenMembershipAdmin(cluster.membership[leaderIndex])
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.StepDownMetaLeader(ctx); err != nil {
		t.Fatalf("scoped metadata step-down: %v", err)
	}
	admin.Close()
	waitMembership(t, ctx, "new metadata leader", func() bool {
		view, err := seed.Meta()
		return err == nil && view.Leader != "" && view.Leader != leaderName
	})

	// A fresh metadata leader can briefly report a peer offline and refuse
	// R3 placement; retry until all three peers are placeable again.
	var stream jetstream.Stream
	waitMembership(t, ctx, "R3 stream placement after step-down", func() bool {
		stream, err = seed.JetStream().CreateStream(ctx, jetstream.StreamConfig{Name: "MEMBERSHIP_REPLACEMENT",
			Subjects: []string{"ts.membership.replacement"}, Replicas: 3, Storage: jetstream.FileStorage})
		return err == nil
	})
	// The new stream's leader may still be settling after the step-down; a
	// publish can briefly get no stream response, so retry each one under a
	// message ID that deduplicates a retried publish the stream did store.
	for index := range 10 {
		waitMembership(t, ctx, "publish before the loss", func() bool {
			_, err = seed.JetStream().Publish(ctx, "ts.membership.replacement", fmt.Appendf(nil, "before-%d", index),
				jetstream.WithMsgID(fmt.Sprintf("before-%d", index)))
			return err == nil
		})
	}

	const oldInstance = "ocid1.instance.oc1.sa-saopaulo-1.broker-b"
	fake := &fakeSlotOCI{
		ledger: map[string]membership.LedgerSlot{
			"broker-a": {Attempt: 1, InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.broker-a", Complete: true},
			"broker-b": {Attempt: 1, InstanceOCID: oldInstance, Complete: true},
			"broker-c": {Attempt: 1, InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.broker-c", Complete: true}},
		lifecycle: map[string]string{oldInstance: membership.LifecycleRunning,
			"ocid1.instance.oc1.sa-saopaulo-1.broker-c": membership.LifecycleRunning},
		evidence: map[string]membership.Evidence{"broker-b": {Slot: "broker-b", PreviousAttempt: 1,
			PriorInstanceOCID: oldInstance, Digest: "2222222222222222222222222222222222222222222222222222222222222222",
			Wire: []byte("root-signed retirement")}},
	}
	fake.relaunch = func(ctx context.Context, action membership.Action) (string, error) {
		if action.Slot != "broker-b" || action.PreviousAttempt != 1 || action.PriorInstanceOCID != oldInstance {
			return "", fmt.Errorf("unexpected replacement %+v", action)
		}
		return oldInstance + "-a2", cluster.relaunch(ctx, 1)
	}
	reconciler, err := membership.New(membership.Config{Enabled: true, Replace: true, OfflineGraceSeconds: 120},
		membership.Topology{Cell: "gru", Slots: cluster.ids, SeedSlot: "broker-a", SelfSlot: "broker-a"},
		membership.Dependencies{Leadership: staticLeadership{epoch: 9}, Peers: peers, Ledger: fake,
			Instances: fake, Evidence: fake, Replacer: fake,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	status := func(slot string) membership.SlotStatus {
		for _, status := range reconciler.Statuses() {
			if status.Slot == slot {
				return status
			}
		}
		return membership.SlotStatus{}
	}
	if err := reconciler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if status("broker-b").Phase != membership.PhaseHealthy {
		t.Fatalf("online slot = %+v", status("broker-b"))
	}

	// The instance dies; the cell keeps quorum and accepts writes.
	cluster.mu.Lock()
	_ = cluster.runtimes[1].Close()
	cluster.mu.Unlock()
	for index := range 10 {
		if _, err := seed.JetStream().Publish(ctx, "ts.membership.replacement", fmt.Appendf(nil, "during-%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	waitMembership(t, ctx, "offline slot is suspect", func() bool {
		return reconciler.Tick(ctx) == nil && status("broker-b").Phase == membership.PhaseSuspect
	})
	if len(fake.replaced) != 0 {
		t.Fatal("a running instance within grace was replaced")
	}
	// OCI reports the pinned instance TERMINATED: replace without waiting.
	fake.mu.Lock()
	fake.lifecycle[oldInstance] = membership.LifecycleTerminated
	fake.mu.Unlock()
	if err := reconciler.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fake.replaced) != 1 {
		t.Fatalf("terminated slot replacement calls = %d status=%+v", len(fake.replaced), status("broker-b"))
	}
	waitMembership(t, ctx, "replacement rejoins under the same server name", func() bool {
		return reconciler.Tick(ctx) == nil && status("broker-b").Phase == membership.PhaseHealthy &&
			status("broker-b").Attempt == 2
	})
	waitMembership(t, ctx, "empty-store replacement catches up the R3 stream", func() bool {
		info, err := stream.Info(ctx)
		if err != nil || info.Cluster == nil || info.State.Msgs != 20 {
			return false
		}
		names := []string{info.Cluster.Leader}
		for _, replica := range info.Cluster.Replicas {
			if !replica.Current || replica.Lag != 0 {
				return false
			}
			names = append(names, replica.Name)
		}
		return slices.Contains(names, "gru-broker-b")
	})
	if len(fake.replaced) != 1 {
		t.Fatalf("replacement repeated: %d", len(fake.replaced))
	}
	if !cluster.runtime(1).FullClusterReady(3) {
		t.Fatal("replacement broker is not fully clustered")
	}
}
