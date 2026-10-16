package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/membership"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// seedFounderRecorder stands in for the seed's founder replacer.
type seedFounderRecorder struct {
	mu      sync.Mutex
	actions []membership.Action
	done    chan struct{}
}

func (founder *seedFounderRecorder) Replace(ctx context.Context, action membership.Action) error {
	if err := action.Fence(ctx); err != nil {
		return err
	}
	founder.mu.Lock()
	founder.actions = append(founder.actions, action)
	founder.mu.Unlock()
	close(founder.done)
	return nil
}

type seedInstances map[string]string

func (instances seedInstances) Lifecycle(_ context.Context, instance string) (string, error) {
	if state, ok := instances[instance]; ok {
		return state, nil
	}
	return "", errors.New("instance not found")
}

func testRetirementWire(t *testing.T, slot, instance string) []byte {
	t.Helper()
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := bootstrap.SignSlotRetirement(bootstrap.RetirementEvidence{SchemaVersion: 1,
		DeploymentID: "0000000000DMC7WFP9VHV640EP", Cell: "GRU", Environment: "production", Role: "controller", Slot: slot,
		PreviousAttempt: 1, PreviousGeneration: 1, PreviousResultDigest: strings.Repeat("c", 64),
		PriorInstanceOCID: instance, PriorCreateKey: "founder-" + slot + "-key",
		Disposition: bootstrap.SlotRetirementDisposition, ObservedEvidenceDigest: strings.Repeat("2", 64),
		FencingAuthority: "authority-epoch-1", ObservedAt: now}, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// TestSeedRoutingOverNATSRunsUnderTheRealLeaderLease drives one routed
// replacement end to end: a non-seed authority leader's term on the real R3
// lease, a NATS request to the seed's service, and the seed's read-only
// foreign-lease fence around the founder call.
func TestSeedRoutingOverNATSRunsUnderTheRealLeaderLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := newAuthenticatedNATS(t, "gru").start(t, ctx, natscell.Config{Cell: "gru", Instance: "seed-routing", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	start := func(candidate string) *authority.Runtime {
		runtime, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru",
			CandidateID: candidate, LeaseDuration: 5 * time.Second, RenewInterval: time.Second, Replicas: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runtime.Close() })
		return runtime
	}
	leader, seedAuthority := start(entityid.Derive("test-controller", "controller-c-1")), start("0000000000Y0WXHAAJ7JVKJYN1")
	if !leader.Current().CanMutate() || seedAuthority.Current().Leader {
		t.Fatal("the non-seed controller must lead for this test")
	}

	const instanceB = "ocid1.instance.oc1.sa-saopaulo-1.controller-b"
	founder := &seedFounderRecorder{done: make(chan struct{})}
	topology := membership.Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
		SeedSlot: "controller-a", SelfSlot: "controller-a"}
	server, err := membership.NewSeedServer(ctx, topology, membership.SeedServerDependencies{
		Leases: seedAuthority, Instances: seedInstances{instanceB: membership.LifecycleTerminated},
		Replacer: &serializedReplacer{inner: founder}})
	if err != nil {
		t.Fatal(err)
	}
	subject := protocol.MembershipReplaceSubject("gru")
	service := &seedReplacementService{conn: broker.Conn(), subject: subject, server: server}
	serveCtx, stopServe := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- service.Run(serveCtx) }()
	t.Cleanup(func() {
		stopServe()
		<-served
	})

	routed := membership.SeedRoutedReplacer{Cell: "gru", Leadership: leader,
		Request: natsSeedRequester(broker.Conn(), subject)}
	term := leader.Current()
	action := membership.Action{Slot: "controller-b", PreviousAttempt: 1, PriorInstanceOCID: instanceB,
		Epoch: term.Epoch, Retirement: membership.Evidence{Slot: "controller-b", PreviousAttempt: 1,
			PriorInstanceOCID: instanceB, Wire: testRetirementWire(t, "controller-b", instanceB)},
		Fence: func(fenceCtx context.Context) error { return leader.Guard(fenceCtx, term.Epoch) }}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = routed.Replace(ctx, action)
		if err == nil || time.Now().After(deadline) {
			break
		}
		// The subscription may not have propagated yet.
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("route replacement to the seed: %v", err)
	}
	select {
	case <-founder.done:
	case <-ctx.Done():
		t.Fatal("seed never executed the routed replacement")
	}
	founder.mu.Lock()
	executed := founder.actions[0]
	founder.mu.Unlock()
	if executed.Slot != "controller-b" || executed.Epoch != term.Epoch || executed.PriorInstanceOCID != instanceB {
		t.Fatalf("seed executed %+v", executed)
	}
	if seedAuthority.Current().Leader {
		t.Fatal("serving a routed request made the seed take authority")
	}

	// A request carrying a term that does not hold the lease is refused.
	stale := membership.SeedRoutedReplacer{Cell: "gru", Leadership: seedAuthorityAsLeader{seedAuthority, term.Epoch},
		Request: natsSeedRequester(broker.Conn(), subject)}
	if err := stale.Replace(ctx, membership.Action{Slot: "controller-b", PreviousAttempt: 1,
		PriorInstanceOCID: instanceB, Epoch: term.Epoch, Retirement: action.Retirement}); !errors.Is(err, membership.ErrSeedRefused) {
		t.Fatalf("forged term reply = %v, want a seed refusal", err)
	}
}

// seedAuthorityAsLeader claims the leader's epoch under another candidate.
type seedAuthorityAsLeader struct {
	runtime *authority.Runtime
	epoch   uint64
}

func (forged seedAuthorityAsLeader) Current() authority.Snapshot {
	snapshot := forged.runtime.Current()
	snapshot.Leader, snapshot.Ready, snapshot.Epoch = true, true, forged.epoch
	snapshot.Revision, snapshot.ExpiresAt = 1, time.Now().Add(time.Hour)
	// A follower's snapshot names the lease holder; claim the seed's own.
	snapshot.CandidateID, snapshot.OwnerID = "0000000000Y0WXHAAJ7JVKJYN1", "forged-owner"
	return snapshot
}

func (seedAuthorityAsLeader) Guard(context.Context, uint64) error { return nil }

type followerLeadership struct{}

func (followerLeadership) Current() authority.Snapshot         { return authority.Snapshot{} }
func (followerLeadership) Guard(context.Context, uint64) error { return authority.ErrNotLeader }

type noPeers struct{}

func (noPeers) Meta(context.Context) (membership.Meta, error) { return membership.Meta{}, nil }

// A seed service that cannot subscribe stops the membership supervisor at
// once, so the controller's worker supervision sees the failure instead of
// it waiting, buffered, until shutdown.
func TestControllerMembershipSurfacesASeedServiceFailureAtOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := newAuthenticatedNATS(t, "gru").start(t, ctx, natscell.Config{Cell: "gru", Instance: "seed-fail", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	topology := membership.Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
		SeedSlot: "controller-a", SelfSlot: "controller-a"}
	founder := &serializedReplacer{inner: &seedFounderRecorder{done: make(chan struct{})}}
	server, err := membership.NewSeedServer(ctx, topology, membership.SeedServerDependencies{
		Leases: seedLeaseRefuser{}, Instances: seedInstances{}, Replacer: founder})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSlotOCI{}
	reconciler, err := membership.New(topology,
		membership.Dependencies{Leadership: followerLeadership{}, Peers: noPeers{}, Ledger: fake, Instances: fake,
			Evidence: fake, Replacer: founder})
	if err != nil {
		t.Fatal(err)
	}
	// An invalid subject makes Subscribe fail synchronously.
	supervisor := &controllerMembership{reconciler: reconciler,
		seed: &seedReplacementService{conn: broker.Conn(), subject: "", server: server}}
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "serve controller slot replacement requests") {
			t.Fatalf("supervisor stopped with %v, want the seed subscription failure", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a seed subscription failure did not stop the membership supervisor")
	}
}

type seedLeaseRefuser struct{}

func (seedLeaseRefuser) VerifyLeaseHolder(context.Context, uint64, string, string) error {
	return authority.ErrFenced
}

func TestControllerCredentialsGrantTheSeedReplacementSubscription(t *testing.T) {
	if !strings.HasSuffix(protocol.MembershipReplaceSubject("gru"), ".membership.replace") {
		t.Fatal("membership replace subject changed")
	}
	found := false
	for _, subject := range natscell.ControllerSubscriptions("gru") {
		found = found || subject == protocol.MembershipReplaceSubject("gru")
	}
	if !found {
		t.Fatal("controller credentials cannot serve routed replacement requests")
	}
}
