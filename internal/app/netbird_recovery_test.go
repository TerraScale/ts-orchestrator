package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rolloutexec"
)

type netbirdRecoveryLease struct {
	fenceLease
	leader bool
}

func (l *netbirdRecoveryLease) Current() authority.Snapshot {
	snapshot := l.fenceLease.Current()
	snapshot.CandidateID, snapshot.Leader = "01M4EB0GDPPHGJPPVY77EMZQKT", l.leader
	return snapshot
}

func netbirdRecoveryControllers(t *testing.T) (*netbirdRollout, *netbirdRollout) {
	t.Helper()
	var users []*server.User
	for _, slot := range []string{"controller-a", "controller-b"} {
		subs := append(natscell.ControllerSubscriptions("gru"), protocol.InboxPrefix("gru", slot)+".>")
		users = append(users, &server.User{Username: slot, Password: slot, Permissions: &server.Permissions{
			Publish:   &server.SubjectPermission{Allow: []string{protocol.Regional("gru", ">"), "$JS.API.>", "$O.>"}},
			Subscribe: &server.SubjectPermission{Allow: subs},
			Response:  &server.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second},
		}})
	}
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, Users: users, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(broker.Shutdown)
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("recovery transport did not start")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllers := make([]*netbirdRollout, 0, 2)
	for index, slot := range []string{"controller-a", "controller-b"} {
		conn, err := nats.Connect(broker.ClientURL(), nats.UserInfo(slot, slot),
			nats.CustomInboxPrefix(protocol.InboxPrefix("gru", slot)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.Close)
		services := &specRegistry{current: cellspec.Spec{Generation: 9, ReleaseFence: &cellspec.ReleaseFence{}, HostGrants: []cellspec.HostGrant{
			{Node: "node-a", Controller: "controller-a", PrivateIP: "10.251.0.11"},
			{Node: "node-b", Controller: "controller-b", PrivateIP: "10.251.0.12"},
		}}}
		controllers = append(controllers, &netbirdRollout{cell: "gru", conn: conn, key: key, services: services,
			cfg:   Config{NATS: natscell.Config{Instance: slot, Embedded: &natscell.Embedded{BrokerIDs: []string{"controller-a", "controller-b"}}}},
			fence: &releaseFence{spec: services.releaseFence, fencer: &netbirdRecoveryLease{leader: index == 0}}})
	}
	return controllers[0], controllers[1]
}

func TestNetBirdLeaderRecoveryRequiresDistinctControllerProof(t *testing.T) {
	leader, peer := netbirdRecoveryControllers(t)
	var probes atomic.Int32
	sub, err := peer.serveRecovery(t.Context(), func(_ context.Context, address string) error {
		if address != "10.251.0.11" || peer.cfg.NATS.Instance == leader.cfg.NATS.Instance {
			t.Error("probe did not originate from a distinct controller for the adopted OCI target")
		}
		probes.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	// The wildcard health collector also receives the request. It must drop
	// this envelope without winning the RPC with an error response.
	collector := rolloutexec.NewCollector("gru", nil, nil)
	collection, err := collector.Subscribe(peer.conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = collection.Unsubscribe() })
	if err := peer.conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := leader.recoverySSH(t.Context(), "node-a", "10.251.0.11"); err != nil || probes.Load() != 1 {
		t.Fatalf("distinct peer proof failed under actual controller inbox/response grants: probes=%d err=%v", probes.Load(), err)
	}
}

func TestNetBirdOCIRecoveryProofSurvivesReleaseFenceRemoval(t *testing.T) {
	leader, peer := netbirdRecoveryControllers(t)
	leader.services.current.ReleaseFence, peer.services.current.ReleaseFence = nil, nil
	var probes atomic.Int32
	sub, err := peer.serveRecovery(t.Context(), func(_ context.Context, address string) error {
		if address != "10.251.0.11" {
			t.Error("proof did not use the adopted target OCI address")
		}
		probes.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := peer.conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := leader.recoverySSH(t.Context(), "node-a", "10.251.0.11"); err != nil || probes.Load() != 1 {
		t.Fatalf("fence removal blocked authenticated read-only recovery proof: probes=%d err=%v", probes.Load(), err)
	}
}

func TestNetBirdLeaderHoldsBeforeDrainWithoutFreshRecoveryProof(t *testing.T) {
	leader, peer := netbirdRecoveryControllers(t)
	sub, err := peer.conn.Subscribe(netbirdRecoverySubject("gru", "controller-b"), func(message *nats.Msg) {
		// An available transport cannot substitute for an authenticated proof.
		_ = message.Respond([]byte("{}"))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := peer.conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	pin := netbirdArtifactTestPin(t)
	leader.services.current.NetBird = &cellspec.NetBird{Pin: pin}
	leader.fence.kv = fenceKV(t)
	leader.artifacts = netbirdArtifactStore(t, leader.conn)
	stageTestNetbirdArtifacts(t, leader.artifacts, pin)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := leader.saveAt(t.Context(), 3, "netbird.status.node-a", network.Status{Version: "0.79.0", Connected: true, ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := leader.preflight(ctx, "node-a"); err == nil || !strings.Contains(err.Error(), "no fresh remote controller") {
		t.Fatalf("missing proof did not hold preflight before drain: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 6*time.Second {
		t.Fatalf("missing proof was not time bounded: %s", elapsed)
	}
	keys, err := leader.fence.keys(t.Context(), fencedKey("*"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("missing proof changed drain state: %v %v", keys, err)
	}
}

func TestNetBirdRecoveryRejectsUnsafeRequestsWithoutDialing(t *testing.T) {
	leader, peer := netbirdRecoveryControllers(t)
	var probes atomic.Int32
	sub, err := peer.serveRecovery(t.Context(), func(context.Context, string) error {
		probes.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := peer.conn.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"127.0.0.1", "10.200.1.2", "8.8.8.8", "10.251.0.99", "::1"} {
		t.Run(address, func(t *testing.T) {
			// Even a matching adopted grant must not authorize a loopback,
			// public or mesh probe. The spare private address stays unadopted.
			peer.services.mu.Lock()
			peer.services.current.HostGrants[0].PrivateIP = "10.251.0.11"
			if address != "10.251.0.99" {
				peer.services.current.HostGrants[0].PrivateIP = address
			}
			peer.services.mu.Unlock()
			request := netbirdRecoveryRequest{Requester: "controller-a", Responder: "controller-b", Authority: "01M4EB0GDPPHGJPPVY77EMZQKT", Node: "node-a", Address: address}
			payload, _ := protocol.EncodeJSON(request)
			now := time.Now()
			envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: netbirdRecoveryRequestKind,
				Actor: "controller-a", OperationID: entityid.New(), Generation: 9, Epoch: 3}, now, now.Add(netbirdRecoveryLifetime), leader.key)
			if err != nil {
				t.Fatal(err)
			}
			wire, _ := protocol.EncodeJSON(envelope)
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if reply, err := leader.conn.RequestWithContext(ctx, netbirdRecoverySubject("gru", "controller-b"), wire); err == nil {
				t.Fatalf("unsafe target got a response: %s", reply.Data)
			}
		})
	}
	if probes.Load() != 0 {
		t.Fatal("unsafe/unadopted address was dialed")
	}
}

func TestNetBirdRecoveryRejectsUnsignedReplayedWrongNodeAndExpiredReplies(t *testing.T) {
	leader, _ := netbirdRecoveryControllers(t)
	request := netbirdRecoveryRequest{Requester: "controller-a", Responder: "controller-b", Authority: "01M4EB0GDPPHGJPPVY77EMZQKT", Node: "node-a", Address: "10.251.0.11"}
	scope, err := leader.recoveryScope(request, netbirdRecoveryRequestKind, request.Requester, entityid.New(), 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range []string{"valid", "unsigned", "replayed", "wrong-node", "wrong-controller", "expired", "disconnected", "unadopted-peer"} {
		t.Run(issue, func(t *testing.T) {
			proof := netbirdRecoveryProof{Request: request, Connected: true}
			responseScope := scope
			responseScope.Kind, responseScope.Actor = netbirdRecoveryProofKind, request.Responder
			now := time.Now()
			issued, expires := now, now.Add(netbirdRecoveryLifetime)
			switch issue {
			case "replayed":
				responseScope.OperationID = "7SR6C4VQACRFWNG35GQE7SG22C"
			case "wrong-node":
				proof.Request.Node = "node-b"
			case "wrong-controller":
				responseScope.Actor = "controller-a"
			case "expired":
				issued, expires = now.Add(-6*time.Second), now.Add(-time.Second)
			case "disconnected":
				proof.Connected = false
			case "unadopted-peer":
				leader.services.current.HostGrants = leader.services.current.HostGrants[:1]
			}
			payload, _ := protocol.EncodeJSON(proof)
			envelope, err := protocol.SignEnvelope(payload, responseScope, issued, expires, leader.key)
			if err != nil {
				t.Fatal(err)
			}
			if issue == "unsigned" {
				envelope.Signature = ""
			}
			wire, _ := protocol.EncodeJSON(envelope)
			if err := leader.verifyRecovery(wire, request, scope); (err == nil) != (issue == "valid") {
				t.Fatalf("reply %s verification: %v", issue, err)
			}
		})
	}
}
