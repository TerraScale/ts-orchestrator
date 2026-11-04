package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

func TestNetBirdRecoveryRejectsUnsignedReplayedWrongNodeAndExpiredReplies(t *testing.T) {
	leader, _ := netbirdRecoveryControllers(t)
	request := netbirdRecoveryRequest{Requester: "controller-a", Responder: "controller-b", Authority: "01M4EB0GDPPHGJPPVY77EMZQKT", Node: "node-a", Address: "10.251.0.11"}
	scope, err := leader.recoveryScope(request, netbirdRecoveryRequestKind, request.Requester, entityid.New(), 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range []string{"valid", "unsigned"} {
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
