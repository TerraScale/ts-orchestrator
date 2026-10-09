package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	netbirdRecoveryRequestKind = "netbird.recovery.request"
	netbirdRecoveryProofKind   = "netbird.recovery.proof"
	netbirdRecoveryLifetime    = 5 * time.Second
	netbirdRecoveryMaxBytes    = 4096
)

type netbirdRecoveryRequest struct {
	Requester string `json:"requester"`
	Responder string `json:"responder"`
	Authority string `json:"authority"`
	Node      string `json:"node"`
	Address   string `json:"address"`
}

type netbirdRecoveryProof struct {
	Request   netbirdRecoveryRequest `json:"request"`
	Connected bool                   `json:"connected"`
}

// Reuse the existing controller-only rollout proof grant: this is a rollout
// recovery proof, on an explicitly namespaced unit. Its protocol.Envelope kinds
// cannot decode as rolloutexec's trust health proofs; that collector drops them
// without replying. No new listener, subject grant or credential rotation.
func netbirdRecoverySubject(cell, slot string) string {
	return protocol.RolloutProofSubject(cell, "netbird-recovery/controller/"+slot)
}

func netbirdSSH(ctx context.Context, address string) error {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.IsLoopback() || netbirdClientRange.Contains(ip) {
		return errors.New("NetBird recovery requires an independent OCI private address")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ssh, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "22"))
	if err != nil {
		return err
	}
	defer ssh.Close()
	deadline, _ := ctx.Deadline()
	if err := ssh.SetReadDeadline(deadline); err != nil {
		return err
	}
	var banner [4]byte
	if _, err := io.ReadFull(ssh, banner[:]); err != nil || string(banner[:]) != "SSH-" {
		return errors.New("OCI recovery listener did not identify as SSH")
	}
	return nil
}

// The read-only SSH proof depends on adopted controller grants and authority;
// draining is authorized separately by the live or persisted release fence.
func (n *netbirdRollout) recoveryScope(request netbirdRecoveryRequest, kind, actor, operationID string, epoch uint64) (protocol.EnvelopeScope, error) {
	if n.services == nil || n.cfg.NATS.Embedded == nil || n.fence == nil || n.fence.fencer == nil ||
		request.Requester == request.Responder || !slices.Contains(n.cfg.NATS.Embedded.BrokerIDs, request.Requester) ||
		!slices.Contains(n.cfg.NATS.Embedded.BrokerIDs, request.Responder) {
		return protocol.EnvelopeScope{}, errors.New("NetBird recovery requires two configured controllers")
	}
	current := n.fence.fencer.Current()
	if !current.Ready || current.Epoch != epoch || epoch == 0 || !entityid.Valid(request.Authority) || !entityid.Valid(operationID) || current.CandidateID != request.Authority || !time.Now().Before(current.ExpiresAt) {
		return protocol.EnvelopeScope{}, errors.New("NetBird recovery request has no current regional authority")
	}
	n.services.mu.Lock()
	defer n.services.mu.Unlock()
	var requester, responder cellspec.HostGrant
	for _, grant := range n.services.current.HostGrants {
		switch grant.Controller {
		case request.Requester:
			requester = grant
		case request.Responder:
			responder = grant
		}
	}
	ip, err := netip.ParseAddr(request.Address)
	peer, peerErr := netip.ParseAddr(responder.PrivateIP)
	if request.Node == "" || requester.Node != request.Node ||
		requester.PrivateIP != request.Address || responder.Node == "" || responder.Node == request.Node ||
		err != nil || !ip.Is4() || !ip.IsPrivate() || ip.IsLoopback() || netbirdClientRange.Contains(ip) ||
		peerErr != nil || !peer.Is4() || !peer.IsPrivate() || peer.IsLoopback() || netbirdClientRange.Contains(peer) || peer == ip {
		return protocol.EnvelopeScope{}, errors.New("NetBird recovery target and peer need distinct adopted OCI controller grants")
	}
	return protocol.EnvelopeScope{Region: n.cell, Kind: kind, Actor: actor, OperationID: operationID,
		Generation: n.services.current.Generation, Epoch: epoch}, nil
}

func (n *netbirdRollout) serveRecovery(ctx context.Context, probe func(context.Context, string) error) (*nats.Subscription, error) {
	if n.conn == nil || len(n.key) != ed25519.PrivateKeySize {
		return nil, errors.New("NetBird recovery responder needs its controller connection and signing key")
	}
	return n.conn.Subscribe(netbirdRecoverySubject(n.cell, n.cfg.NATS.Instance), func(message *nats.Msg) {
		if message.Reply == "" || ctx.Err() != nil {
			return
		}
		var envelope protocol.Envelope
		var request netbirdRecoveryRequest
		if protocol.DecodeStrict(message.Data, &envelope, netbirdRecoveryMaxBytes) != nil ||
			protocol.DecodeStrict(envelope.Payload, &request, netbirdRecoveryMaxBytes) != nil || request.Responder != n.cfg.NATS.Instance {
			return
		}
		scope, err := n.recoveryScope(request, netbirdRecoveryRequestKind, request.Requester, envelope.OperationID, envelope.Epoch)
		if err != nil || protocol.VerifyEnvelope(envelope, scope, n.key.Public().(ed25519.PublicKey), time.Now(),
			protocol.VerifyPolicy{MaxLifetime: netbirdRecoveryLifetime, ClockSkew: time.Second}) != nil {
			return
		}
		probeCtx, cancel := context.WithDeadline(ctx, envelope.ExpiresAt)
		defer cancel()
		connected := probe(probeCtx, request.Address) == nil
		if probeCtx.Err() != nil {
			return
		}
		payload, err := protocol.EncodeJSON(netbirdRecoveryProof{Request: request, Connected: connected})
		if err != nil {
			return
		}
		scope.Kind, scope.Actor = netbirdRecoveryProofKind, n.cfg.NATS.Instance
		proof, err := protocol.SignEnvelope(payload, scope, time.Now(), envelope.ExpiresAt, n.key)
		if err != nil {
			return
		}
		if wire, err := protocol.EncodeJSON(proof); err == nil {
			// Production credentials grant exactly one response for five
			// seconds after this allowed subscription receives the request.
			_ = message.Respond(wire)
		}
	})
}

func (n *netbirdRollout) verifyRecovery(wire []byte, request netbirdRecoveryRequest, scope protocol.EnvelopeScope) error {
	var envelope protocol.Envelope
	var proof netbirdRecoveryProof
	scope.Kind, scope.Actor = netbirdRecoveryProofKind, request.Responder
	if err := protocol.DecodeStrict(wire, &envelope, netbirdRecoveryMaxBytes); err != nil {
		return err
	}
	if err := protocol.VerifyEnvelope(envelope, scope, n.key.Public().(ed25519.PublicKey), time.Now(),
		protocol.VerifyPolicy{MaxLifetime: netbirdRecoveryLifetime, ClockSkew: time.Second}); err != nil {
		return err
	}
	if err := protocol.DecodeStrict(envelope.Payload, &proof, netbirdRecoveryMaxBytes); err != nil {
		return err
	}
	if proof.Request != request || !proof.Connected {
		return errors.New("remote controller did not prove this node's OCI SSH path")
	}
	// Adoption or authority may change while the remote probe runs.
	current, err := n.recoveryScope(request, netbirdRecoveryProofKind, request.Responder, scope.OperationID, scope.Epoch)
	if err != nil || current != scope {
		return errors.New("NetBird recovery proof no longer matches adopted regional authority")
	}
	return nil
}

func (n *netbirdRollout) recoverySSH(ctx context.Context, node, address string) error {
	if node != n.services.controllerNode(n.cell, n.cfg.NATS.Instance) {
		return netbirdSSH(ctx, address)
	}
	// A self-dial follows the local route and proves no remote OCI ingress.
	// Require another actual controller to read the target's SSH banner.
	if n.conn == nil || len(n.key) != ed25519.PrivateKeySize || n.cfg.NATS.Embedded == nil {
		return errors.New("NetBird leader requires a fresh remote controller OCI SSH recovery proof")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	epoch, err := n.fence.leading(ctx)
	if err != nil {
		return err
	}
	for _, slot := range n.cfg.NATS.Embedded.BrokerIDs {
		if slot == n.cfg.NATS.Instance {
			continue
		}
		request := netbirdRecoveryRequest{Requester: n.cfg.NATS.Instance, Responder: slot,
			Authority: n.fence.fencer.Current().CandidateID, Node: node, Address: address}
		scope, err := n.recoveryScope(request, netbirdRecoveryRequestKind, request.Requester, entityid.New(), epoch)
		if err != nil {
			continue
		}
		payload, err := protocol.EncodeJSON(request)
		if err != nil {
			return err
		}
		now := time.Now()
		envelope, err := protocol.SignEnvelope(payload, scope, now, now.Add(netbirdRecoveryLifetime), n.key)
		if err != nil {
			return err
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			return err
		}
		attempt, stop := context.WithTimeout(ctx, 4*time.Second)
		reply, err := n.conn.RequestWithContext(attempt, netbirdRecoverySubject(n.cell, slot), wire)
		stop()
		if err == nil && n.verifyRecovery(reply.Data, request, scope) == nil {
			return n.fence.fencer.Guard(ctx, epoch)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("NetBird leader %s has no fresh remote controller OCI SSH recovery proof; no node will be drained", node)
}
