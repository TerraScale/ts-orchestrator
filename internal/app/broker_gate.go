package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const brokerTicketRequestMaxBytes = 4096

// Broker RPCs must stay outside the durable ts.control.*.> stream. A request
// published into that stream receives a JetStream PubAck before the broker's
// signed ticket or fence acknowledgement.
func brokerRPCSubject(cell, operation, recipient string) string {
	return protocol.Broker(cell, operation, recipient)
}

var ErrBrokerFencePending = errors.New("regional broker claim fence is pending")

type fenceRequest struct {
	Cell     string `json:"cell"`
	Account  string `json:"account"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

type fenceAck struct {
	Broker   string `json:"broker"`
	Cell     string `json:"cell"`
	Account  string `json:"account"`
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

type fenceResult struct {
	Claim   brokerauth.Claim
	Acks    map[string]fenceAck
	Pending []string
}

func brokerTicketKeys(cfg Config) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if cfg.NATS.Embedded == nil || cfg.Controller.BrokerTicketKeyFile == "" || cfg.NATS.Embedded.TicketPublicKeyFile == "" {
		return nil, nil, errors.New("production broker ticket signing and pinned public keys are required")
	}
	private, err := readPrivateKey(cfg.Controller.BrokerTicketKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read broker ticket signing key: %w", err)
	}
	publicRaw, err := os.ReadFile(cfg.NATS.Embedded.TicketPublicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read pinned broker ticket key: %w", err)
	}
	public, err := decodePublicKey(string(publicRaw))
	if err != nil || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return nil, nil, errors.New("pinned broker ticket key does not match the private signer")
	}
	return private, public, nil
}

type brokerGate struct {
	mu                    sync.Mutex
	commitMu              sync.Mutex
	runtime               *natscell.Runtime
	native                controllerBrokerNative
	store                 *brokerauth.Store
	control               *authority.Runtime
	issuer                *brokerauth.Issuer
	public                ed25519.PublicKey
	clock                 brokerauth.ClockProbe
	cell, broker, account string
	deploymentID          string
	brokers               []string
	ackedSequence         uint64
	ackedHash             string
	acked                 map[string]fenceAck
}

func startBrokerGate(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	native controllerBrokerNative,
	control *authority.Runtime, deploymentID, candidateID string, private ed25519.PrivateKey,
	public ed25519.PublicKey, clock brokerauth.ClockProbe) (*brokerGate, error) {
	if runtime == nil || native == nil || clock == nil || len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize || !entityid.Valid(deploymentID) {
		return nil, errors.New("production broker gate prerequisites are unavailable")
	}
	if err := natscell.ValidateBrokerControllerCredentials(cfg.NATS.CredentialsFile, cfg.NATS.Cell, cfg.NATS.Instance); err != nil {
		return nil, err
	}
	store, err := brokerauth.OpenStore(ctx, runtime.JetStream(), cfg.NATS.Cell, control)
	if err != nil {
		return nil, err
	}
	account, err := native.ReadControllerAccount(ctx)
	if err != nil || account.Account == "" || account.JWT == "" {
		return nil, errors.New("current native broker account is unavailable")
	}
	allowed := make(map[string]struct{}, len(cfg.NATS.Embedded.BrokerIDs))
	for _, broker := range cfg.NATS.Embedded.BrokerIDs {
		allowed[broker] = struct{}{}
	}
	gate := &brokerGate{runtime: runtime, native: native, store: store, control: control, public: public, clock: clock,
		deploymentID: deploymentID,
		cell:         cfg.NATS.Cell, broker: cfg.NATS.Instance, account: account.Account,
		brokers: append([]string(nil), cfg.NATS.Embedded.BrokerIDs...)}
	gate.issuer = &brokerauth.Issuer{Store: store, Account: gate.account, Brokers: allowed, Key: private, Clock: clock}
	subject := brokerRPCSubject(gate.cell, "ticket", candidateID)
	subscription, err := runtime.Conn().Subscribe(subject, func(message *nats.Msg) {
		if len(message.Data) == 0 || len(message.Data) > brokerTicketRequestMaxBytes || message.Reply == "" {
			return
		}
		var request brokerauth.TicketRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		signed, err := gate.issuer.Issue(requestCtx, request)
		if err != nil {
			return
		}
		wire, err := json.Marshal(signed)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("serve broker ticket requests: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = subscription.Unsubscribe()
	}()
	return gate, nil
}

// commitAndFence uses the issuer's Store, so the local signing mutex orders
// the replacement behind every earlier ticket. A replacement is effective
// only when each named broker proves local application and old socket closure.
func (g *brokerGate) commitAndFence(ctx context.Context, raw string, expectedSequence uint64) (fenceResult, error) {
	result := fenceResult{Acks: make(map[string]fenceAck)}
	if g == nil {
		return result, authority.ErrNotLeader
	}
	if current := g.control.Current(); !current.CanMutate() || current.DeploymentID != g.deploymentID {
		return result, authority.ErrFenced
	}
	g.commitMu.Lock()
	defer g.commitMu.Unlock()
	g.mu.Lock()
	prior, err := g.store.Read(ctx, g.account)
	if errors.Is(err, brokerauth.ErrNoClaim) {
		err = nil
	}
	if err != nil {
		g.mu.Unlock()
		return result, err
	}
	if prior.Sequence != expectedSequence && prior.JWT != raw {
		g.mu.Unlock()
		return result, authority.ErrConflict
	}
	epoch := g.control.Current().Epoch
	claim, err := g.store.Commit(ctx, epoch, g.account, raw, expectedSequence)
	g.mu.Unlock()
	if err != nil {
		return result, err
	}
	result.Claim = claim
	if g.ackedSequence == claim.Sequence && g.ackedHash == claim.Hash {
		for broker, ack := range g.acked {
			result.Acks[broker] = ack
		}
	} else {
		g.ackedSequence, g.ackedHash = claim.Sequence, claim.Hash
		g.acked = make(map[string]fenceAck)
	}
	request := fenceRequest{Cell: g.cell, Account: g.account, Sequence: claim.Sequence, Hash: claim.Hash}
	wire, err := json.Marshal(request)
	if err != nil {
		return result, err
	}
	for _, broker := range g.brokers {
		if _, ok := result.Acks[broker]; ok {
			continue
		}
		var ack fenceAck
		{
			requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			var reply *nats.Msg
			reply, err = g.runtime.Conn().RequestWithContext(requestCtx,
				brokerRPCSubject(g.cell, "fence", broker), wire)
			cancel()
			if err == nil && len(reply.Data) <= brokerTicketRequestMaxBytes {
				err = json.Unmarshal(reply.Data, &ack, json.RejectUnknownMembers(true))
			} else if err == nil {
				err = errors.New("broker fence acknowledgement is too large")
			}
		}
		if err != nil || ack.Broker != broker || ack.Cell != g.cell || ack.Account != g.account ||
			ack.Sequence != claim.Sequence || ack.Hash != claim.Hash {
			result.Pending = append(result.Pending, broker)
			continue
		}
		result.Acks[broker] = ack
		g.acked[broker] = ack
	}
	if len(result.Pending) > 0 {
		return result, ErrBrokerFencePending
	}
	return result, nil
}
