package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
)

const brokerTicketRequestMaxBytes = 4096

// Broker RPCs must stay outside the durable ts.control.*.> stream. A request
// published into that stream receives a JetStream PubAck before the broker's
// signed ticket or fence acknowledgement.
func brokerRPCSubject(cell, operation, recipient string) string {
	return "ts.broker." + cell + "." + operation + "." + recipient
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
	if cfg.NATS.Lab {
		return nil, nil, nil
	}
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
	mu                                sync.Mutex
	commitMu                          sync.Mutex
	runtime                           *natscell.Runtime
	store                             *brokerauth.Store
	control                           *authority.Runtime
	issuer                            *brokerauth.Issuer
	public                            ed25519.PublicKey
	clock                             brokerauth.ClockProbe
	cell, broker, account, initialJWT string
	applied                           uint64
	brokers                           []string
	ackedSequence                     uint64
	ackedHash                         string
	acked                             map[string]fenceAck
}

func startBrokerGate(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	control *authority.Runtime, candidateID string, private ed25519.PrivateKey,
	public ed25519.PublicKey, clock brokerauth.ClockProbe) (*brokerGate, error) {
	if cfg.NATS.Lab {
		return nil, nil
	}
	if runtime.Bridge() == nil || clock == nil || len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("production broker gate prerequisites are unavailable")
	}
	if err := natscell.ValidateBrokerControllerCredentials(cfg.NATS.CredentialsFile, cfg.NATS.Cell, cfg.NATS.Instance); err != nil {
		return nil, err
	}
	store, err := brokerauth.OpenStore(ctx, runtime.JetStream(), cfg.NATS.Cell, control)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]struct{}, len(cfg.NATS.Embedded.BrokerIDs))
	for _, broker := range cfg.NATS.Embedded.BrokerIDs {
		allowed[broker] = struct{}{}
	}
	gate := &brokerGate{runtime: runtime, store: store, control: control, public: public, clock: clock,
		cell: cfg.NATS.Cell, broker: cfg.NATS.Instance, account: runtime.CellAccount(), initialJWT: runtime.InitialCellJWT(),
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
	fenceSubject := brokerRPCSubject(gate.cell, "fence", gate.broker)
	fenceSubscription, err := runtime.Conn().Subscribe(fenceSubject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > brokerTicketRequestMaxBytes {
			return
		}
		var request fenceRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		ack, err := gate.fenceClaim(requestCtx, request)
		if err != nil {
			return
		}
		wire, err := json.Marshal(ack)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
	if err != nil {
		_ = subscription.Unsubscribe()
		return nil, fmt.Errorf("serve broker claim fences: %w", err)
	}
	go func() {
		defer subscription.Unsubscribe()
		defer fenceSubscription.Unsubscribe()
		defer runtime.Bridge().Fence()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		lastError := ""
		for {
			if err := gate.renew(ctx); err != nil {
				runtime.Bridge().Fence()
				cause := err.Error()
				if cause != lastError {
					slog.Warn("regional broker gate closed", "cause", cause)
					lastError = cause
				}
			} else if lastError != "" {
				slog.Info("regional broker gate renewed")
				lastError = ""
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return gate, nil
}

func (g *brokerGate) renew(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, err := g.clock.Measure(); err != nil {
		return err
	}
	claim, err := g.store.Read(ctx, g.account)
	if errors.Is(err, brokerauth.ErrNoClaim) && g.control.Current().CanMutate() {
		claim, err = g.store.Commit(ctx, g.control.Current().Epoch, g.account, g.initialJWT, 0)
	}
	if err != nil {
		return err
	}
	if claim.Sequence != g.applied {
		if err := g.runtime.ApplyCellClaim(ctx, claim.Sequence, claim.JWT); err != nil {
			return err
		}
		g.applied = claim.Sequence
	}
	lease, err := authority.Observe(ctx, g.runtime.JetStream(), g.cell)
	if err != nil || !lease.Ready || lease.CandidateID == "" {
		return authority.ErrNotLeader
	}
	request, err := brokerauth.NewRequest(g.cell, g.broker, g.account)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(request)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, brokerauth.MaxTicketRoundTrip)
	defer cancel()
	started := time.Now()
	reply, err := g.runtime.Conn().RequestWithContext(requestCtx,
		brokerRPCSubject(g.cell, "ticket", lease.CandidateID), wire)
	finished := time.Now()
	if err != nil {
		return err
	}
	if len(reply.Data) == 0 || len(reply.Data) > brokerauth.MaxTicketWireBytes {
		return errors.New("broker ticket reply is too large")
	}
	var signed brokerauth.SignedTicket
	if err := json.Unmarshal(reply.Data, &signed, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	current, err := g.store.Read(ctx, g.account)
	if err != nil {
		return err
	}
	lease, err = authority.Observe(ctx, g.runtime.JetStream(), g.cell)
	if err != nil {
		return err
	}
	bound, err := g.clock.Measure()
	if err != nil {
		return err
	}
	_, deadline, err := brokerauth.VerifyTicket(signed, g.public, request, started, finished, bound, current, lease)
	if err != nil {
		return err
	}
	if current.Sequence != g.applied {
		return brokerauth.ErrClaimChanged
	}
	return g.runtime.Bridge().OpenUntil(current.Sequence, current.JWT, deadline)
}

// commitAndFence uses the issuer's Store, so the local signing mutex orders
// the replacement behind every earlier ticket. A replacement is effective
// only when each named broker proves local application and old socket closure.
func (g *brokerGate) commitAndFence(ctx context.Context, raw string, expectedSequence uint64) (fenceResult, error) {
	result := fenceResult{Acks: make(map[string]fenceAck)}
	if g == nil {
		return result, authority.ErrNotLeader
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
	if prior.JWT != raw {
		g.runtime.Bridge().Fence()
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
		if broker == g.broker {
			ack, err = g.fenceClaim(ctx, request)
		} else {
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

func (g *brokerGate) fenceClaim(ctx context.Context, request fenceRequest) (fenceAck, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if request.Cell != g.cell || request.Account != g.account || request.Sequence == 0 || request.Hash == "" {
		return fenceAck{}, errors.New("broker fence target is invalid")
	}
	claim, err := g.store.Read(ctx, g.account)
	if err != nil {
		return fenceAck{}, err
	}
	if claim.Sequence != request.Sequence || claim.Hash != request.Hash {
		return fenceAck{}, brokerauth.ErrClaimChanged
	}
	g.runtime.Bridge().FenceClaim(request.Sequence)
	if err := g.runtime.ApplyCellClaim(ctx, claim.Sequence, claim.JWT); err != nil {
		return fenceAck{}, err
	}
	g.applied = claim.Sequence
	for g.runtime.Bridge().Status().ActiveSessions != 0 {
		if err := ctx.Err(); err != nil {
			return fenceAck{}, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	status := g.runtime.Bridge().Status()
	if status.Open || status.ActiveSessions != 0 {
		return fenceAck{}, errors.New("broker gate did not close its old sessions")
	}
	return fenceAck{Broker: g.broker, Cell: g.cell, Account: g.account,
		Sequence: claim.Sequence, Hash: claim.Hash}, nil
}
