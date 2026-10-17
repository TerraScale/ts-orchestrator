package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/nats-io/nats.go"
)

// Native application and the public gate have no ordinary-controller proxy.
type rootBrokerGate struct {
	broker    *rootBrokerRuntime
	mu        sync.Mutex
	public    ed25519.PublicKey
	clock     brokerauth.ClockProbe
	applied   uint64
	handlerMu sync.Mutex
	stopping  bool
	handlers  sync.WaitGroup
	slots     chan struct{}
}

func startRootBrokerGate(broker *rootBrokerRuntime) error {
	if err := broker.guard(broker.ctx); err != nil {
		return err
	}
	raw, err := os.ReadFile(broker.cfg.NATS.Embedded.TicketPublicKeyFile)
	if err != nil {
		return err
	}
	public, err := decodePublicKey(string(raw))
	if err != nil {
		return err
	}
	gate := &rootBrokerGate{broker: broker, public: public, clock: hostClockProbe(), slots: make(chan struct{}, 2)}
	subscription, err := broker.runtime.Conn().Subscribe(brokerRPCSubject(broker.cfg.NATS.Cell, "fence", broker.cfg.NATS.Instance), func(message *nats.Msg) {
		gate.handlerMu.Lock()
		defer gate.handlerMu.Unlock()
		if gate.stopping || broker.ctx.Err() != nil || message.Reply == "" || len(message.Data) == 0 || len(message.Data) > brokerTicketRequestMaxBytes {
			return
		}
		select {
		case gate.slots <- struct{}{}:
			gate.handlers.Go(func() { defer func() { <-gate.slots }(); gate.serveFence(message) })
		default:
		}
	})
	if err != nil {
		return err
	}
	broker.workers.Go(func() {
		defer func() {
			gate.handlerMu.Lock()
			gate.stopping = true
			gate.handlerMu.Unlock()
			_ = subscription.Unsubscribe()
			gate.handlers.Wait()
		}()
		defer broker.runtime.Bridge().Fence()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		last := ""
		for broker.ctx.Err() == nil {
			ctx, cancel := context.WithTimeout(broker.ctx, 30*time.Second)
			err := gate.renew(ctx)
			cancel()
			if err != nil {
				broker.runtime.Bridge().Fence()
				if err.Error() != last {
					slog.WarnContext(broker.ctx, "root regional broker gate closed", "cause", err)
				}
				last = err.Error()
			} else {
				last = ""
			}
			select {
			case <-broker.ctx.Done():
			case <-ticker.C:
			}
		}
	})
	return nil
}

func (gate *rootBrokerGate) serveFence(message *nats.Msg) {
	broker := gate.broker
	if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > brokerTicketRequestMaxBytes {
		return
	}
	var request fenceRequest
	if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(broker.ctx, 3*time.Second)
	defer cancel()
	ack, err := gate.fenceClaim(ctx, request)
	if err != nil {
		return
	}
	wire, err := json.Marshal(ack)
	if err == nil && broker.guard(ctx) == nil {
		_ = message.Respond(wire)
	}
}

func (gate *rootBrokerGate) renew(ctx context.Context) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	broker := gate.broker
	ctx, cancelOriginal := broker.operationContext(ctx)
	defer cancelOriginal()
	if err := broker.guard(ctx); err != nil {
		return err
	}
	if _, err := gate.clock.Measure(); err != nil {
		return err
	}
	store, err := brokerauth.OpenStore(ctx, broker.runtime.JetStream(), broker.cfg.NATS.Cell, nil)
	if err != nil {
		return err
	}
	lease, err := authority.Observe(ctx, broker.runtime.JetStream(), broker.cfg.NATS.Cell)
	if err != nil || !lease.Ready || lease.DeploymentID != broker.authority.accepted.DeploymentID || lease.CandidateID == "" {
		return authority.ErrNotLeader
	}
	claim, err := store.Read(ctx, broker.runtime.CellAccount())
	if err != nil {
		return err
	}
	if claim.Sequence != gate.applied {
		if err := gate.applyClaim(ctx, claim); err != nil {
			return err
		}
	}
	request, err := brokerauth.NewRequest(broker.cfg.NATS.Cell, broker.cfg.NATS.Instance, broker.runtime.CellAccount())
	if err != nil {
		return err
	}
	wire, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := broker.guard(ctx); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, brokerauth.MaxTicketRoundTrip)
	defer cancel()
	started := time.Now()
	reply, err := broker.runtime.Conn().RequestWithContext(requestCtx, brokerRPCSubject(broker.cfg.NATS.Cell, "ticket", lease.CandidateID), wire)
	finished := time.Now()
	if err != nil {
		return err
	}
	if len(reply.Data) == 0 || len(reply.Data) > brokerauth.MaxTicketWireBytes {
		return errors.New("broker ticket reply is too large")
	}
	var signed brokerauth.SignedTicket
	if json.Unmarshal(reply.Data, &signed, json.RejectUnknownMembers(true)) != nil {
		return errors.New("broker ticket reply is invalid")
	}
	current, err := store.Read(ctx, broker.runtime.CellAccount())
	if err != nil {
		return err
	}
	lease, err = authority.Observe(ctx, broker.runtime.JetStream(), broker.cfg.NATS.Cell)
	if err != nil || lease.DeploymentID != broker.authority.accepted.DeploymentID {
		return authority.ErrFenced
	}
	bound, err := gate.clock.Measure()
	if err != nil {
		return err
	}
	_, deadline, err := brokerauth.VerifyTicket(signed, gate.public, request, started, finished, bound, current, lease)
	if err != nil {
		return err
	}
	if current.Sequence != gate.applied || current.Hash != claim.Hash || current.JWT != claim.JWT {
		return brokerauth.ErrClaimChanged
	}
	if err := broker.guard(ctx); err != nil {
		return err
	}
	view, err := broker.runtime.ReadControllerAccount(ctx)
	if err != nil || view.Account != current.Account || view.JWT != current.JWT {
		return brokerauth.ErrClaimChanged
	}
	deadline = earlier(deadline, broker.origin.ExpiresAt())
	if original, ok := ctx.Deadline(); ok {
		deadline = earlier(deadline, original)
	}
	if err := broker.guard(ctx); err != nil {
		return err
	}
	if err := broker.runtime.Bridge().OpenUntil(current.Sequence, current.JWT, deadline); err != nil {
		return err
	}
	if err := broker.guard(ctx); err != nil {
		broker.runtime.Bridge().Fence()
		return err
	}
	return nil
}

func (gate *rootBrokerGate) applyClaim(ctx context.Context, claim brokerauth.Claim) error {
	if err := gate.broker.guard(ctx); err != nil {
		return err
	}
	if err := gate.broker.runtime.ApplyCellClaim(ctx, claim.Sequence, claim.JWT); err != nil {
		return err
	}
	view, err := gate.broker.runtime.ReadControllerAccount(ctx)
	if err != nil || view.Account != claim.Account || view.JWT != claim.JWT {
		return brokerauth.ErrClaimChanged
	}
	if err := gate.broker.guard(ctx); err != nil {
		return err
	}
	gate.applied = claim.Sequence
	return nil
}

func (gate *rootBrokerGate) fenceClaim(ctx context.Context, request fenceRequest) (fenceAck, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	broker := gate.broker
	ctx, cancelOriginal := broker.operationContext(ctx)
	defer cancelOriginal()
	if request.Cell != broker.cfg.NATS.Cell || request.Account != broker.runtime.CellAccount() || request.Sequence == 0 || request.Hash == "" {
		return fenceAck{}, brokerauth.ErrClaimChanged
	}
	if err := broker.guard(ctx); err != nil {
		return fenceAck{}, err
	}
	store, err := brokerauth.OpenStore(ctx, broker.runtime.JetStream(), broker.cfg.NATS.Cell, nil)
	if err != nil {
		return fenceAck{}, err
	}
	claim, err := store.Read(ctx, request.Account)
	if err != nil || claim.Sequence != request.Sequence || claim.Hash != request.Hash {
		return fenceAck{}, brokerauth.ErrClaimChanged
	}
	if err := gate.applyClaim(ctx, claim); err != nil {
		return fenceAck{}, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for broker.runtime.Bridge().Status().ActiveSessions != 0 {
		select {
		case <-ctx.Done():
			return fenceAck{}, ctx.Err()
		case <-ticker.C:
		}
	}
	if err := broker.guard(ctx); err != nil {
		return fenceAck{}, err
	}
	current, err := store.Read(ctx, request.Account)
	if err != nil || current.Sequence != claim.Sequence || current.Hash != claim.Hash || current.JWT != claim.JWT {
		return fenceAck{}, brokerauth.ErrClaimChanged
	}
	status := broker.runtime.Bridge().Status()
	if status.Open || status.ActiveSessions != 0 || broker.guard(ctx) != nil {
		return fenceAck{}, errors.New("broker gate did not close its old sessions")
	}
	return fenceAck{Broker: broker.cfg.NATS.Instance, Cell: claim.Cell, Account: claim.Account, Sequence: claim.Sequence, Hash: claim.Hash}, nil
}
