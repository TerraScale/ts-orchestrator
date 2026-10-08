package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/globalcontrol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
)

// A cell spec for another region travels through the global control
// stream (TS-562). The operator signs a cell.spec.relay request for the
// target region around the signed spec and hands it to the home region's
// global leader in a cell.spec.publish request; the global leader stores the
// relay request as the target's document in TS_GLOBAL_CONTROL, and every
// region's mirror carries it. The target's authority leader applies it only
// when the relay request's signer is trusted in the target's own signed
// config and the spec passes the target's own admission, as a local
// ts-orch apply would. The relay therefore never widens authority.
const (
	cellSpecPublishKind = "cell.spec.publish"
	cellSpecRelayKind   = "cell.spec.relay"
	// relayRecheck offers the relayed spec again, so a new leader applies
	// it without waiting for another change.
	relayRecheck = 10 * time.Second
)

// relayTarget reads the cell and generation a signed spec names, without
// verifying it: only the target region holds the roots to verify it.
func relayTarget(signedSpec []byte) (string, uint64, error) {
	var signed cellspec.Signed
	if err := protocol.DecodeStrict(signedSpec, &signed, cellspec.MaxSignedBytes); err != nil {
		return "", 0, fmt.Errorf("decode signed cell spec: %w", err)
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return "", 0, fmt.Errorf("cell spec envelope: %w", err)
	}
	var header struct {
		Generation uint64 `json:"generation"`
	}
	if envelope.Scope.Domain != cellspec.Domain || json.Unmarshal(envelope.Payload, &header) != nil || header.Generation == 0 {
		return "", 0, errors.New("the file is not a signed cell spec")
	}
	return envelope.Scope.Cell, header.Generation, nil
}

// operatorSpecRelay hands a signed spec for target, another region, to
// the home region's global leader.
func operatorSpecRelay(ctx context.Context, cfg Config, runtime *natscell.Runtime, target string, signedSpec []byte,
	output io.Writer,
) error {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	relay, err := protocol.SignEnvelope(signedSpec, protocol.EnvelopeScope{Region: target, Kind: cellSpecRelayKind,
		Actor: cfg.Operator.Actor, OperationID: entityid.New(), Generation: 1,
	}, now, now.Add(cellspec.MaxSpecLifetime), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(relay)
	if err != nil {
		return err
	}
	data, err := requestAuthority(ctx, cfg, runtime, protocol.GlobalScope, cellSpecPublishKind, "cell-spec", wire)
	if err != nil {
		return fmt.Errorf("relay the spec for %s through the global home region: %w", target, err)
	}
	var reply specReply
	if err := protocol.DecodeStrict(data, &reply, 3*cellspec.MaxSpecBytes); err != nil {
		return fmt.Errorf("decode %s reply: %w", cellSpecPublishKind, err)
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	return printJSON(output, struct {
		Status     string `json:"status"`
		Cell       string `json:"cell"`
		Generation uint64 `json:"generation"`
	}{reply.Status, target, reply.Spec.Generation})
}

// serveCellSpecRelay answers cell.spec.publish on the home region's global
// leader, on the host registration subject every operator credential may
// publish to; the regional leader's handler leaves the kind to it.
func serveCellSpecRelay(ctx context.Context, conn *nats.Conn, cfg Config, policy signerPolicy, global *globalControl,
) (*nats.Subscription, error) {
	peers := globalMirrorPeers(cfg.NATS)
	return conn.Subscribe(hostRegistrationSubject(cfg.NATS.Cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxRegistrationWireBytes ||
			!global.authority.Current().CanMutate() {
			return
		}
		var envelope protocol.Envelope
		if protocol.DecodeStrict(message.Data, &envelope, maxRegistrationWireBytes) != nil || envelope.Kind != cellSpecPublishKind {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		reply, err := relayCellSpec(requestCtx, message.Data, policy, global, peers)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !global.authority.Current().CanMutate() {
			return
		}
		if err != nil {
			reply = specReply{Error: err.Error()}
		}
		if wire, err := json.Marshal(reply); err == nil {
			_ = message.Respond(wire)
		}
	})
}

// relayCellSpec stores an operator's relay request as the target region's
// document. It checks what it can without the target's trust: the request
// is the publishing operator's own, for an interregion peer, around a spec
// for that peer that is not older than the one waiting there.
func relayCellSpec(ctx context.Context, wire []byte, policy signerPolicy, global *globalControl, peers []string,
) (specReply, error) {
	request, actor, err := verifyCellRequest(wire, policy, global.authority)
	if err != nil {
		return specReply{}, err
	}
	var relay protocol.Envelope
	if err := protocol.DecodeStrict(request.Payload, &relay, maxRegistrationWireBytes); err != nil {
		return specReply{}, fmt.Errorf("decode the relayed request: %w", err)
	}
	if relay.Kind != cellSpecRelayKind || relay.Actor != actor || relay.KeyID != request.KeyID {
		return specReply{}, errors.New("the relayed request must be the publishing operator's own cell.spec.relay")
	}
	cell, err := protocol.RegionToken(relay.Region)
	if err != nil || !slices.Contains(peers, cell) {
		return specReply{}, fmt.Errorf("cell %q is not an interregion peer of this region", relay.Region)
	}
	target, generation, err := relayTarget(relay.Payload)
	if err != nil {
		return specReply{}, err
	}
	if target != cell {
		return specReply{}, fmt.Errorf("the spec is for cell %q, not %q", target, cell)
	}
	// A spec this binary cannot decode never travels, unless it only needs
	// a newer binary than the home runs: the target may understand it.
	spec, err := cellspec.Candidate(relay.Payload)
	if newer := (*cellspec.NewerBinaryError)(nil); err != nil && !errors.As(err, &newer) {
		return specReply{}, fmt.Errorf("decode the relayed cell spec: %w", err)
	}
	spec.Generation = generation
	// An older spec never displaces the one waiting; an equal generation
	// may (a renewed signature). The append is conditional on the record
	// this check saw.
	olderThanWaiting := func(prior []byte) error {
		var waiting protocol.Envelope
		if prior == nil || protocol.DecodeStrict(prior, &waiting, maxRegistrationWireBytes) != nil {
			return nil
		}
		if _, pending, err := relayTarget(waiting.Payload); err == nil && generation < pending {
			return fmt.Errorf("cell %s already has generation %d waiting; generation %d is older", target, pending, generation)
		}
		return nil
	}
	if _, err := global.writer.PutDocument(ctx, request.Epoch, globalcontrol.KindCellSpec, target, request.Payload,
		olderThanWaiting); err != nil {
		return specReply{}, err
	}
	slog.Info("cell spec relayed", observability.ComponentKey, "cellspec", "actor", actor, "cell", target,
		"generation", generation)
	return specReply{Spec: spec, Status: "relayed"}, nil
}

// followRelayedSpecs applies the spec the home region relays for this cell
// on the authority leader. Followers adopt the result from TS_SERVICE_SET.
func (r *specRegistry) followRelayedSpecs(ctx context.Context, reader *globalcontrol.Reader, policy signerPolicy,
	fencer authority.Fencer, hosts *host.Controller,
) error {
	var reported string
	return reader.Follow(ctx, globalcontrol.KindCellSpec, r.cell, relayRecheck,
		func(ctx context.Context, document globalcontrol.Document) {
			snapshot := fencer.Current()
			if !snapshot.CanMutate() {
				return
			}
			_, err := r.applyRelayed(ctx, document.Payload, policy, snapshot.Epoch, fencer, hosts)
			if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) {
				return
			}
			outcome := fmt.Sprint(document.Sequence, err)
			if err != nil && outcome != reported {
				slog.Error("relayed cell spec refused; keeping the current spec", observability.ComponentKey, "cellspec",
					"sequence", document.Sequence, "error", err)
			}
			reported = outcome
		})
}

// applyRelayed verifies the relay request against this cell's trusted
// signers and applies its spec like a local apply.
func (r *specRegistry) applyRelayed(ctx context.Context, wire []byte, policy signerPolicy, epoch uint64,
	fencer authority.Fencer, hosts *host.Controller,
) (specReply, error) {
	var relay protocol.Envelope
	if err := protocol.DecodeStrict(wire, &relay, maxRegistrationWireBytes); err != nil {
		return specReply{}, fmt.Errorf("decode the relayed request: %w", err)
	}
	trusted, ok := policy.trusted(relay.KeyID)
	if !ok || trusted.Actor != relay.Actor {
		return specReply{}, errors.New("the relayed request's signer is not trusted in this cell")
	}
	if err := protocol.VerifyEnvelope(relay, protocol.EnvelopeScope{Region: policy.cell, Kind: cellSpecRelayKind,
		Actor: trusted.Actor, OperationID: relay.OperationID, Generation: 1,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: cellspec.MaxSpecLifetime, ClockSkew: 30 * time.Second}); err != nil {
		return specReply{}, fmt.Errorf("verify the relayed request: %w", err)
	}
	return r.apply(ctx, relay.Payload, relay.KeyID, epoch, fencer, hosts)
}
