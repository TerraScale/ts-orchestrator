package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const maxMaterialSpecBytes = 16 << 10
const maxMaterialWireBytes = maxMaterialSpecBytes + 4096
const maxMaterialReplyBytes = 64 << 10

func materialPrepareOperationID(spec []byte) string {
	digest := sha256.Sum256(spec)
	return "material-g1-" + hex.EncodeToString(digest[:16])
}

type materialPrepareReply struct {
	Receipt  managedmaterial.PreparationReceipt `json:"receipt"`
	Customer managedmaterial.CustomerEnvelope   `json:"customer"`
	Error    string                             `json:"error,omitempty"`
}

// requestMaterialPreparation asks the regional leader to prepare generation
// one material for the exact signed spec. Preparation is idempotent for one
// spec, so a timed-out request is repeated with a freshly signed envelope.
// The reply is authenticated against the operator's controller key pin.
func requestMaterialPreparation(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	spec managedmaterial.InitialSpec,
) (materialPrepareReply, error) {
	payload, err := protocol.EncodeJSON(spec)
	if err != nil {
		return materialPrepareReply{}, err
	}
	if len(payload) > maxMaterialSpecBytes {
		return materialPrepareReply{}, errors.New("material preparation spec exceeds size limit")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return materialPrepareReply{}, err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanPrepareManagedMaterial {
		return materialPrepareReply{}, errors.New("operator is not authorized to prepare managed material")
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return materialPrepareReply{}, err
	}
	controllerKey, err := decodePublicKey(cfg.Operator.ControllerPublicKey)
	if err != nil {
		return materialPrepareReply{}, fmt.Errorf("material preparation controller trust pin: %w", err)
	}
	var lastErr error
	for attempt := range 3 {
		epoch, err := authoritySnapshot(ctx, runtime, cfg.NATS.Cell)
		if err != nil {
			return materialPrepareReply{}, err
		}
		now := time.Now().UTC()
		envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
			Region: cfg.NATS.Cell, Kind: managedKindMaterialPrepare, Actor: cfg.Operator.Actor,
			OperationID: materialPrepareOperationID(payload), Generation: 1, Epoch: epoch,
		}, now, now.Add(time.Minute), codec.PrivateKey)
		if err != nil {
			return materialPrepareReply{}, err
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			return materialPrepareReply{}, err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, managedAdmissionSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr != nil {
			lastErr = fmt.Errorf("request managed material preparation: %w", requestErr)
			if (errors.Is(requestErr, nats.ErrTimeout) || errors.Is(requestErr, context.DeadlineExceeded) ||
				errors.Is(requestErr, nats.ErrNoResponders)) && ctx.Err() == nil && attempt < 2 {
				continue
			}
			return materialPrepareReply{}, lastErr
		}
		if len(message.Data) == 0 || len(message.Data) > maxMaterialReplyBytes {
			return materialPrepareReply{}, errors.New("material preparation response exceeds size limit")
		}
		var reply materialPrepareReply
		if err := json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)); err != nil {
			return materialPrepareReply{}, err
		}
		if reply.Error != "" {
			return materialPrepareReply{}, fmt.Errorf("material preparation request was rejected: %s", reply.Error)
		}
		if err := verifyMaterialPrepareReply(reply, controllerKey, cfg.NATS.Cell, spec); err != nil {
			return materialPrepareReply{}, fmt.Errorf("unauthenticated material preparation response: %w", err)
		}
		return reply, nil
	}
	return materialPrepareReply{}, lastErr
}

func verifyMaterialPrepareReply(reply materialPrepareReply, controllerKey ed25519.PublicKey,
	cell string, spec managedmaterial.InitialSpec,
) error {
	return managedmaterial.VerifyPreparationReply(reply.Receipt, reply.Customer, controllerKey,
		cell, spec.PartitionID, spec)
}

func serveMaterialPreparation(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy,
	service managedmaterial.PreparationService,
) (*nats.Subscription, error) {
	return serveManagedAdmissionKind(ctx, conn, cell, managedKindMaterialPrepare, func(ctx context.Context, message *nats.Msg) {
		if len(message.Data) > maxMaterialWireBytes || !service.Fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		reply, err := verifyAndPrepareMaterial(requestCtx, message.Data, cell, policy, service)
		if err != nil {
			reply = materialPrepareReply{Error: err.Error()}
		}
		wire, err := json.Marshal(reply)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndPrepareMaterial(ctx context.Context, wire []byte, cell string, policy signerPolicy,
	service managedmaterial.PreparationService,
) (materialPrepareReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxMaterialWireBytes); err != nil {
		return materialPrepareReply{}, err
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(envelope.Payload, &spec, maxMaterialSpecBytes); err != nil {
		return materialPrepareReply{}, err
	}
	canonical, err := protocol.EncodeJSON(spec)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return materialPrepareReply{}, errors.New("signed material preparation is not canonical")
	}
	grant, exists := policy.grants[envelope.Actor]
	if !exists || !grant.CanPrepareManagedMaterial {
		return materialPrepareReply{}, errors.New("material preparation actor is unauthorized")
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor {
		return materialPrepareReply{}, errors.New("material preparation signing key is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: managedKindMaterialPrepare, Actor: trusted.Actor,
		OperationID: materialPrepareOperationID(canonical), Generation: 1, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return materialPrepareReply{}, err
	}
	if envelope.Epoch == 0 || service.Fencer.Current().Epoch != envelope.Epoch {
		return materialPrepareReply{}, authority.ErrFenced
	}
	receipt, err := service.PrepareInitial(ctx, envelope.Epoch, spec.PartitionID, spec, time.Now().UTC())
	if err != nil {
		return materialPrepareReply{}, err
	}
	bundle, err := service.Repository.ReadPinned(ctx, receipt.Object,
		service.ControllerKey.Public().(ed25519.PublicKey))
	if err != nil {
		return materialPrepareReply{}, err
	}
	return materialPrepareReply{Receipt: receipt, Customer: bundle.Customer}, nil
}
