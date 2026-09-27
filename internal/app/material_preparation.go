package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const maxMaterialSpecBytes = 16 << 10
const maxMaterialWireBytes = maxMaterialSpecBytes + 4096

func materialPrepareSubject(cell string) string { return "ts.orch.v1." + cell + ".material.prepare" }

func materialPrepareOperationID(spec []byte) string {
	digest := sha256.Sum256(spec)
	return "material-g1-" + hex.EncodeToString(digest[:16])
}

type materialPrepareReply struct {
	Receipt  managedmaterial.PreparationReceipt `json:"receipt"`
	Customer managedmaterial.CustomerEnvelope   `json:"customer"`
	Error    string                             `json:"error,omitempty"`
}

func operatorMaterialPrepare(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) > maxMaterialSpecBytes {
		return errors.New("material preparation spec exceeds size limit")
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(data, &spec, maxMaterialSpecBytes); err != nil {
		return err
	}
	payload, err := protocol.EncodeJSON(spec)
	if err != nil {
		return err
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanPrepareManagedMaterial {
		return errors.New("operator is not authorized to prepare managed material")
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return err
	}
	snapshot, err := authority.Observe(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return errors.New("regional authority lease is not current")
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "material.prepare", Actor: cfg.Operator.Actor,
		OperationID: materialPrepareOperationID(payload), Generation: 1, Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	message, err := runtime.Conn().RequestWithContext(requestCtx, materialPrepareSubject(cfg.NATS.Cell), wire)
	if err != nil {
		return fmt.Errorf("request managed material preparation: %w", err)
	}
	var reply materialPrepareReply
	if err := json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	if reply.Receipt.Spec.PlacementDatabaseID != spec.PlacementDatabaseID || reply.Receipt.Generation != 1 ||
		reply.Customer.Version != 1 {
		return errors.New("controller returned a different material preparation")
	}
	returned, err := protocol.EncodeJSON(reply.Receipt.Spec)
	if err != nil || !bytes.Equal(returned, payload) {
		return errors.New("controller returned a different material spec")
	}
	return printJSON(output, reply)
}

func serveMaterialPreparation(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy,
	service managedmaterial.PreparationService,
) (*nats.Subscription, error) {
	return conn.Subscribe(materialPrepareSubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxMaterialWireBytes ||
			!service.Fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		Region: cell, Kind: "material.prepare", Actor: trusted.Actor,
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
	bundle, err := service.Repository.ReadPinned(ctx, receipt.Object)
	if err != nil {
		return materialPrepareReply{}, err
	}
	return materialPrepareReply{Receipt: receipt, Customer: bundle.Customer}, nil
}
