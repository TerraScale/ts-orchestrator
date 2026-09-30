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

const maxCredentialRequestBytes = 16 << 10
const maxCredentialReplyBytes = 512 << 10

type materialCredentialsReply struct {
	Credential managedmaterial.CredentialReply `json:"credential"`
	Status     string                          `json:"status"`
	Error      string                          `json:"error,omitempty"`
}

func operatorMaterialCredentials(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	path string, output io.Writer,
) error {
	data, err := readBoundedConfigFile(path)
	if err != nil || len(data) > maxCredentialRequestBytes {
		return errors.New("client credential request is invalid or oversized")
	}
	var request managedmaterial.CredentialRequest
	if err := protocol.DecodeStrict(data, &request, maxCredentialRequestBytes); err != nil {
		return err
	}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return err
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	if !policy.canManageClientKeys(cfg.Operator.Actor, request.DatabaseID, request.PartitionID) {
		return errors.New("operator lacks the exact client-key scope")
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return err
	}
	controllerKey, err := decodePublicKey(cfg.Operator.ControllerPublicKey)
	if err != nil {
		return err
	}
	snapshot, err := authority.Observe(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 ||
		!time.Now().Before(snapshot.ExpiresAt) {
		return errors.New("regional authority lease is not current")
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: managedKindCredentials, Actor: cfg.Operator.Actor,
		OperationID: request.OperationID, Generation: request.ExpectedGeneration + 1,
		Epoch: snapshot.Epoch,
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
	message, err := runtime.Conn().RequestWithContext(requestCtx, managedAdmissionSubject(cfg.NATS.Cell), wire)
	if err != nil {
		return fmt.Errorf("request client credential change: %w", err)
	}
	if len(message.Data) == 0 || len(message.Data) > maxCredentialReplyBytes {
		return errors.New("client credential reply is invalid or oversized")
	}
	var reply materialCredentialsReply
	if err := json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if reply.Error != "" || reply.Status != "pending" {
		return errors.New("client credential change was rejected")
	}
	if err := managedmaterial.VerifyCredentialReply(reply.Credential, request, controllerKey,
		cfg.NATS.Cell); err != nil {
		return fmt.Errorf("client credential reply cannot be authenticated: %w", err)
	}
	return printJSON(output, reply)
}

func serveMaterialCredentials(ctx context.Context, conn *nats.Conn, cell string,
	policy signerPolicy, service managedmaterial.CredentialService,
) (*nats.Subscription, error) {
	return serveManagedAdmissionKind(ctx, conn, cell, managedKindCredentials, func(ctx context.Context, message *nats.Msg) {
		if len(message.Data) > maxCredentialRequestBytes+4096 || !service.Preparation.Fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		reply, err := verifyAndApplyMaterialCredentials(requestCtx, message.Data, cell, policy, service)
		if err != nil {
			reply = materialCredentialsReply{Error: "credential change was rejected"}
		}
		wire, err := protocol.EncodeJSON(reply)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndApplyMaterialCredentials(ctx context.Context, wire []byte, cell string,
	policy signerPolicy, service managedmaterial.CredentialService,
) (materialCredentialsReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxCredentialRequestBytes+4096); err != nil {
		return materialCredentialsReply{}, err
	}
	var request managedmaterial.CredentialRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxCredentialRequestBytes); err != nil {
		return materialCredentialsReply{}, err
	}
	canonical, err := protocol.EncodeJSON(request)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) ||
		!policy.canManageClientKeys(envelope.Actor, request.DatabaseID, request.PartitionID) {
		return materialCredentialsReply{}, errors.New("client credential request is not canonical or authorized")
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor || request.ExpectedGeneration == ^uint64(0) {
		return materialCredentialsReply{}, errors.New("client credential request signer is invalid")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: managedKindCredentials, Actor: trusted.Actor,
		OperationID: request.OperationID, Generation: request.ExpectedGeneration + 1,
		Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		return materialCredentialsReply{}, err
	}
	if envelope.Epoch == 0 || service.Preparation.Fencer.Current().Epoch != envelope.Epoch {
		return materialCredentialsReply{}, authority.ErrFenced
	}
	receipt, err := service.Apply(ctx, envelope.Epoch, request, time.Now().UTC())
	if err != nil {
		return materialCredentialsReply{}, err
	}
	initial, bundle, err := service.Preparation.CurrentBundle(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return materialCredentialsReply{}, err
	}
	initialWire, err := protocol.EncodeJSON(initial)
	if err != nil {
		return materialCredentialsReply{}, err
	}
	initialSum := sha256.Sum256(initialWire)
	if hex.EncodeToString(initialSum[:]) != request.InitialReceiptSHA {
		return materialCredentialsReply{}, managedmaterial.ErrMaterialConflict
	}
	return materialCredentialsReply{Status: "pending", Credential: managedmaterial.CredentialReply{
		Initial: initial, AuthorityKey: bundle.Authority.TrustedKey, Receipt: receipt,
	}}, nil
}
