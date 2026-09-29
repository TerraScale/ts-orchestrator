package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

type materialCredentialStatusRequest struct {
	DatabaseID        string `json:"database_id"`
	PartitionID       string `json:"partition_id"`
	InitialReceiptSHA string `json:"initial_receipt_sha256"`
	Generation        uint64 `json:"generation"`
	OperationID       string `json:"operation_id"`
}

type materialCredentialMemberStatus struct {
	SeatID     string `json:"seat_id"`
	MemberID   string `json:"member_id"`
	Node       string `json:"node,omitempty"`
	Generation uint64 `json:"generation,omitzero"`
	Applied    bool   `json:"applied"`
}

type materialCredentialStatusReply struct {
	DatabaseID        string                            `json:"database_id"`
	PartitionID       string                            `json:"partition_id"`
	InitialReceiptSHA string                            `json:"initial_receipt_sha256"`
	Generation        uint64                            `json:"generation"`
	StateSHA256       string                            `json:"state_sha256"`
	Status            string                            `json:"status"`
	Members           [2]materialCredentialMemberStatus `json:"members"`
}

func operatorMaterialCredentialsStatus(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	path string, output io.Writer,
) error {
	data, err := readBoundedConfigFile(path)
	if err != nil || len(data) > maxCredentialRequestBytes {
		return errors.New("client credential status request is invalid or oversized")
	}
	var request materialCredentialStatusRequest
	if err := protocol.DecodeStrict(data, &request, maxCredentialRequestBytes); err != nil {
		return err
	}
	if request.Generation < 2 || request.OperationID == "" || request.InitialReceiptSHA == "" {
		return errors.New("client credential status request lacks a committed generation")
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
	snapshot, err := authoritySnapshot(ctx, runtime, cfg.NATS.Cell)
	if err != nil {
		return err
	}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: managedKindCredentialStatus, Actor: cfg.Operator.Actor,
		OperationID: request.OperationID, Generation: request.Generation, Epoch: snapshot,
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
	message, err := runtime.Conn().RequestWithContext(requestCtx,
		managedAdmissionSubject(cfg.NATS.Cell), wire)
	if err != nil {
		return fmt.Errorf("request client credential status: %w", err)
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &signed, maxCredentialReplyBytes); err != nil {
		return err
	}
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "material.credentials.status.reply", Actor: "controller",
		OperationID: request.OperationID, Generation: request.Generation, Epoch: snapshot,
	}, controllerKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		return err
	}
	var reply materialCredentialStatusReply
	if err := protocol.DecodeStrict(signed.Payload, &reply, maxCredentialReplyBytes); err != nil {
		return err
	}
	canonical, err := protocol.EncodeJSON(reply)
	if err != nil || !bytes.Equal(canonical, signed.Payload) ||
		reply.DatabaseID != request.DatabaseID || reply.PartitionID != request.PartitionID ||
		reply.InitialReceiptSHA != request.InitialReceiptSHA || reply.Generation != request.Generation ||
		reply.Status != "pending" && reply.Status != "applied" {
		return errors.New("client credential status reply is invalid")
	}
	return printJSON(output, reply)
}

// authoritySnapshot keeps operator status requests fenced to the current R1
// lease, as credential changes themselves are.
func authoritySnapshot(ctx context.Context, runtime *natscell.Runtime, cell string) (uint64, error) {
	snapshot, err := authority.Observe(ctx, runtime.JetStream(), cell)
	if err != nil {
		return 0, err
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 ||
		!time.Now().Before(snapshot.ExpiresAt) {
		return 0, errors.New("regional authority lease is not current")
	}
	return snapshot.Epoch, nil
}

func serveMaterialCredentialStatus(ctx context.Context, conn *nats.Conn, cell string,
	policy signerPolicy, service managedmaterial.CredentialService, hosts *host.Controller,
) (*nats.Subscription, error) {
	return serveManagedAdmissionKind(ctx, conn, cell, managedKindCredentialStatus, func(ctx context.Context, message *nats.Msg) {
		if len(message.Data) > maxCredentialRequestBytes+4096 || !service.Preparation.Fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		reply, request, epoch, err := readMaterialCredentialStatus(requestCtx, message.Data, cell,
			policy, service, hosts)
		if err != nil {
			return
		}
		payload, err := protocol.EncodeJSON(reply)
		if err != nil {
			return
		}
		now := time.Now().UTC()
		signed, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
			Region: cell, Kind: "material.credentials.status.reply", Actor: "controller",
			OperationID: request.OperationID, Generation: request.Generation, Epoch: epoch,
		}, now, now.Add(time.Minute), service.Preparation.ControllerKey)
		if err != nil {
			return
		}
		wire, err := protocol.EncodeJSON(signed)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func readMaterialCredentialStatus(ctx context.Context, wire []byte, cell string,
	policy signerPolicy, service managedmaterial.CredentialService, hosts *host.Controller,
) (materialCredentialStatusReply, materialCredentialStatusRequest, uint64, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxCredentialRequestBytes+4096); err != nil {
		return materialCredentialStatusReply{}, materialCredentialStatusRequest{}, 0, err
	}
	var request materialCredentialStatusRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxCredentialRequestBytes); err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	canonical, err := protocol.EncodeJSON(request)
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if err != nil || !bytes.Equal(canonical, envelope.Payload) || !exists ||
		trusted.Actor != envelope.Actor || request.Generation < 2 || request.OperationID == "" ||
		!policy.canManageClientKeys(envelope.Actor, request.DatabaseID, request.PartitionID) {
		return materialCredentialStatusReply{}, request, 0, errors.New("client credential status is not authorized")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: managedKindCredentialStatus, Actor: trusted.Actor,
		OperationID: request.OperationID, Generation: request.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	if envelope.Epoch == 0 || service.Preparation.Fencer.Current().Epoch != envelope.Epoch {
		return materialCredentialStatusReply{}, request, 0, errors.New("credential status authority changed")
	}
	initial, _, err := service.Preparation.CurrentBundle(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	initialWire, err := protocol.EncodeJSON(initial)
	if err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	initialSum := sha256.Sum256(initialWire)
	if hex.EncodeToString(initialSum[:]) != request.InitialReceiptSHA {
		return materialCredentialStatusReply{}, request, 0, errors.New("initial client material receipt changed")
	}
	state, receipt, err := service.Current(ctx, request.DatabaseID, request.PartitionID)
	if err != nil || receipt == nil || state.Generation != request.Generation {
		return materialCredentialStatusReply{}, request, 0, errors.New("requested credential generation is not current")
	}
	stateSHA, err := managedmaterial.CredentialStateDigest(state)
	if err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	listed, err := hosts.ListHosts(ctx)
	if err != nil {
		return materialCredentialStatusReply{}, request, 0, err
	}
	reply := materialCredentialStatusReply{DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		InitialReceiptSHA: request.InitialReceiptSHA, Generation: request.Generation, StateSHA256: stateSHA,
		Status: "pending"}
	applied, members := credentialMembersApplied(initial.Spec.Members, state.Generation, listed,
		request.DatabaseID, request.PartitionID)
	reply.Members = members
	confirmed, _, err := service.Current(ctx, request.DatabaseID, request.PartitionID)
	if err != nil || confirmed.Generation != state.Generation {
		return materialCredentialStatusReply{}, request, 0, errors.New("credential generation changed during status read")
	}
	confirmedSHA, err := managedmaterial.CredentialStateDigest(confirmed)
	if err != nil || confirmedSHA != stateSHA || service.Preparation.Fencer.Current().Epoch != envelope.Epoch {
		return materialCredentialStatusReply{}, request, 0, errors.New("credential authority changed during status read")
	}
	if applied {
		reply.Status = "applied"
	}
	return reply, request, envelope.Epoch, nil
}

func credentialMembersApplied(expected [2]managedmaterial.InitialMember, generation uint64,
	listed []host.HostStatus, database, partition string,
) (bool, [2]materialCredentialMemberStatus) {
	var members [2]materialCredentialMemberStatus
	applied := true
	for index, member := range expected {
		observation := materialCredentialMemberStatus{SeatID: member.SeatID, MemberID: member.MemberID}
		matches := 0
		for _, listedHost := range listed {
			placement := listedHost.Registration.ManagedPlacement
			binding := listedHost.Registration.ManagedMember
			if placement == nil || binding == nil || placement.DatabaseID != database ||
				placement.PartitionID != partition || placement.SeatID != member.SeatID {
				continue
			}
			matches++
			observation.Node = listedHost.Registration.Node
			if binding.Scope.MemberID != member.MemberID || binding.Scope.Incarnation != member.Incarnation ||
				!listedHost.Verified {
				continue
			}
			for _, report := range listedHost.Reports {
				if report.State == "running" && report.Managed != nil &&
					report.Managed.Member == *binding {
					observation.Generation = report.Managed.ClientCredentialGeneration
					observation.Applied = observation.Generation == generation
				}
			}
		}
		if matches != 1 || !observation.Applied {
			applied = false
		}
		members[index] = observation
	}
	return applied, members
}
