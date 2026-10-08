package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	maxTerminalPayloadBytes = 32 << 10
	maxTerminalWireBytes    = maxTerminalPayloadBytes + 4096
)

var terminalRequestToken = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type terminalRequest struct {
	DatabaseID  string `json:"database_id"`
	PartitionID string `json:"partition_id"`
	OperationID string `json:"operation_id"`
	Nonce       string `json:"nonce"`
}

type terminalReply struct {
	Intent         *authority.TerminalIntent `json:"intent,omitempty"`
	MarkerSequence uint64                    `json:"marker_sequence,omitzero"`
	Status         *oci.TerminalStatus       `json:"status,omitempty"`
	Error          string                    `json:"error,omitempty"`
}

type terminalAdmissionMembers interface {
	ListMembers(context.Context, string, string) ([]placement.VersionedMemberState, error)
}

type terminalAdmissionControl interface {
	Current() authority.Snapshot
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
	ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error)
	ListPendingEnrollmentEffects(context.Context, authority.WorkloadScope) ([]authority.EnrollmentEffect, error)
	CommitTerminalIntent(context.Context, uint64, authority.WorkloadScope, string, []byte, func(context.Context) error) (uint64, error)
}

type terminalGrantStatus func(context.Context, authority.TerminalIntent) error
type terminalGrantFence func(context.Context, uint64, authority.TerminalIntent) error
type terminalGrantProof func(context.Context, authority.TerminalIntent) error

func terminalSubject(cell, action string) string { return protocol.TerminalSubject(cell, action) }

func terminalOperatorCodec(cfg Config) (signerPolicy, error) {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return signerPolicy{}, err
	}
	grant, ok := policy.grant(cfg.Operator.Actor)
	if !ok || !grant.CanTeardownTerraBase {
		return signerPolicy{}, errors.New("operator is not authorized for TerraBase terminal cleanup")
	}
	return policy, nil
}

func operatorTerminalPlan(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	databaseID, partitionID, operationID string, output io.Writer,
) error {
	if operationID == "" {
		operationID = entityid.New()
	}
	request := terminalRequest{DatabaseID: databaseID, PartitionID: partitionID,
		OperationID: operationID, Nonce: entityid.New()}
	if !validTerminalRequest(request) {
		return errors.New("terminal plan requires a valid database, partition, and operation ID")
	}
	reply, err := requestTerminal(ctx, cfg, runtime, "plan", request.OperationID, 1, request)
	if err != nil {
		return err
	}
	if reply.Intent == nil || reply.Intent.DatabaseID != databaseID || reply.Intent.PartitionID != partitionID ||
		reply.Intent.OperationID != request.OperationID || reply.Intent.Nonce != request.Nonce ||
		reply.Intent.DisposableWorkload || reply.Intent.AcknowledgePermanentDataLoss || reply.Intent.AuthorizeForcedStop {
		return errors.New("controller returned an invalid terminal plan")
	}
	return printJSON(output, reply.Intent)
}

func operatorTerminalApply(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	var intent authority.TerminalIntent
	if len(data) == 0 || len(data) > maxTerminalPayloadBytes ||
		json.Unmarshal(data, &intent, json.RejectUnknownMembers(true)) != nil || intent.Validate() != nil ||
		intent.Cell != cfg.NATS.Cell {
		return errors.New("terminal apply requires an exact reviewed plan and all three explicit consent fields")
	}
	reply, err := requestTerminal(ctx, cfg, runtime, "apply", intent.OperationID, intent.PlacementGeneration, intent)
	if err != nil {
		return err
	}
	if reply.Intent == nil || reply.MarkerSequence == 0 {
		return errors.New("controller returned an incomplete terminal receipt")
	}
	confirmed, err := protocol.EncodeJSON(reply.Intent)
	expected, expectedErr := protocol.EncodeJSON(intent)
	if err != nil || expectedErr != nil || !bytes.Equal(confirmed, expected) {
		return errors.New("controller returned an incomplete terminal receipt")
	}
	return printJSON(output, reply)
}

func operatorTerminalStatus(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	databaseID, partitionID string, output io.Writer,
) error {
	request := terminalRequest{DatabaseID: databaseID, PartitionID: partitionID,
		OperationID: entityid.New(), Nonce: entityid.New()}
	if !validTerminalRequest(request) {
		return errors.New("terminal status requires a valid database and partition")
	}
	reply, err := requestTerminal(ctx, cfg, runtime, "status", request.OperationID, 1, request)
	if err != nil {
		return err
	}
	if reply.Intent == nil || reply.Status == nil || reply.MarkerSequence == 0 ||
		reply.Intent.DatabaseID != databaseID || reply.Intent.PartitionID != partitionID {
		return errors.New("controller returned an invalid terminal status")
	}
	return printJSON(output, reply)
}

func requestTerminal(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	action, operationID string, generation uint64, payload any,
) (terminalReply, error) {
	policy, err := terminalOperatorCodec(cfg)
	if err != nil {
		return terminalReply{}, err
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return terminalReply{}, err
	}
	epoch, err := observeOperatorAuthority(ctx, func(callCtx context.Context) (authority.Snapshot, error) {
		return authority.Observe(callCtx, runtime.JetStream(), cfg.NATS.Cell)
	})
	if err != nil {
		return terminalReply{}, err
	}
	encoded, err := protocol.EncodeJSON(payload)
	if err != nil || len(encoded) > maxTerminalPayloadBytes {
		return terminalReply{}, errors.New("terminal request payload is too large")
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(encoded, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "placement.terminal." + action, Actor: cfg.Operator.Actor,
		OperationID: operationID, Generation: generation, Epoch: epoch,
	}, now, now.Add(5*time.Minute), codec.PrivateKey)
	if err != nil {
		return terminalReply{}, err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return terminalReply{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	message, err := runtime.Conn().RequestWithContext(requestCtx, terminalSubject(cfg.NATS.Cell, action), wire)
	if err != nil {
		return terminalReply{}, fmt.Errorf("request terminal %s: %w", action, err)
	}
	var reply terminalReply
	if err := protocol.DecodeStrict(message.Data, &reply, maxTerminalWireBytes); err != nil {
		return terminalReply{}, err
	}
	if reply.Error != "" {
		return terminalReply{}, errors.New(reply.Error)
	}
	return reply, nil
}

func serveTerminalAdmission(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy,
	control *authority.Runtime, region oci.RegionConfig, members placement.Store,
	inventory oci.TerminalExecutor, fence terminalGrantFence, proof terminalGrantProof,
	grants terminalGrantStatus,
) (*nats.Subscription, error) {
	if control == nil || members == nil || inventory == nil || fence == nil || proof == nil || grants == nil ||
		!strings.EqualFold(string(region.Region), cell) {
		return nil, errors.New("terminal admission requires bound authority, placement, and OCI inventory")
	}
	return conn.Subscribe(terminalSubject(cell, ">"), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxTerminalWireBytes ||
			!control.Current().CanMutate() {
			return
		}
		var action string
		for _, candidate := range []string{"plan", "apply", "status"} {
			if message.Subject == terminalSubject(cell, candidate) {
				action = candidate
				break
			}
		}
		if action == "" {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		reply, err := handleTerminalRequest(requestCtx, message.Data, action, cell, policy,
			control, region, members, inventory, fence, proof, grants)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) ||
			!control.Current().CanMutate() {
			return
		}
		if err != nil {
			reply = terminalReply{Error: err.Error()}
		}
		encoded, err := protocol.EncodeJSON(reply)
		if err == nil {
			_ = message.Respond(encoded)
		}
	})
}

func handleTerminalRequest(ctx context.Context, wire []byte, action, cell string, policy signerPolicy,
	control terminalAdmissionControl, region oci.RegionConfig, members terminalAdmissionMembers,
	inventory oci.TerminalExecutor, fence terminalGrantFence, proof terminalGrantProof,
	grants terminalGrantStatus,
) (terminalReply, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxTerminalWireBytes); err != nil {
		return terminalReply{}, err
	}
	var request terminalRequest
	var intent authority.TerminalIntent
	var operationID string
	var generation uint64 = 1
	if action == "apply" {
		if err := protocol.DecodeStrict(envelope.Payload, &intent, maxTerminalPayloadBytes); err != nil || intent.Validate() != nil {
			return terminalReply{}, errors.New("terminal apply payload is invalid")
		}
		operationID, generation = intent.OperationID, intent.PlacementGeneration
		request = terminalRequest{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			OperationID: intent.OperationID, Nonce: intent.Nonce}
	} else {
		if action != "plan" && action != "status" {
			return terminalReply{}, errors.New("unknown terminal request")
		}
		if err := protocol.DecodeStrict(envelope.Payload, &request, maxTerminalPayloadBytes); err != nil ||
			!validTerminalRequest(request) {
			return terminalReply{}, errors.New("terminal request scope is invalid")
		}
		operationID = request.OperationID
	}
	grant, ok := policy.grant(envelope.Actor)
	trusted, trustedOK := policy.trusted(envelope.KeyID)
	if !ok || !grant.CanTeardownTerraBase || !trustedOK || trusted.Actor != envelope.Actor {
		return terminalReply{}, errors.New("terminal signing actor is unauthorized")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: "placement.terminal." + action, Actor: trusted.Actor,
		OperationID: operationID, Generation: generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		return terminalReply{}, err
	}
	if envelope.Epoch == 0 || control.Current().Epoch != envelope.Epoch {
		return terminalReply{}, authority.ErrFenced
	}
	canonical, err := protocol.EncodeJSON(request)
	if action == "apply" {
		canonical, err = protocol.EncodeJSON(intent)
	}
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return terminalReply{}, errors.New("terminal request payload is not canonical")
	}
	scope := authority.WorkloadScope{DatabaseID: request.DatabaseID, PartitionID: request.PartitionID}
	if action == "status" {
		entry, err := control.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID)
		if err != nil {
			return terminalReply{}, err
		}
		accepted, err := decodeCurrentTerminal(entry, scope.DatabaseID, scope.PartitionID)
		if err != nil {
			return terminalReply{}, err
		}
		status, err := inventory.InspectTerminalStatus(ctx, accepted)
		if err != nil {
			return terminalReply{}, err
		}
		if status.Phase == "complete" {
			if grants == nil || grants(ctx, accepted) != nil {
				status.Phase = "held"
				status.Pending = append(status.Pending, "terminal enrollment grant readback incomplete")
			}
		}
		return terminalReply{Intent: &accepted, MarkerSequence: entry.Sequence, Status: &status}, nil
	}
	if action == "apply" {
		prior, err := control.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID)
		if err == nil {
			if prior.OperationID == intent.OperationID && bytes.Equal(prior.Payload, envelope.Payload) {
				return terminalReply{Intent: &intent, MarkerSequence: prior.Sequence}, nil
			}
			return terminalReply{}, authority.ErrOperationConflict
		}
		if !errors.Is(err, authority.ErrNotFound) {
			return terminalReply{}, err
		}
	}
	planned, err := buildTerminalPlan(ctx, cell, region, members, inventory, control, request)
	if err != nil {
		return terminalReply{}, err
	}
	if action == "plan" {
		planned.DisposableWorkload = false
		planned.AcknowledgePermanentDataLoss = false
		planned.AuthorizeForcedStop = false
		return terminalReply{Intent: &planned}, nil
	}
	plannedBytes, err := protocol.EncodeJSON(planned)
	if err != nil || !bytes.Equal(plannedBytes, envelope.Payload) {
		return terminalReply{}, errors.New("signed terminal cleanup differs from current admitted inventory")
	}
	if fence == nil || proof == nil || grants == nil {
		return terminalReply{}, errors.New("terminal enrollment grant fencing is unavailable")
	}
	if err := fence(ctx, envelope.Epoch, intent); err != nil {
		return terminalReply{}, fmt.Errorf("terminal cleanup held during grant fencing; some exact grants may already be disabled: %w", err)
	}
	sequence, err := control.CommitTerminalIntent(ctx, envelope.Epoch, scope, intent.OperationID, envelope.Payload,
		func(lockedCtx context.Context) error {
			pending, err := control.ListPendingEnrollmentEffects(lockedCtx, scope)
			if err != nil {
				return err
			}
			if len(pending) != 0 {
				return errors.New("terminal admission is held by unsettled enrollment grant effects")
			}
			latest, err := buildTerminalPlan(lockedCtx, cell, region, members, inventory, control, request)
			if err != nil {
				return err
			}
			latestBytes, err := protocol.EncodeJSON(latest)
			if err != nil || !bytes.Equal(latestBytes, envelope.Payload) {
				return errors.New("terminal inventory changed before durable admission")
			}
			if err := proof(lockedCtx, intent); err != nil {
				return fmt.Errorf("terminal enrollment grant fence readback: %w", err)
			}
			return inventory.VerifyTerminalInventorySettled(lockedCtx, intent)
		})
	if err != nil {
		return terminalReply{}, fmt.Errorf("terminal cleanup held after exact grant fencing; retry the reviewed intent: %w", err)
	}
	return terminalReply{Intent: &intent, MarkerSequence: sequence}, nil
}

func validTerminalRequest(request terminalRequest) bool {
	nonce, err := entityid.Parse(request.Nonce)
	return entityid.Valid(request.DatabaseID) &&
		entityid.Valid(request.PartitionID) &&
		entityid.Valid(request.OperationID) &&
		err == nil && entityid.Valid(request.Nonce) && nonce.String() == request.Nonce
}

func buildTerminalPlan(ctx context.Context, cell string, region oci.RegionConfig,
	members terminalAdmissionMembers, inventory oci.TerminalExecutor,
	control terminalAdmissionControl, request terminalRequest,
) (authority.TerminalIntent, error) {
	if !validTerminalRequest(request) || !strings.EqualFold(string(region.Region), cell) {
		return authority.TerminalIntent{}, errors.New("terminal plan has invalid scope or region")
	}
	if _, err := control.ReadTerminalIntent(ctx, request.DatabaseID, request.PartitionID); err == nil {
		return authority.TerminalIntent{}, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return authority.TerminalIntent{}, err
	}
	entry, err := control.ReadPlacementIntent(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return authority.TerminalIntent{}, err
	}
	admitted, err := placement.DecodeCommittedIntent(entry.Payload)
	if err != nil || admitted.ValidateForAdmission() != nil || admitted.DatabaseID != request.DatabaseID ||
		admitted.PartitionID != request.PartitionID || !intentSelectsCell(admitted, cell) {
		return authority.TerminalIntent{}, errors.New("current placement is not an admitted managed workload")
	}
	states, err := members.ListMembers(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return authority.TerminalIntent{}, err
	}
	targets, err := placement.TerminalTargetsForRegion(admitted, region.Region, region.FaultDomains, states)
	if err != nil {
		return authority.TerminalIntent{}, err
	}
	planned := authority.TerminalIntent{Cell: cell, DatabaseID: request.DatabaseID,
		PartitionID: request.PartitionID, Region: string(region.Region), Owner: region.Owner,
		CompartmentID: region.CompartmentID, FleetGeneration: region.Generation,
		PlacementGeneration: admitted.Generation, PlacementPayloadDigest: admitted.PayloadDigest(),
		OperationID: request.OperationID, Nonce: request.Nonce, Targets: targets,
		DisposableWorkload: true, AcknowledgePermanentDataLoss: true, AuthorizeForcedStop: true}
	if err := planned.Validate(); err != nil {
		return authority.TerminalIntent{}, err
	}
	discovered, err := inventory.DiscoverTerminalTargets(ctx, planned)
	if err != nil {
		return authority.TerminalIntent{}, err
	}
	if len(discovered) != len(targets) {
		return authority.TerminalIntent{}, errors.New("terminal discovery returned a different seat count")
	}
	for index, target := range targets {
		found := discovered[index]
		if found.SeatID != target.SeatID || found.MemberID != target.MemberID ||
			found.HostCreateKey != target.HostCreateKey || found.DataCreateKey != target.DataCreateKey {
			return authority.TerminalIntent{}, errors.New("terminal discovery changed an admitted target")
		}
	}
	for _, member := range states {
		index := slices.IndexFunc(discovered, func(target authority.TerminalTarget) bool {
			return target.SeatID == member.State.MemberID
		})
		if index < 0 || member.State.InstanceID != "" && member.State.InstanceID != discovered[index].InstanceID ||
			member.State.VolumeID != "" && member.State.VolumeID != discovered[index].DataVolumeID {
			return authority.TerminalIntent{}, errors.New("terminal discovery differs from durable placement member")
		}
	}
	planned.Targets = discovered
	if err := planned.Validate(); err != nil {
		return authority.TerminalIntent{}, err
	}
	return planned, nil
}
