package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"time"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const maxBackupAdmissionBytes = 8 << 10

type backupOperationRequest struct {
	Action      string `json:"action"`
	DatabaseID  string `json:"database_id"`
	PartitionID string `json:"partition_id"`
	OperationID string `json:"operation_id,omitempty"`
}

type backupOperationReply struct {
	DatabaseID  string `json:"database_id"`
	PartitionID string `json:"partition_id"`
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Ordinal     uint64 `json:"ordinal"`
	Attempt     uint64 `json:"attempt"`
	Sequence    uint64 `json:"sequence"`
	Error       string `json:"error,omitempty"`
}

type backupOperationRuntime struct {
	cell        string
	memberRole  string
	control     *authority.Runtime
	placements  placement.Store
	hosts       *host.Controller
	producer    managedmaterial.BackupOperationProducer
	policy      signerPolicy
	responseKey ed25519.PrivateKey
}

func backupOperationSubject(cell string) string { return "ts.orch.v1." + cell + ".backup.operation" }

func operatorBackupOperation(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	action, databaseID, partitionID, operationID string, output io.Writer,
) error {
	if databaseID == "" || partitionID == "" ||
		(action != "start" && action != "abort" && action != "status") ||
		action == "abort" && operationID == "" {
		return errors.New("backup operation requires database, partition and exact operation ID for abort")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanOperateBackup {
		return errors.New("operator is not authorized for backup operations")
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
	if !snapshot.Ready || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return errors.New("regional authority lease is not current")
	}
	request := backupOperationRequest{Action: action, DatabaseID: databaseID,
		PartitionID: partitionID, OperationID: operationID}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return err
	}
	requestID := uuid.New().String()
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "backup.operation", Actor: cfg.Operator.Actor,
		OperationID: requestID, Generation: 1, Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	message, err := runtime.Conn().RequestWithContext(requestCtx, backupOperationSubject(cfg.NATS.Cell), wire)
	if err != nil {
		return fmt.Errorf("backup operation admission: %w", err)
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &signed, maxBackupAdmissionBytes); err != nil {
		return err
	}
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "backup.operation.reply", Actor: "controller",
		OperationID: requestID, Generation: 1, Epoch: snapshot.Epoch,
	}, controllerKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return err
	}
	var reply backupOperationReply
	if err := protocol.DecodeStrict(signed.Payload, &reply, maxBackupAdmissionBytes); err != nil {
		return err
	}
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	if reply.DatabaseID != databaseID || reply.PartitionID != partitionID ||
		operationID != "" && reply.OperationID != operationID || reply.OperationID == "" {
		return errors.New("backup operation response differs from request")
	}
	return printJSON(output, reply)
}

func serveBackupOperation(ctx context.Context, conn *nats.Conn,
	runtime backupOperationRuntime,
) (*nats.Subscription, error) {
	return conn.Subscribe(backupOperationSubject(runtime.cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxBackupAdmissionBytes ||
			!runtime.control.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		var envelope protocol.Envelope
		if err := protocol.DecodeStrict(message.Data, &envelope, maxBackupAdmissionBytes); err != nil {
			return
		}
		reply, err := runtime.admit(requestCtx, envelope)
		if err != nil {
			reply = backupOperationReply{Error: "backup operation was rejected"}
		}
		payload, err := protocol.EncodeJSON(reply)
		if err != nil {
			return
		}
		now := time.Now().UTC()
		signed, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
			Region: runtime.cell, Kind: "backup.operation.reply", Actor: "controller",
			OperationID: envelope.OperationID, Generation: 1, Epoch: envelope.Epoch,
		}, now, now.Add(time.Minute), runtime.responseKey)
		if err != nil {
			return
		}
		wire, err := protocol.EncodeJSON(signed)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func (runtime backupOperationRuntime) admit(ctx context.Context,
	envelope protocol.Envelope,
) (backupOperationReply, error) {
	var request backupOperationRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxBackupAdmissionBytes); err != nil {
		return backupOperationReply{}, err
	}
	canonical, err := protocol.EncodeJSON(request)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) ||
		(request.Action != "start" && request.Action != "abort" && request.Action != "status") ||
		request.DatabaseID == "" || request.PartitionID == "" {
		return backupOperationReply{}, errors.New("backup admission request is invalid")
	}
	grant, exists := runtime.policy.grants[envelope.Actor]
	if !exists || !grant.CanOperateBackup {
		return backupOperationReply{}, errors.New("backup operation actor is unauthorized")
	}
	trusted, exists := runtime.policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor {
		return backupOperationReply{}, errors.New("backup operation signer is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: runtime.cell, Kind: "backup.operation", Actor: trusted.Actor,
		OperationID: envelope.OperationID, Generation: 1, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return backupOperationReply{}, err
	}
	if envelope.Epoch == 0 || runtime.control.Current().Epoch != envelope.Epoch {
		return backupOperationReply{}, authority.ErrFenced
	}
	if err := runtime.control.Guard(ctx, envelope.Epoch); err != nil {
		return backupOperationReply{}, err
	}
	if request.Action == "start" {
		if request.OperationID != "" {
			return backupOperationReply{}, errors.New("backup start must allocate its own operation ID")
		}
		members, placementSequence, err := runtime.currentRoster(ctx, request.DatabaseID, request.PartitionID)
		if err != nil {
			return backupOperationReply{}, err
		}
		record, sequence, err := runtime.producer.AllocatePrepare(ctx, envelope.Epoch,
			request.DatabaseID, request.PartitionID, placementSequence, members, time.Now().UTC(),
			func(check context.Context) error {
				current, currentPlacementSequence, err := runtime.currentRoster(check,
					request.DatabaseID, request.PartitionID)
				if err != nil {
					return err
				}
				if currentPlacementSequence != placementSequence || !sameBackupServingRoster(members, current) {
					return authority.ErrFenced
				}
				return nil
			})
		if err != nil {
			return backupOperationReply{}, err
		}
		return backupReplyFor(record, sequence), nil
	}
	record, sequence, err := runtime.control.ReadBackupOperation(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return backupOperationReply{}, err
	}
	if request.Action == "status" && request.OperationID == "" {
		return backupReplyFor(record, sequence), nil
	}
	if request.OperationID != record.OperationID {
		for _, terminal := range record.Terminal {
			if request.Action == "status" && terminal.OperationID == request.OperationID {
				return backupOperationReply{DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
					OperationID: terminal.OperationID, State: "failed/aborted", Ordinal: terminal.Ordinal,
					Attempt: terminal.Attempt, Sequence: sequence}, nil
			}
		}
		return backupOperationReply{}, authority.ErrNotFound
	}
	if request.Action == "abort" {
		record, sequence, err = runtime.producer.BeginAbort(ctx, envelope.Epoch,
			request.DatabaseID, request.PartitionID, time.Now().UTC())
		if err != nil {
			return backupOperationReply{}, err
		}
	}
	return backupReplyFor(record, sequence), nil
}

func backupReplyFor(record authority.BackupOperationRecord, sequence uint64) backupOperationReply {
	state := record.State
	if state == "aborting" {
		state = "uncertain"
	} else if state == "aborted" {
		state = "failed/aborted"
	}
	return backupOperationReply{DatabaseID: record.DatabaseID, PartitionID: record.PartitionID,
		OperationID: record.OperationID, State: state, Ordinal: record.Ordinal,
		Attempt: record.Attempt, Sequence: sequence}
}

func (runtime backupOperationRuntime) currentRoster(ctx context.Context,
	databaseID, partitionID string,
) ([]authority.BackupOperationMember, uint64, error) {
	if _, err := runtime.control.ReadTerminalIntent(ctx, databaseID, partitionID); err == nil {
		return nil, 0, authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return nil, 0, err
	}
	entry, err := runtime.control.ReadPlacementIntent(ctx, databaseID, partitionID)
	if err != nil {
		return nil, 0, err
	}
	intent, err := placement.DecodeCommittedIntent(entry.Payload)
	if err != nil || intent.DatabaseID != databaseID || intent.PartitionID != partitionID {
		return nil, 0, errors.New("backup current placement is invalid")
	}
	receipt, err := runtime.producer.Preparation.Current(ctx, databaseID, partitionID)
	if err != nil || receipt.Spec.Backup == nil || managedmaterial.VerifyIntentAgainstReceipt(intent, receipt) != nil {
		return nil, 0, errors.Join(errors.New("backup material differs from current placement"), err)
	}
	states, err := runtime.placements.ListMembers(ctx, databaseID, partitionID)
	if err != nil {
		return nil, 0, err
	}
	if len(intent.CanonicalRoster.Rows) != 2 {
		return nil, 0, errors.New("backup initial roster requires two members")
	}
	members := make([]authority.BackupOperationMember, 0, 2)
	for _, row := range intent.CanonicalRoster.Rows {
		found := false
		for _, versioned := range states {
			state := versioned.State
			if state.CanonicalRosterRow == row && state.Stage == placement.StageServing &&
				state.HostNode != "" && state.HostAttempt == 1 &&
				state.IntentGeneration == intent.Generation &&
				state.IntentPayloadDigest == intent.PayloadDigest() {
				members = append(members, authority.BackupOperationMember{
					Origin:   strings.ReplaceAll(row.MemberID, "-", "") + row.Incarnation,
					MemberID: row.MemberID, Incarnation: row.Incarnation,
					TLSLeafSHA256: row.TLSLeafSHA256, Node: state.HostNode, Role: runtime.memberRole})
				found = true
				break
			}
		}
		if !found {
			return nil, 0, errors.New("backup roster member is not serving on its exact host")
		}
	}
	slices.SortFunc(members, func(left, right authority.BackupOperationMember) int {
		return strings.Compare(left.Origin, right.Origin)
	})
	return members, entry.Sequence, nil
}

func sameBackupServingRoster(left, right []authority.BackupOperationMember) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		first, second := left[index], right[index]
		if first.Origin != second.Origin || first.MemberID != second.MemberID ||
			first.Incarnation != second.Incarnation || first.TLSLeafSHA256 != second.TLSLeafSHA256 ||
			first.Node != second.Node || first.Role != second.Role {
			return false
		}
	}
	return true
}

// Run retries only R3-committed Prepare and Abort envelopes. It never signs a
// Barrier, Completion or Complete Release, so this slice cannot publish.
func (runtime backupOperationRuntime) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := runtime.reconcileAll(ctx); err != nil && ctx.Err() == nil {
			log.Printf("backup operation reconciliation held: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (runtime backupOperationRuntime) reconcileAll(ctx context.Context) error {
	if !runtime.control.Current().CanMutate() {
		return nil
	}
	entries, err := runtime.control.ListPlacementIntents(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		intent, err := placement.DecodeCommittedIntent(entry.Payload)
		if err != nil {
			failures = append(failures, fmt.Errorf("decode placement for backup reconciliation: %w", err))
			continue
		}
		record, sequence, err := runtime.control.ReadBackupOperation(ctx, intent.DatabaseID, intent.PartitionID)
		if errors.Is(err, authority.ErrNotFound) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("read backup operation %s/%s: %w",
				intent.DatabaseID, intent.PartitionID, err))
			continue
		}
		if record.State != "aborted" {
			if err := runtime.reconcileOne(ctx, record, sequence); err != nil {
				failures = append(failures, fmt.Errorf("reconcile backup operation %s/%s: %w",
					intent.DatabaseID, intent.PartitionID, err))
			}
		}
	}
	return errors.Join(failures...)
}

func (runtime backupOperationRuntime) reconcileOne(ctx context.Context,
	record authority.BackupOperationRecord, sequence uint64,
) error {
	epoch := runtime.control.Current().Epoch
	if err := runtime.control.Guard(ctx, epoch); err != nil {
		return err
	}
	if record.State == "held" || time.Now().UnixMilli() >= int64(record.PrepareExpiresAtMS)-5_000 {
		var err error
		record, sequence, err = runtime.producer.BeginAbort(ctx, epoch,
			record.DatabaseID, record.PartitionID, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	if len(record.AbortEnvelope) != 0 {
		return runtime.reconcileAbort(ctx, epoch, record, sequence)
	}
	for index, member := range record.Roster {
		if len(member.CutEnvelope) != 0 {
			continue
		}
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, member.MemberID, "prepare"); err != nil {
			continue
		}
		result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, member.Node, member.Role)
		if err != nil || !found || result.Command.OperationID != record.OperationID ||
			result.Command.Kind != "prepare" {
			continue
		}
		if _, err := runtime.producer.VerifyCut(ctx, record, member.MemberID, result.CutEnvelope); err != nil {
			_, _, abortErr := runtime.producer.BeginAbort(ctx, epoch,
				record.DatabaseID, record.PartitionID, time.Now().UTC())
			return errors.Join(err, abortErr)
		}
		record.Roster[index].CutEnvelope = bytes.Clone(result.CutEnvelope)
		allHeld := true
		for _, current := range record.Roster {
			if len(current.CutEnvelope) == 0 {
				allHeld = false
			}
		}
		if allHeld {
			record.State = "held"
		}
		sequence, err = runtime.control.CommitBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, sequence, record)
		if err != nil {
			return err
		}
	}
	return nil
}

func (runtime backupOperationRuntime) reconcileAbort(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64,
) error {
	nowMS := time.Now().UnixMilli()
	// A previous Release must expire with the member's 30-second clock skew
	// before renewal. Stop relaying near expiry rather than offering a member
	// an envelope that can expire while waiting behind its Prepare gate.
	if nowMS > int64(record.AbortExpiresAtMS)-5_000 &&
		nowMS <= int64(record.AbortExpiresAtMS)+30_000 {
		return nil
	}
	if nowMS > int64(record.AbortExpiresAtMS)+30_000 {
		var err error
		record, sequence, err = runtime.producer.BeginAbort(ctx, epoch,
			record.DatabaseID, record.PartitionID, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	for index, member := range record.Roster {
		if member.AbortAcknowledged {
			continue
		}
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, member.MemberID, "abort"); err != nil {
			continue
		}
		result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, member.Node, member.Role)
		if err != nil || !found || result.Command.OperationID != record.OperationID ||
			result.Command.Kind != "abort" || result.Status.State != "failed" ||
			result.Status.ErrorCode != "aborted" {
			continue
		}
		record.Roster[index].AbortAcknowledged = true
		allAck := true
		for _, current := range record.Roster {
			if !current.AbortAcknowledged {
				allAck = false
			}
		}
		if allAck {
			record.State = "aborted"
		}
		sequence, err = runtime.control.CommitBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, sequence, record)
		if err != nil {
			return err
		}
	}
	return nil
}
