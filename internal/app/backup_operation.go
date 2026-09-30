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
const maxBackupStatusReplyBytes = 64 << 10

type backupOperationRequest struct {
	Action        string `json:"action"`
	DatabaseID    string `json:"database_id"`
	PartitionID   string `json:"partition_id"`
	OperationID   string `json:"operation_id,omitempty"`
	HistoryCursor string `json:"history_cursor,omitempty"`
}

type backupOperationReply struct {
	DatabaseID         string `json:"database_id"`
	PartitionID        string `json:"partition_id"`
	OperationID        string `json:"operation_id"`
	State              string `json:"state"`
	Ordinal            uint64 `json:"ordinal"`
	Attempt            uint64 `json:"attempt"`
	Sequence           uint64 `json:"sequence"`
	Error              string `json:"error,omitempty"`
	HistoryCursor      string `json:"history_cursor,omitempty"`
	PublicationReceipt string `json:"publication_receipt,omitempty"`
	CompleteRelease    string `json:"complete_release,omitempty"`
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
	action, databaseID, partitionID, operationID, historyCursor string, output io.Writer,
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
		PartitionID: partitionID, OperationID: operationID, HistoryCursor: historyCursor}
	requestCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	for {
		payload, err := protocol.EncodeJSON(request)
		if err != nil || len(payload) > maxBackupAdmissionBytes {
			return errors.New("backup request exceeds bound")
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
		if err != nil || len(wire) > maxBackupAdmissionBytes {
			return errors.New("backup signed request exceeds bound")
		}
		message, err := runtime.Conn().RequestWithContext(requestCtx, backupOperationSubject(cfg.NATS.Cell), wire)
		if err != nil {
			return fmt.Errorf("backup operation admission: %w", err)
		}
		var signed protocol.Envelope
		responseLimit := maxBackupAdmissionBytes
		if action == "status" {
			responseLimit = maxBackupStatusReplyBytes
		}
		if err := protocol.DecodeStrict(message.Data, &signed, responseLimit); err != nil {
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
		if err := protocol.DecodeStrict(signed.Payload, &reply, responseLimit); err != nil {
			return err
		}
		if reply.Error != "" {
			return errors.New(reply.Error)
		}
		if reply.DatabaseID != databaseID || reply.PartitionID != partitionID ||
			operationID != "" && reply.OperationID != operationID || reply.OperationID == "" {
			return errors.New("backup operation response differs from request")
		}
		deadline, _ := requestCtx.Deadline()
		if reply.State != "history_incomplete" || time.Until(deadline) < 2*time.Second {
			return printJSON(output, reply)
		}
		if reply.HistoryCursor == "" || len(reply.HistoryCursor) > maxBackupAdmissionBytes {
			return errors.New("backup history continuation is invalid")
		}
		request.HistoryCursor = reply.HistoryCursor
	}
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
		var request backupOperationRequest
		_ = protocol.DecodeStrict(envelope.Payload, &request, maxBackupAdmissionBytes)
		reply, err := runtime.admit(requestCtx, envelope)
		if err != nil {
			code := "backup operation was rejected"
			if request.Action == "status" {
				switch {
				case errors.Is(err, authority.ErrNotFound):
					code = "not_found"
				case err.Error() == "history_cursor_expired":
					code = "history_cursor_expired"
				default:
					code = "history_unavailable"
				}
			}
			reply = backupOperationReply{Error: code}
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
		limit := maxBackupAdmissionBytes
		if request.Action == "status" {
			limit = maxBackupStatusReplyBytes
		}
		if err == nil && len(wire) <= limit && len(payload) <= limit {
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
		request.DatabaseID == "" || request.PartitionID == "" ||
		request.HistoryCursor != "" && (request.Action != "status" || request.OperationID == "" ||
			len(request.HistoryCursor) > maxBackupAdmissionBytes) {
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
	if request.HistoryCursor != "" {
		if _, err := verifyBackupHistoryCursor(request.HistoryCursor,
			runtime.responseKey.Public().(ed25519.PublicKey), time.Now().UTC(),
			envelope.Actor, runtime.cell, request.DatabaseID, request.PartitionID,
			request.OperationID); err != nil {
			return backupOperationReply{}, err
		}
	}
	if request.Action == "status" && request.OperationID == "" {
		return runtime.backupStatusReply(ctx, record, sequence)
	}
	if request.OperationID != record.OperationID {
		if request.Action == "status" {
			return runtime.backupHistoryStatus(ctx, envelope.Actor, request)
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
	if request.Action == "status" {
		return runtime.backupStatusReply(ctx, record, sequence)
	}
	return backupReplyFor(record, sequence), nil
}

func (runtime backupOperationRuntime) backupHistoryStatus(ctx context.Context, actor string,
	request backupOperationRequest,
) (backupOperationReply, error) {
	cursor := backupHistoryCursor{Actor: actor, Cell: runtime.cell,
		Stream: authority.ControlStreamName, DatabaseID: request.DatabaseID,
		PartitionID: request.PartitionID, OperationID: request.OperationID}
	if request.HistoryCursor != "" {
		parsed, err := verifyBackupHistoryCursor(request.HistoryCursor,
			runtime.responseKey.Public().(ed25519.PublicKey), time.Now().UTC(),
			actor, runtime.cell, request.DatabaseID, request.PartitionID, request.OperationID)
		if err != nil {
			return backupOperationReply{}, err
		}
		cursor = parsed
	}
	page, err := runtime.control.ReadBackupHistoryPage(ctx, request.DatabaseID,
		request.PartitionID, request.OperationID, cursor.Watermark, cursor.NextSequence)
	if err != nil {
		return backupOperationReply{}, err
	}
	if page.LatestMatchSequence != 0 {
		cursor.LatestMatchSequence = page.LatestMatchSequence
	}
	if !page.Exhausted {
		cursor.Watermark, cursor.NextSequence = page.Watermark, page.NextSequence
		token, err := signBackupHistoryCursor(cursor, runtime.responseKey)
		if err != nil {
			return backupOperationReply{}, err
		}
		return backupOperationReply{DatabaseID: request.DatabaseID,
			PartitionID: request.PartitionID, OperationID: request.OperationID,
			State: "history_incomplete", HistoryCursor: token}, nil
	}
	if cursor.LatestMatchSequence == 0 {
		return backupOperationReply{}, authority.ErrNotFound
	}
	record, err := runtime.control.ReadBackupOperationAtSequence(ctx, request.DatabaseID,
		request.PartitionID, request.OperationID, cursor.LatestMatchSequence)
	if err != nil {
		return backupOperationReply{}, err
	}
	return runtime.backupStatusReply(ctx, record, cursor.LatestMatchSequence)
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

func backupStatusReplyFor(record authority.BackupOperationRecord, sequence uint64) backupOperationReply {
	reply := backupReplyFor(record, sequence)
	if record.State == "releasing" || record.State == "complete" {
		reply.PublicationReceipt = string(record.PublicationReceipt)
		reply.CompleteRelease = string(record.CompleteRelease)
	}
	return reply
}

func (runtime backupOperationRuntime) backupStatusReply(ctx context.Context,
	record authority.BackupOperationRecord, sequence uint64,
) (backupOperationReply, error) {
	if err := runtime.producer.VerifyCommittedPublication(ctx, record); err != nil {
		return backupOperationReply{}, err
	}
	return backupStatusReplyFor(record, sequence), nil
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

// Run reconciles only exact R3-committed proof and release bytes.
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
		if record.State != "aborted" && record.State != "complete" {
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
	switch record.State {
	case "held":
		current, placementSequence, err := runtime.currentRoster(ctx, record.DatabaseID, record.PartitionID)
		if err != nil || placementSequence != record.PlacementSequence ||
			!sameBackupServingRoster(record.Roster, current) {
			return errors.Join(authority.ErrFenced, err)
		}
		record, sequence, err = runtime.producer.CommitBarrier(ctx, epoch, record, sequence, time.Now().UTC())
		if err != nil {
			return err
		}
		return runtime.reconcileBarrier(ctx, epoch, record, sequence)
	case "barrier":
		return runtime.reconcileBarrier(ctx, epoch, record, sequence)
	case "publishing":
		return runtime.reconcilePublishing(ctx, epoch, record, sequence)
	case "releasing":
		return runtime.reconcileComplete(ctx, epoch, record, sequence)
	}
	if record.State == "accepted" && time.Now().UnixMilli() >= int64(record.PrepareExpiresAtMS)-5_000 {
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
		_, leafDER, err := runtime.producer.VerifyCutWithLeaf(ctx, record, member.MemberID, result.CutEnvelope)
		if err != nil {
			_, _, abortErr := runtime.producer.BeginAbort(ctx, epoch,
				record.DatabaseID, record.PartitionID, time.Now().UTC())
			return errors.Join(err, abortErr)
		}
		record.Roster[index].CutEnvelope = bytes.Clone(result.CutEnvelope)
		record.Roster[index].CutLeafDER = leafDER
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

func (runtime backupOperationRuntime) reconcileBarrier(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64,
) error {
	for _, target := range record.Roster {
		if target.BarrierAcknowledged {
			continue
		}
		// A member must fsync every other pinned Cut+DER before it may see
		// the full-roster Barrier. Each host command is derived from R3.
		for _, source := range record.Roster {
			if source.MemberID == target.MemberID {
				continue
			}
			kind := "cut-proof/" + source.MemberID
			if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
				record.DatabaseID, record.PartitionID, target.MemberID, kind); err != nil {
				return err
			}
			result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, target.Node, target.Role)
			if err != nil || !found || result.Command.OperationID != record.OperationID ||
				result.Command.Kind != "cut-proof" || result.Command.ProofMemberID != source.MemberID {
				return err
			}
		}
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, target.MemberID, "barrier"); err != nil {
			return err
		}
		result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, target.Node, target.Role)
		if err != nil || !found || result.Command.OperationID != record.OperationID ||
			result.Command.Kind != "barrier" {
			return err
		}
		record, sequence, err = runtime.producer.AcknowledgeBarrier(ctx, epoch, record, sequence,
			target.MemberID, result.Status.BarrierSHA256)
		if err != nil {
			return err
		}
	}
	for _, member := range record.Roster {
		if !member.BarrierAcknowledged {
			return nil
		}
	}
	if len(record.CandidateEnvelope) == 0 {
		for _, owner := range record.Roster {
			if owner.MemberID != record.OwnerMemberID {
				continue
			}
			if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
				record.DatabaseID, record.PartitionID, owner.MemberID, "barrier"); err != nil {
				return err
			}
			result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, owner.Node, owner.Role)
			if err != nil || !found || result.Command.OperationID != record.OperationID ||
				result.Command.Kind != "barrier" || result.Status.CandidateEnvelope == "" {
				return err
			}
			record, sequence, err = runtime.producer.AcceptCandidate(ctx, epoch, record, sequence,
				[]byte(result.Status.CandidateEnvelope))
			if err != nil {
				return err
			}
			break
		}
	}
	if len(record.CandidateEnvelope) == 0 {
		return nil
	}
	_, _, err := runtime.producer.CommitCompletion(ctx, epoch, record, sequence, time.Now().UTC())
	return err
}

func (runtime backupOperationRuntime) reconcilePublishing(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64,
) error {
	for _, owner := range record.Roster {
		if owner.MemberID != record.OwnerMemberID {
			continue
		}
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, owner.MemberID, "publish"); err != nil {
			return err
		}
		result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, owner.Node, owner.Role)
		if err != nil || !found || result.Command.OperationID != record.OperationID ||
			result.Command.Kind != "publish" || len(result.ReceiptEnvelope) == 0 {
			return err
		}
		_, _, err = runtime.producer.CommitOwnerReceipt(ctx, epoch, record, sequence,
			result.ReceiptEnvelope, time.Now().UTC())
		return err
	}
	return errors.New("backup owner is absent from committed roster")
}

func (runtime backupOperationRuntime) reconcileComplete(ctx context.Context, epoch uint64,
	record authority.BackupOperationRecord, sequence uint64,
) error {
	for _, member := range record.Roster {
		if member.CompleteAcknowledged {
			continue
		}
		// A member may have fsynced Complete while its R3 acknowledgment was
		// lost. Read process-bound status before offering a renewed Release:
		// Rust terminal replay remains bound to the original Release digest.
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, member.MemberID, "complete-status"); err != nil {
			return err
		}
		statusResult, found, err := runtime.hosts.ReadManagedBackupResult(ctx, member.Node, member.Role)
		if err != nil || !found || statusResult.Command.OperationID != record.OperationID ||
			statusResult.Command.Kind != "complete-status" {
			return err
		}
		if statusResult.Status.State == "complete" {
			record, sequence, err = runtime.producer.AcknowledgeComplete(ctx, epoch, record, sequence,
				member.MemberID, statusResult.Status.HeadGeneration,
				[]byte(statusResult.Status.PublishedHeadReceipt))
			if err != nil {
				return err
			}
			continue
		}
		if statusResult.Status.State != "pending" {
			return errors.New("backup member Complete status is not pending or complete")
		}
		current, nextSequence, ready, err := runtime.producer.EnsureCurrentCompleteRelease(ctx,
			epoch, record, sequence, time.Now().UTC())
		if err != nil {
			return err
		}
		if !ready {
			return nil
		}
		record, sequence = current, nextSequence
		if err := runtime.hosts.RequestManagedBackupOperation(ctx, epoch,
			record.DatabaseID, record.PartitionID, member.MemberID, "complete"); err != nil {
			return err
		}
		result, found, err := runtime.hosts.ReadManagedBackupResult(ctx, member.Node, member.Role)
		if err != nil || !found || result.Command.OperationID != record.OperationID ||
			result.Command.Kind != "complete" || result.Status.State != "complete" {
			return err
		}
		record, sequence, err = runtime.producer.AcknowledgeComplete(ctx, epoch, record, sequence,
			member.MemberID, result.Status.HeadGeneration, []byte(result.Status.PublishedHeadReceipt))
		if err != nil {
			return err
		}
	}
	return nil
}
