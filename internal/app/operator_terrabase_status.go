package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	maxPlacementStatusRequestBytes = 1 << 10
	maxPlacementStatusReplyBytes   = 48 << 10
	placementStatusReplyKind       = "placement.status.reply"
	placementStatusPollInterval    = 10 * time.Second
	maxPlacementHoldRecords        = 32
	placementHoldRetention         = 2 * time.Minute
)

type placementStatusRequest struct {
	DatabaseID  string `json:"database_id"`
	PartitionID string `json:"partition_id"`
	Nonce       string `json:"nonce"`
}

// placementStatusReport is the regional leader's durable placement record for
// one database partition joined with its current host sessions and reports.
// It is signed by the controller response key the operator already pins.
type placementStatusReport struct {
	Cell           string                  `json:"cell"`
	DatabaseID     string                  `json:"database_id"`
	PartitionID    string                  `json:"partition_id"`
	Nonce          string                  `json:"nonce"`
	ObservedAt     time.Time               `json:"observed_at"`
	AuthorityEpoch uint64                  `json:"authority_epoch"`
	Generation     uint64                  `json:"generation,omitzero"`
	PayloadSHA256  string                  `json:"payload_sha256,omitempty"`
	Sequence       uint64                  `json:"placement_sequence,omitzero"`
	Terminal       bool                    `json:"terminal,omitzero"`
	Serving        bool                    `json:"serving"`
	Members        []placementMemberStatus `json:"members"`
	Holds          []placementHoldRecord   `json:"holds,omitempty"`
}

type placementMemberStatus struct {
	SeatID            string                 `json:"seat_id"`
	MemberID          string                 `json:"member_id,omitempty"`
	FailureDomain     string                 `json:"failure_domain,omitempty"`
	Stage             string                 `json:"stage"`
	HostAttempt       uint64                 `json:"host_attempt,omitzero"`
	InstanceID        string                 `json:"instance_id,omitempty"`
	HostNode          string                 `json:"host_node,omitempty"`
	VolumeID          string                 `json:"volume_id,omitempty"`
	AttachmentID      string                 `json:"attachment_id,omitempty"`
	AttachmentDevice  string                 `json:"attachment_device,omitempty"`
	DesiredGeneration uint64                 `json:"desired_generation,omitzero"`
	ArtifactDigest    string                 `json:"artifact_digest,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at,omitzero"`
	Host              *placementHostStatus   `json:"host,omitempty"`
	Update            *placementUpdateStatus `json:"update,omitempty"`
	// UpdatePins are the exact predecessor pins a managed update of this
	// seat must sign, present once the seat has a host and attached volume.
	UpdatePins *placement.ManagedUpdateSeat `json:"update_pins,omitempty"`
}

type placementHostStatus struct {
	SessionCurrent   bool      `json:"session_current"`
	SessionExpiresAt time.Time `json:"session_expires_at,omitzero"`
	ReportState      string    `json:"report_state,omitempty"`
	ReportError      string    `json:"report_error,omitempty"`
	ReportDigest     string    `json:"report_digest,omitempty"`
	ReportGeneration uint64    `json:"report_generation,omitzero"`
	ReportObservedAt time.Time `json:"report_observed_at,omitzero"`
	MountPath        string    `json:"mount_path,omitempty"`
	ProcessPID       int       `json:"process_pid,omitzero"`
	StorageRecovered bool      `json:"storage_recovered"`
	ListenerReady    bool      `json:"listener_ready"`
	ServingProof     bool      `json:"serving_proof"`
}

type placementUpdateStatus struct {
	OperationID            string `json:"operation_id"`
	ArtifactDigest         string `json:"artifact_digest"`
	SourceDigest           string `json:"source_digest"`
	PreviousArtifactDigest string `json:"previous_artifact_digest"`
	Phase                  string `json:"phase"`
	Outcome                string `json:"outcome,omitempty"`
}

type placementHoldRecord struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// placementHoldLog keeps the latest placement holds and reconciliation
// errors so status can explain why a member is not advancing.
type placementHoldLog struct {
	mu      sync.Mutex
	records []placementHoldRecord
}

func (log *placementHoldLog) record(reason string) {
	log.recordChange(reason)
}

// recordChange records reason and reports whether it differs from the
// latest record, so a repeated hold is not re-announced as a new event.
func (log *placementHoldLog) recordChange(reason string) bool {
	if log == nil {
		return false
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	now := time.Now().UTC()
	if count := len(log.records); count > 0 && log.records[count-1].Reason == reason {
		log.records[count-1].At = now
		return false
	}
	log.records = append(log.records, placementHoldRecord{At: now, Reason: reason})
	if len(log.records) > maxPlacementHoldRecords {
		log.records = slices.Delete(log.records, 0, len(log.records)-maxPlacementHoldRecords)
	}
	return true
}

func (log *placementHoldLog) recent(now time.Time) []placementHoldRecord {
	if log == nil {
		return nil
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	var recent []placementHoldRecord
	for _, record := range log.records {
		if now.Sub(record.At) <= placementHoldRetention {
			recent = append(recent, record)
		}
	}
	return recent
}

// operatorTerraBaseStatus reports the controller's durable member stages and
// host observations for the deployment in statePath, optionally waiting until
// both members serve.
func operatorTerraBaseStatus(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	statePath string, wait time.Duration, output io.Writer,
) error {
	state, err := openDeployState(statePath)
	if err != nil {
		return err
	}
	var intent placement.Intent
	exists, err := state.readJSON(deployIntentFile, &intent)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("deployment state has no rendered placement intent; run terrabase-deploy first")
	}
	deadline := time.Now().Add(wait)
	var previous []byte
	for {
		report, err := requestPlacementStatus(ctx, cfg, runtime, intent.DatabaseID, intent.PartitionID)
		if err != nil {
			return err
		}
		fingerprint, err := protocol.EncodeJSON(struct {
			Members []placementMemberStatus `json:"members"`
			Holds   []string                `json:"holds"`
		}{statusProgress(report.Members), holdReasons(report.Holds)})
		if err != nil {
			return err
		}
		if !bytes.Equal(fingerprint, previous) || report.Serving || !time.Now().Before(deadline) {
			if err := printJSON(output, report); err != nil {
				return err
			}
			previous = fingerprint
		}
		if report.Serving || wait == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("TerraBase members did not all serve within %s", wait)
		}
		timer := time.NewTimer(min(placementStatusPollInterval, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// statusProgress drops fields that change on every poll, so --wait prints a
// report only when a member actually moves.
func statusProgress(members []placementMemberStatus) []placementMemberStatus {
	stable := slices.Clone(members)
	for index := range stable {
		stable[index].UpdatedAt = time.Time{}
		if stable[index].Host != nil {
			hostStatus := *stable[index].Host
			hostStatus.SessionExpiresAt, hostStatus.ReportObservedAt = time.Time{}, time.Time{}
			stable[index].Host = &hostStatus
		}
	}
	return stable
}

func holdReasons(records []placementHoldRecord) []string {
	reasons := make([]string, 0, len(records))
	for _, record := range records {
		reasons = append(reasons, record.Reason)
	}
	return reasons
}

// statusRejected marks a placement status failure that no retry can fix:
// the operator's own authorization or key configuration, or a reply that
// fails verification or answers another request. Transport, timeout and
// authority-lease failures stay unmarked and are retryable.
type statusRejected struct{ error }

func (s statusRejected) Unwrap() error { return s.error }

func requestPlacementStatus(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	database, partition string,
) (placementStatusReport, error) {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return placementStatusReport{}, statusRejected{err}
	}
	grant, exists := policy.grant(cfg.Operator.Actor)
	if !exists || !grant.CanPlaceTerraBase {
		return placementStatusReport{}, statusRejected{errors.New("operator is not authorized to read TerraBase placement status")}
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return placementStatusReport{}, statusRejected{err}
	}
	controllerKey, err := decodePublicKey(cfg.Operator.ControllerPublicKey)
	if err != nil {
		return placementStatusReport{}, statusRejected{fmt.Errorf("operator controller key pin: %w", err)}
	}
	epoch, err := authoritySnapshot(ctx, runtime, cfg.NATS.Cell)
	if err != nil {
		return placementStatusReport{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return placementStatusReport{}, err
	}
	request := placementStatusRequest{DatabaseID: database, PartitionID: partition, Nonce: hex.EncodeToString(nonce[:])}
	payload, err := protocol.EncodeJSON(request)
	if err != nil {
		return placementStatusReport{}, err
	}
	scope := protocol.EnvelopeScope{Region: cfg.NATS.Cell, Kind: managedKindPlacementStatus, Actor: cfg.Operator.Actor,
		OperationID: entityid.Derive("status", request.Nonce), Generation: 1, Epoch: epoch}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, scope, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return placementStatusReport{}, err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return placementStatusReport{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	message, err := runtime.Conn().RequestWithContext(requestCtx, managedAdmissionSubject(cfg.NATS.Cell), wire)
	if err != nil {
		return placementStatusReport{}, fmt.Errorf("request TerraBase placement status: %w", err)
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &signed, maxPlacementStatusReplyBytes); err != nil {
		return placementStatusReport{}, statusRejected{err}
	}
	scope.Kind, scope.Actor = placementStatusReplyKind, "controller"
	if err := protocol.VerifyEnvelope(signed, scope, controllerKey, time.Now().UTC(),
		protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return placementStatusReport{}, statusRejected{fmt.Errorf("unauthenticated placement status: %w", err)}
	}
	var report placementStatusReport
	if err := protocol.DecodeStrict(signed.Payload, &report, maxPlacementStatusReplyBytes); err != nil {
		return placementStatusReport{}, statusRejected{err}
	}
	if report.Cell != cfg.NATS.Cell || report.DatabaseID != database || report.PartitionID != partition ||
		report.Nonce != request.Nonce {
		return placementStatusReport{}, statusRejected{errors.New("placement status reply answers a different request")}
	}
	return report, nil
}

type placementStatusSource struct {
	cell            string
	policy          signerPolicy
	control         placementStatusAuthority
	placements      placement.Store
	hosts           placement.HostView
	holds           *placementHoldLog
	responseKey     ed25519.PrivateKey
	owner           string
	fleetGeneration uint64
}

type placementStatusAuthority interface {
	authority.Fencer
	ReadPlacementIntent(context.Context, string, string) (authority.LogEntry, error)
}

// servePlacementStatus answers signed operator status reads on the leader.
// It is read-only: it never advances placement or touches OCI.
func servePlacementStatus(ctx context.Context, conn *nats.Conn, source placementStatusSource) (*nats.Subscription, error) {
	if source.placements == nil || source.hosts == nil || len(source.responseKey) != ed25519.PrivateKeySize {
		return nil, errors.New("placement status requires placement state, host view and response key")
	}
	return serveManagedAdmissionKind(ctx, conn, source.cell, managedKindPlacementStatus, func(ctx context.Context, message *nats.Msg) {
		if len(message.Data) > maxPlacementStatusRequestBytes+4096 || !source.control.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		wire, err := source.answer(requestCtx, message.Data)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func (source placementStatusSource) answer(ctx context.Context, wire []byte) ([]byte, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxPlacementStatusRequestBytes+4096); err != nil {
		return nil, err
	}
	var request placementStatusRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxPlacementStatusRequestBytes); err != nil {
		return nil, err
	}
	canonical, err := protocol.EncodeJSON(request)
	grant, granted := source.policy.grant(envelope.Actor)
	trusted, known := source.policy.trusted(envelope.KeyID)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) || !granted || !grant.CanPlaceTerraBase ||
		!known || trusted.Actor != envelope.Actor || len(request.Nonce) != 32 || !lowerHexString(request.Nonce) {
		return nil, errors.New("placement status request is not authorized")
	}
	scope := protocol.EnvelopeScope{Region: source.cell, Kind: managedKindPlacementStatus, Actor: trusted.Actor,
		OperationID: entityid.Derive("status", request.Nonce), Generation: 1, Epoch: envelope.Epoch}
	if err := protocol.VerifyEnvelope(envelope, scope, trusted.PublicKey, time.Now().UTC(),
		protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return nil, err
	}
	if envelope.Epoch == 0 || source.control.Current().Epoch != envelope.Epoch {
		return nil, authority.ErrFenced
	}
	report, err := source.report(ctx, request, envelope.Epoch)
	if err != nil {
		return nil, err
	}
	payload, err := protocol.EncodeJSON(report)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	scope.Kind, scope.Actor = placementStatusReplyKind, "controller"
	signed, err := protocol.SignEnvelope(payload, scope, now, now.Add(time.Minute), source.responseKey)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeJSON(signed)
}

func (source placementStatusSource) report(ctx context.Context, request placementStatusRequest, epoch uint64) (placementStatusReport, error) {
	now := time.Now().UTC()
	report := placementStatusReport{Cell: source.cell, DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		Nonce: request.Nonce, ObservedAt: now, AuthorityEpoch: epoch}
	intents, err := source.placements.ListIntents(ctx)
	if err != nil {
		return placementStatusReport{}, err
	}
	var intent *placement.Intent
	for index := range intents {
		if intents[index].DatabaseID == request.DatabaseID && intents[index].PartitionID == request.PartitionID {
			intent = &intents[index]
		}
	}
	if _, err := source.placements.ReadTerminalIntent(ctx, request.DatabaseID, request.PartitionID); err == nil {
		report.Terminal = true
	} else if !errors.Is(err, authority.ErrNotFound) {
		return placementStatusReport{}, err
	}
	members, err := source.placements.ListMembers(ctx, request.DatabaseID, request.PartitionID)
	if err != nil {
		return placementStatusReport{}, err
	}
	statuses, err := source.hosts.ListHosts(ctx)
	if err != nil {
		return placementStatusReport{}, err
	}
	byNode := make(map[string]host.HostStatus, len(statuses))
	for _, status := range statuses {
		byNode[status.Registration.Node] = status
	}
	byMember := make(map[string]placement.MemberState, len(members))
	for _, member := range members {
		byMember[member.State.MemberID] = member.State
	}
	var seats []string
	if intent != nil {
		report.Generation, report.PayloadSHA256 = intent.Generation, intent.PayloadDigest()
		for _, row := range intent.CanonicalRoster.Rows {
			seats = append(seats, row.SeatID)
		}
		entry, err := source.control.ReadPlacementIntent(ctx, request.DatabaseID, request.PartitionID)
		if err != nil {
			return placementStatusReport{}, err
		}
		report.Sequence = entry.Sequence
	}
	for _, member := range members {
		if !slices.Contains(seats, member.State.MemberID) {
			seats = append(seats, member.State.MemberID)
		}
	}
	report.Serving = intent != nil && !report.Terminal && len(seats) > 0
	for _, seat := range seats {
		entry := placementMemberStatus{SeatID: seat, Stage: "unprepared"}
		if intent != nil {
			for _, row := range intent.CanonicalRoster.Rows {
				if row.SeatID == seat {
					entry.MemberID, entry.FailureDomain = row.MemberID, row.FailureDomain
				}
			}
		}
		if state, exists := byMember[seat]; exists {
			manifest := state.EffectiveRuntimeManifest()
			entry.MemberID, entry.FailureDomain = state.CanonicalRosterRow.MemberID, state.FailureDomain
			entry.Stage, entry.HostAttempt = string(state.Stage), state.HostAttempt
			entry.InstanceID, entry.HostNode, entry.VolumeID = state.InstanceID, state.HostNode, state.VolumeID
			entry.AttachmentID, entry.AttachmentDevice = state.AttachmentID, state.AttachmentDevice
			entry.DesiredGeneration, entry.ArtifactDigest, entry.UpdatedAt = state.DesiredGeneration, manifest.ArtifactDigest, state.UpdatedAt
			if target := state.ManagedRuntimeTarget; target.OperationID != "" {
				entry.Update = &placementUpdateStatus{OperationID: target.OperationID, ArtifactDigest: target.ArtifactDigest,
					SourceDigest: target.SourceDigest, PreviousArtifactDigest: target.PreviousArtifactDigest,
					Phase: string(target.Phase), Outcome: target.Outcome}
			}
			if state.InstanceID != "" && state.AttachmentID != "" && state.DesiredGeneration != 0 {
				pins := placement.ManagedUpdateSeatFor(state, source.owner, source.fleetGeneration)
				entry.UpdatePins = &pins
			}
			if status, registered := byNode[state.HostNode]; registered && state.HostNode != "" {
				entry.Host = memberHostStatus(status, state, now)
			}
		}
		report.Serving = report.Serving && entry.Stage == string(placement.StageServing)
		report.Members = append(report.Members, entry)
	}
	report.Holds = source.holds.recent(now)
	for index := range report.Holds {
		if !holdMentions(report.Holds[index].Reason, request, seats) {
			report.Holds[index].Reason = ""
		}
	}
	report.Holds = slices.DeleteFunc(report.Holds, func(record placementHoldRecord) bool { return record.Reason == "" })
	return report, nil
}

func memberHostStatus(status host.HostStatus, state placement.MemberState, now time.Time) *placementHostStatus {
	observed := &placementHostStatus{SessionCurrent: status.Verified && now.Before(status.SessionExpiresAt),
		SessionExpiresAt: status.SessionExpiresAt}
	for _, report := range status.Reports {
		if report.Managed == nil || report.Managed.Member.Scope.MemberID != state.CanonicalRosterRow.MemberID {
			continue
		}
		observed.ReportState, observed.ReportError, observed.ReportDigest = report.State, report.Error, report.Digest
		observed.ReportGeneration, observed.ReportObservedAt = report.Generation, report.ObservedAt
		observed.MountPath, observed.ProcessPID = report.Managed.MountPath, report.Managed.ProcessPID
		observed.StorageRecovered, observed.ListenerReady = report.Managed.StorageRecovered, report.Managed.ListenerReady
		observed.ServingProof = report.Managed.ServingProof != nil
	}
	if observed.ReportState == "" {
		for _, report := range status.Reports {
			if report.Managed == nil && report.Error != "" {
				observed.ReportState, observed.ReportError = report.State, report.Error
			}
		}
	}
	return observed
}

// holdMentions keeps a hold only when it names this database or one of its
// seats, as placement holds and reconciliation errors do.
func holdMentions(reason string, request placementStatusRequest, seats []string) bool {
	if strings.Contains(reason, request.DatabaseID+"/") {
		return true
	}
	for _, seat := range seats {
		if strings.Contains(reason, "member "+seat+" ") || strings.Contains(reason, "/"+seat+":") {
			return true
		}
	}
	return false
}

func lowerHexString(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
