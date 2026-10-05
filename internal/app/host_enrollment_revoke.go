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
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type hostEnrollmentRevoke struct {
	SchemaVersion int    `json:"schema_version"`
	InstanceID    string `json:"instance_id"`
}

type hostEnrollmentRevokeReceipt struct {
	InstanceID    string `json:"instance_id"`
	GrantRevision uint64 `json:"grant_revision"`
	Disabled      bool   `json:"disabled"`
}

type hostEnrollmentRevokeReply struct {
	Receipt hostEnrollmentRevokeReceipt `json:"receipt"`
	Error   string                      `json:"error,omitempty"`
}

func hostEnrollmentRevokeOperationID(instanceID string) string {
	sum := sha256.Sum256([]byte(instanceID))
	return "host-enrollment-revoke." + hex.EncodeToString(sum[:])
}

func operatorHostEnrollmentRevoke(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	instanceID string, output io.Writer,
) error {
	if !validEnrollmentInstanceID(instanceID) {
		return errors.New("host-enrollment-revoke requires a valid --instance-id")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, ok := policy.grants[cfg.Operator.Actor]
	if !ok || !grant.CanRegisterHosts || !grant.CanPlaceTerraBase ||
		!slices.Contains(grant.Roles, "terrabase") ||
		!slices.Contains(grant.Environments, "production") && !slices.Contains(grant.Environments, "canary") {
		return errors.New("operator cannot revoke managed host enrollment")
	}
	codec, err := policy.withOperator(cfg.Operator)
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
	payload, err := protocol.EncodeJSON(hostEnrollmentRevoke{SchemaVersion: 1, InstanceID: instanceID})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "host.enrollment.revoke", Actor: cfg.Operator.Actor,
		OperationID: hostEnrollmentRevokeOperationID(instanceID), Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, hostRegistrationSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var response hostEnrollmentRevokeReply
			if err := protocol.DecodeStrict(message.Data, &response, 4096); err != nil {
				return fmt.Errorf("decode host enrollment revoke reply: %w", err)
			}
			if response.Error != "" {
				return errors.New(response.Error)
			}
			if response.Receipt.InstanceID != instanceID || !response.Receipt.Disabled || response.Receipt.GrantRevision == 0 {
				return errors.New("host enrollment revoke reply lacks the exact grant revision")
			}
			return printJSON(output, response.Receipt)
		}
		if (!errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded)) || attempt == 2 {
			return fmt.Errorf("request host enrollment revoke: %w", requestErr)
		}
	}
	return errors.New("host enrollment revoke request exhausted")
}

func validEnrollmentInstanceID(instanceID string) bool {
	if len(instanceID) <= len("ocid1.instance.") || len(instanceID) > 255 ||
		!strings.HasPrefix(instanceID, "ocid1.instance.") {
		return false
	}
	for _, character := range instanceID {
		if character != '.' && character != '-' && character != '_' &&
			(character < '0' || character > '9') &&
			(character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

func verifyAndRevokeHostEnrollment(ctx context.Context, wire []byte, cell string,
	policy signerPolicy, enrollment *managedHostEnrollment,
) (hostEnrollmentRevokeReceipt, error) {
	if enrollment == nil || enrollment.grants == nil {
		return hostEnrollmentRevokeReceipt{}, errors.New("managed host enrollment is unavailable")
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	var request hostEnrollmentRevoke
	if err := protocol.DecodeStrict(envelope.Payload, &request, 4096); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	if request.SchemaVersion != 1 || !validEnrollmentInstanceID(request.InstanceID) {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment revoke request is invalid")
	}
	grant, ok := policy.grants[envelope.Actor]
	if !ok || !grant.CanRegisterHosts || !grant.CanPlaceTerraBase ||
		!slices.Contains(grant.Roles, "terrabase") || !slices.Contains(grant.Environments, enrollment.environment) {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment revoke actor is unauthorized")
	}
	trusted, ok := policy.codec.Trusted[envelope.KeyID]
	if !ok || trusted.Actor != envelope.Actor {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment revoke signer is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: "host.enrollment.revoke", Actor: trusted.Actor,
		OperationID: hostEnrollmentRevokeOperationID(request.InstanceID), Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{
		MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second,
	}); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	if envelope.Epoch == 0 || enrollment.fencer.Current().Epoch != envelope.Epoch {
		return hostEnrollmentRevokeReceipt{}, authority.ErrFenced
	}
	if err := enrollment.fencer.Guard(ctx, envelope.Epoch); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	return enrollment.revoke(ctx, envelope.Epoch, request.InstanceID)
}

func (enrollment *managedHostEnrollment) revoke(ctx context.Context, epoch uint64,
	instanceID string,
) (hostEnrollmentRevokeReceipt, error) {
	grant, _, err := enrollment.grants.Read(ctx, instanceID)
	if err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	var original hostenroll.Request
	if json.Unmarshal(grant.Request, &original, json.RejectUnknownMembers(true)) != nil {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment grant request is invalid")
	}
	request, descriptor, err := hostenroll.ParseRequest(grant.Request, original.IssuedAt.Add(time.Second))
	if err == nil && descriptor.IsStatic() {
		return enrollment.revokeStatic(ctx, epoch, instanceID, grant, request, descriptor)
	}
	if err != nil || request.Operation != "enroll" || request.InstanceID != instanceID ||
		descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) ||
		descriptor.Owner != enrollment.owner || descriptor.FleetGeneration != enrollment.generation ||
		descriptor.CreateKey != grant.CreateKey {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment grant is not bound to this regional managed fleet")
	}
	digest, err := descriptor.Digest()
	if err != nil || digest != grant.DescriptorSHA256 {
		return hostEnrollmentRevokeReceipt{}, errors.New("host enrollment grant descriptor differs from its durable pin")
	}
	member, err := enrollment.members.ReadMember(ctx, descriptor.DatabaseID, descriptor.PartitionID, descriptor.SeatID)
	if err != nil || member.Revision == 0 || member.State.Validate() != nil ||
		member.State.DatabaseID != descriptor.DatabaseID ||
		member.State.PartitionID != descriptor.PartitionID ||
		member.State.MemberID != descriptor.SeatID || member.State.Region != enrollment.region {
		return hostEnrollmentRevokeReceipt{}, errors.New("current managed placement seat is unavailable")
	}
	entry, err := enrollment.intents.ReadPlacementIntent(ctx, descriptor.DatabaseID, descriptor.PartitionID)
	if err != nil || entry.Kind != authority.MutationPlacementIntent ||
		entry.SubjectKey != descriptor.DatabaseID+"."+descriptor.PartitionID ||
		entry.Sequence == 0 || entry.Epoch == 0 || len(entry.Payload) == 0 ||
		len(entry.Payload) > maxPlacementIntentBytes {
		return hostEnrollmentRevokeReceipt{}, errors.New("current managed placement intent is unavailable")
	}
	intent, err := placement.DecodeCommittedIntent(entry.Payload)
	if err != nil || intent.ValidateForAdmission() != nil ||
		intent.DatabaseID != descriptor.DatabaseID || intent.PartitionID != descriptor.PartitionID ||
		intent.OperationID() != entry.OperationID || !intentSelectsCell(intent, enrollment.cell) ||
		intent.Generation < descriptor.IntentGeneration || member.State.IntentGeneration > intent.Generation {
		return hostEnrollmentRevokeReceipt{}, errors.New("current managed placement intent is invalid")
	}
	instances, err := enrollment.fleet.Observe(ctx)
	if err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	// A terminated instance can be absent from OCI. The exact durable grant,
	// current owned seat, and operator authority still permit disabling it.
	seenExact := false
	for _, observed := range instances {
		if observed.Node == descriptor.Node && observed.ID != instanceID {
			return hostEnrollmentRevokeReceipt{}, errors.New("current OCI node conflicts with the revoked grant")
		}
		if observed.ID == instanceID && (seenExact || observed.Node != descriptor.Node ||
			observed.CreateKey != descriptor.CreateKey || observed.Owner != enrollment.owner ||
			observed.Region != enrollment.region || observed.Generation != enrollment.generation) {
			return hostEnrollmentRevokeReceipt{}, errors.New("current OCI instance differs from the revoked grant")
		}
		if observed.ID == instanceID {
			seenExact = true
		}
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	revision, err := enrollment.grants.Disable(ctx, instanceID)
	if err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	return hostEnrollmentRevokeReceipt{InstanceID: instanceID, GrantRevision: revision, Disabled: true}, nil
}

type terminalEnrollmentEffectLedger interface {
	ListPendingEnrollmentEffects(context.Context, authority.WorkloadScope) ([]authority.EnrollmentEffect, error)
	SettleEnrollmentEffect(context.Context, uint64, authority.WorkloadScope, string, string, uint64) (uint64, error)
	SettleFencedEnrollmentEffect(context.Context, uint64, authority.WorkloadScope, string, string, uint64,
		func(context.Context) error) (uint64, error)
}

// fenceTerminalGrants is called before the marker. Each exact grant is disabled
// with a per-key CAS, and every absent key becomes a durable tombstone before
// the handler attempts terminal-marker commit.
func (enrollment *managedHostEnrollment) fenceTerminalGrants(ctx context.Context, epoch uint64,
	intent authority.TerminalIntent,
) error {
	if enrollment == nil || enrollment.grants == nil || enrollment.members == nil {
		return errors.New("managed terminal grant fencing is unavailable")
	}
	if err := enrollment.validateTerminalGrantIntent(intent); err != nil {
		return err
	}
	if epoch == 0 || enrollment.fencer.Current().Epoch != epoch {
		return authority.ErrFenced
	}
	reader, ok := enrollment.fencer.(authority.TerminalIntentReader)
	if !ok {
		return errors.New("terminal grant fencing requires authority marker access")
	}
	if _, err := reader.ReadTerminalIntent(ctx, intent.DatabaseID, intent.PartitionID); err == nil {
		return authority.ErrFenced
	} else if !errors.Is(err, authority.ErrNotFound) {
		return err
	}
	for _, target := range intent.Targets {
		if target.InstanceID == "" {
			continue
		}
		fenced := false
		for range 4 {
			if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
				return err
			}
			grant, revision, err := enrollment.grants.Read(ctx, target.InstanceID)
			if errors.Is(err, jetstream.ErrKeyNotFound) {
				expected := hostenroll.Grant{SchemaVersion: 1,
					InstanceID: target.InstanceID, CreateKey: target.HostCreateKey}
				_, _, err = enrollment.grants.TerminalFence(ctx, expected, 0, intent.OperationID)
				if errors.Is(err, hostenroll.ErrTerminalFenceConflict) {
					continue
				}
				if err != nil {
					return fmt.Errorf("create terminal grant tombstone for seat %s: %w", target.SeatID, err)
				}
			} else if err != nil {
				return fmt.Errorf("read terminal grant for seat %s: %w", target.SeatID, err)
			} else {
				if !isTerminalGrantTombstone(grant, target, intent.OperationID) {
					if err := enrollment.verifyTerminalGrantBinding(ctx, intent, target, grant, revision); err != nil {
						return fmt.Errorf("terminal grant for seat %s: %w", target.SeatID, err)
					}
				}
				if _, _, err := enrollment.grants.TerminalFence(ctx, grant, revision, intent.OperationID); err != nil {
					if errors.Is(err, hostenroll.ErrTerminalFenceConflict) {
						continue
					}
					return fmt.Errorf("fence terminal grant for seat %s: %w", target.SeatID, err)
				}
			}
			if err := enrollment.verifyTerminalGrantTarget(ctx, intent, target); err != nil {
				return fmt.Errorf("terminal grant fence readback for seat %s: %w", target.SeatID, err)
			}
			fenced = true
			break
		}
		if !fenced {
			return fmt.Errorf("terminal grant for seat %s changed repeatedly during fencing", target.SeatID)
		}
	}
	return enrollment.settleFencedEnrollmentEffects(ctx, epoch, intent)
}

func (enrollment *managedHostEnrollment) settleFencedEnrollmentEffects(ctx context.Context, epoch uint64,
	intent authority.TerminalIntent,
) error {
	ledger, ok := enrollment.fencer.(terminalEnrollmentEffectLedger)
	if !ok {
		return errors.New("terminal grant fencing requires durable enrollment-effect settlement")
	}
	scope := authority.WorkloadScope{DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID}
	pending, err := ledger.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil {
		return err
	}
	targets := make(map[string]authority.TerminalTarget, len(intent.Targets))
	for _, target := range intent.Targets {
		if target.InstanceID != "" {
			targets[target.InstanceID] = target
		}
	}
	for _, effect := range pending {
		target, exists := targets[effect.InstanceID]
		if !exists || effect.Epoch > epoch {
			return fmt.Errorf("unmatched enrollment effect %s blocks terminal admission", effect.EffectID)
		}
		if err := enrollment.verifyTerminalGrantTarget(ctx, intent, target); err != nil {
			return fmt.Errorf("pending enrollment effect %s lacks its exact disabled grant fence: %w", effect.EffectID, err)
		}
		if effect.Epoch == epoch {
			_, err = ledger.SettleEnrollmentEffect(ctx, epoch, scope,
				effect.EffectID, effect.InstanceID, effect.Sequence)
		} else {
			verifyFence := func(verifyCtx context.Context) error {
				return enrollment.verifyTerminalGrantTarget(verifyCtx, intent, target)
			}
			_, err = ledger.SettleFencedEnrollmentEffect(ctx, epoch, scope,
				effect.EffectID, effect.InstanceID, effect.Sequence, verifyFence)
		}
		if err != nil {
			return fmt.Errorf("settle terminally fenced enrollment effect %s: %w", effect.EffectID, err)
		}
	}
	pending, err = ledger.ListPendingEnrollmentEffects(ctx, scope)
	if err != nil {
		return err
	}
	if len(pending) != 0 {
		return errors.New("unsettled enrollment effects remain after exact grant fencing")
	}
	return nil
}

func (enrollment *managedHostEnrollment) validateTerminalGrantIntent(intent authority.TerminalIntent) error {
	if err := intent.Validate(); err != nil || intent.Cell != enrollment.cell ||
		intent.Region != string(enrollment.region) || intent.Owner != enrollment.owner ||
		intent.FleetGeneration != enrollment.generation {
		return errors.New("terminal grant intent differs from the current regional fleet")
	}
	return nil
}

func isTerminalGrantTombstone(grant hostenroll.Grant, target authority.TerminalTarget,
	operationID string,
) bool {
	return grant.SchemaVersion == 1 && grant.InstanceID == target.InstanceID &&
		grant.CreateKey == target.HostCreateKey && grant.Disabled &&
		grant.TerminalOperationID == operationID && grant.DescriptorSHA256 == "" &&
		len(grant.Request) == 0 && len(grant.Response) == 0 && grant.OwnerToken == "" &&
		grant.LeaseUntil.IsZero() && len(grant.RenewalRequest) == 0 &&
		len(grant.RenewalResponse) == 0 && grant.RenewalToken == "" &&
		grant.RenewalLeaseUntil.IsZero()
}

func (enrollment *managedHostEnrollment) verifyTerminalGrantTarget(ctx context.Context,
	intent authority.TerminalIntent, target authority.TerminalTarget,
) error {
	if target.InstanceID == "" {
		return nil
	}
	grant, revision, err := enrollment.grants.Read(ctx, target.InstanceID)
	if err != nil {
		return err
	}
	if revision == 0 || !grant.Disabled || grant.TerminalOperationID != intent.OperationID ||
		grant.InstanceID != target.InstanceID || grant.CreateKey != target.HostCreateKey {
		return errors.New("grant is not the exact disabled terminal fence")
	}
	if isTerminalGrantTombstone(grant, target, intent.OperationID) {
		return nil
	}
	if err := enrollment.verifyTerminalGrantBinding(ctx, intent, target, grant, revision); err != nil {
		return err
	}
	return nil
}

// verifyTerminalGrantFence is a read-only proof used before marker commit.
// Every inventory target with an instance ID must have an exact disabled
// grant or create-if-absent tombstone tied to this terminal operation.
func (enrollment *managedHostEnrollment) verifyTerminalGrantFence(ctx context.Context,
	intent authority.TerminalIntent,
) error {
	if enrollment == nil || enrollment.grants == nil || enrollment.members == nil {
		return errors.New("managed terminal grant readback is unavailable")
	}
	if err := enrollment.validateTerminalGrantIntent(intent); err != nil {
		return err
	}
	for _, target := range intent.Targets {
		if err := enrollment.verifyTerminalGrantTarget(ctx, intent, target); err != nil {
			return fmt.Errorf("terminal grant for seat %s: %w", target.SeatID, err)
		}
	}
	return nil
}

// verifyTerminalGrants returns only after every terminal target has an exact
// disabled grant or tombstone tied to the accepted operation and read back.
func (enrollment *managedHostEnrollment) verifyTerminalGrants(ctx context.Context,
	intent authority.TerminalIntent,
) error {
	if enrollment == nil || enrollment.grants == nil || enrollment.members == nil {
		return errors.New("managed terminal grant readback is unavailable")
	}
	if err := enrollment.validateTerminalGrantIntent(intent); err != nil {
		return err
	}
	if err := enrollment.verifyCurrentTerminalIntent(ctx, intent); err != nil {
		return err
	}
	return enrollment.verifyTerminalGrantFence(ctx, intent)
}

func (enrollment *managedHostEnrollment) verifyCurrentTerminalIntent(ctx context.Context,
	intent authority.TerminalIntent,
) error {
	reader, ok := enrollment.fencer.(authority.TerminalIntentReader)
	if !ok {
		return errors.New("terminal grant readback requires authority marker access")
	}
	entry, err := reader.ReadTerminalIntent(ctx, intent.DatabaseID, intent.PartitionID)
	if err != nil {
		return err
	}
	payload, err := protocol.EncodeJSON(intent)
	if err != nil || entry.Sequence == 0 || !bytes.Equal(entry.Payload, payload) {
		return errors.New("terminal grant readback intent differs from the immutable authority marker")
	}
	return nil
}

func (enrollment *managedHostEnrollment) verifyTerminalGrantBinding(ctx context.Context,
	intent authority.TerminalIntent, target authority.TerminalTarget, grant hostenroll.Grant, revision uint64,
) error {
	if revision == 0 || grant.SchemaVersion != 1 || grant.InstanceID != target.InstanceID ||
		grant.CreateKey != target.HostCreateKey || len(grant.Request) == 0 {
		return errors.New("grant identity differs from the exact terminal pins")
	}
	var original hostenroll.Request
	if json.Unmarshal(grant.Request, &original, json.RejectUnknownMembers(true)) != nil || original.IssuedAt.IsZero() {
		return errors.New("grant request is invalid")
	}
	request, descriptor, err := hostenroll.ParseRequest(grant.Request, original.IssuedAt.Add(time.Second))
	if err != nil || request.Operation != "enroll" || request.InstanceID != target.InstanceID ||
		descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) ||
		descriptor.Owner != enrollment.owner || descriptor.FleetGeneration != enrollment.generation ||
		descriptor.DatabaseID != intent.DatabaseID || descriptor.PartitionID != intent.PartitionID ||
		descriptor.SeatID != target.SeatID || descriptor.CreateKey != target.HostCreateKey {
		return errors.New("grant request descriptor differs from the exact terminal workload pins")
	}
	digest, err := descriptor.Digest()
	if err != nil || digest != grant.DescriptorSHA256 {
		return errors.New("grant descriptor digest differs from its durable pin")
	}
	member, err := enrollment.members.ReadMember(ctx, intent.DatabaseID, intent.PartitionID, target.SeatID)
	if err != nil || member.Revision == 0 || member.State.Validate() != nil ||
		member.State.DatabaseID != intent.DatabaseID || member.State.PartitionID != intent.PartitionID ||
		member.State.MemberID != target.SeatID || member.State.Region != enrollment.region ||
		member.State.HostNode != descriptor.Node || member.State.HostAttempt != descriptor.HostAttempt ||
		member.State.InstanceID != target.InstanceID || member.State.CreateKey != target.HostCreateKey ||
		member.State.VolumeID != target.DataVolumeID ||
		member.State.CanonicalRosterRow.MemberID != target.MemberID {
		return errors.New("grant does not match the durable placement seat")
	}
	return nil
}
