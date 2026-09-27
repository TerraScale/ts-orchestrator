package app

import (
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
