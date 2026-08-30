// Port of src/TerraScale.Orchestrator/ControlPlane/Runtime/RuntimeCommandContracts.cs
package control

import (
	"strconv"
	"time"
)

// NativeGitOpsAcceptedCellSpec is the immutable scalar acceptance receipt
// consumed by the runtime command boundary. Payload bytes stay in the delivery
// journal and are deliberately excluded from host commands.
type NativeGitOpsAcceptedCellSpec struct {
	Cell             string
	Generation       int64
	GlobalPlanDigest string
	HandoffDigest    string
	PayloadSha256    string
	WriterEpoch      int64
	ProtocolVersion  int64
	OperationId      string
	IdempotencyKey   string
	DeliveryAttempt  int64
	IssuedAt         time.Time
	ExpiresAt        time.Time
	AcceptedAt       time.Time
	StreamSequence   uint64
	SignatureSha256  string
	JournalRevision  uint64
}

// NativeGitOpsVerifiedConvergenceDispatchV1 is the durable convergence receipt
// accepted by the runtime command boundary.
type NativeGitOpsVerifiedConvergenceDispatchV1 struct {
	Cell                      string
	Generation                int64
	GlobalPlanDigest          string
	HandoffDigest             string
	PayloadSha256             string
	WriterEpoch               int64
	AcceptanceStreamSequence  uint64
	AcceptanceSignatureSha256 string
	AcceptanceRevision        uint64
	IntentWorkloadId          string
	IntentGeneration          int64
	IntentWorkloadSha256      string
	CheckpointSequence        int64
	PreviousCheckpointDigest  string
	CheckpointDigest          string
	JournalRevision           uint64
}

// RuntimeCommandV1 is the internal v1 command for a future durable host
// consumer. It is deliberately not a transport DTO and is emitted only by the
// Native GitOps projector after all persisted fences agree.
type RuntimeCommandV1 struct {
	SchemaVersion                       int
	AcceptedOperationId                 string
	AcceptedIdempotencyKey              string
	AcceptedCell                        RuntimeLifecycleCellId
	AcceptedGeneration                  RuntimeGeneration
	AcceptedGlobalPlanDigest            RuntimeDigest
	AcceptedHandoffDigest               RuntimeDigest
	AcceptedPayloadDigest               RuntimeDigest
	AcceptedWriterEpoch                 RuntimeEpoch
	AcceptedProtocolVersion             int64
	AcceptedDeliveryAttempt             int64
	AcceptedIssuedAt                    time.Time
	AcceptedExpiresAt                   time.Time
	AcceptedAt                          time.Time
	AcceptanceStreamSequence            uint64
	AcceptanceSignatureDigest           RuntimeDigest
	AcceptanceJournalRevision           uint64
	ConvergenceIntentWorkloadId         string
	ConvergenceIntentGeneration         int64
	ConvergenceIntentWorkloadDigest     RuntimeDigest
	ConvergenceCheckpointSequence       int64
	PreviousConvergenceCheckpointDigest RuntimeDigest
	ConvergenceCheckpointDigest         RuntimeDigest
	ConvergenceJournalRevision          uint64
	Assignment                          RuntimeHostAssignmentV1
	Request                             RuntimeLifecycleOperationRequest
	CanonicalDigest                     RuntimeDigest
}

const RuntimeCommandV1CurrentSchemaVersion = 1

func NewRuntimeCommandV1(
	accepted *NativeGitOpsAcceptedCellSpec,
	checkpoint *NativeGitOpsVerifiedConvergenceDispatchV1,
	assignment RuntimeHostAssignmentV1,
	request RuntimeLifecycleOperationRequest) (*RuntimeCommandV1, error) {
	if accepted == nil {
		return nil, argumentNil("accepted")
	}
	if checkpoint == nil {
		return nil, argumentNil("checkpoint")
	}
	if accepted.Generation <= 0 {
		return nil, argumentOutOfRange("accepted.Generation")
	}
	if accepted.WriterEpoch <= 0 {
		return nil, argumentOutOfRange("accepted.WriterEpoch")
	}
	cell, err := NewRuntimeLifecycleCellId(accepted.Cell)
	if err != nil {
		return nil, err
	}
	acceptedGeneration, err := NewRuntimeGeneration(uint64(accepted.Generation))
	if err != nil {
		return nil, err
	}
	globalPlanDigest, err := NewRuntimeDigest(accepted.GlobalPlanDigest)
	if err != nil {
		return nil, err
	}
	handoffDigest, err := NewRuntimeDigest(accepted.HandoffDigest)
	if err != nil {
		return nil, err
	}
	payloadDigest, err := NewRuntimeDigest(accepted.PayloadSha256)
	if err != nil {
		return nil, err
	}
	writerEpoch, err := NewRuntimeEpoch(uint64(accepted.WriterEpoch))
	if err != nil {
		return nil, err
	}
	signatureDigest, err := NewRuntimeDigest(accepted.SignatureSha256)
	if err != nil {
		return nil, err
	}
	intentWorkloadDigest, err := NewRuntimeDigest(checkpoint.IntentWorkloadSha256)
	if err != nil {
		return nil, err
	}
	previousCheckpointDigest, err := NewRuntimeDigest(checkpoint.PreviousCheckpointDigest)
	if err != nil {
		return nil, err
	}
	checkpointDigest, err := NewRuntimeDigest(checkpoint.CheckpointDigest)
	if err != nil {
		return nil, err
	}
	command := &RuntimeCommandV1{
		SchemaVersion:                       RuntimeCommandV1CurrentSchemaVersion,
		AcceptedOperationId:                 accepted.OperationId,
		AcceptedIdempotencyKey:              accepted.IdempotencyKey,
		AcceptedCell:                        cell,
		AcceptedGeneration:                  acceptedGeneration,
		AcceptedGlobalPlanDigest:            globalPlanDigest,
		AcceptedHandoffDigest:               handoffDigest,
		AcceptedPayloadDigest:               payloadDigest,
		AcceptedWriterEpoch:                 writerEpoch,
		AcceptedProtocolVersion:             accepted.ProtocolVersion,
		AcceptedDeliveryAttempt:             accepted.DeliveryAttempt,
		AcceptedIssuedAt:                    accepted.IssuedAt,
		AcceptedExpiresAt:                   accepted.ExpiresAt,
		AcceptedAt:                          accepted.AcceptedAt,
		AcceptanceStreamSequence:            accepted.StreamSequence,
		AcceptanceSignatureDigest:           signatureDigest,
		AcceptanceJournalRevision:           accepted.JournalRevision,
		ConvergenceIntentWorkloadId:         checkpoint.IntentWorkloadId,
		ConvergenceIntentGeneration:         checkpoint.IntentGeneration,
		ConvergenceIntentWorkloadDigest:     intentWorkloadDigest,
		ConvergenceCheckpointSequence:       checkpoint.CheckpointSequence,
		PreviousConvergenceCheckpointDigest: previousCheckpointDigest,
		ConvergenceCheckpointDigest:         checkpointDigest,
		ConvergenceJournalRevision:          checkpoint.JournalRevision,
		Assignment:                          assignment,
		Request:                             request,
	}
	canonicalDigest, err := NewRuntimeDigest(RuntimeCommandFingerprint.Compute(command))
	if err != nil {
		return nil, err
	}
	command.CanonicalDigest = canonicalDigest
	return command, nil
}

// RuntimeCommandFingerprint ports the internal fingerprint static class.
var RuntimeCommandFingerprint runtimeCommandFingerprint

type runtimeCommandFingerprint struct{}

func (runtimeCommandFingerprint) Compute(command *RuntimeCommandV1) string {
	assignment := command.Assignment
	values := []string{
		"runtime-command-v1",
		strconv.Itoa(command.SchemaVersion),
		command.AcceptedOperationId,
		command.AcceptedIdempotencyKey,
		command.AcceptedCell.Value,
		strconv.FormatUint(command.AcceptedGeneration.Value, 10),
		command.AcceptedGlobalPlanDigest.Sha256,
		command.AcceptedHandoffDigest.Sha256,
		command.AcceptedPayloadDigest.Sha256,
		strconv.FormatUint(command.AcceptedWriterEpoch.Value, 10),
		strconv.FormatInt(command.AcceptedProtocolVersion, 10),
		strconv.FormatInt(command.AcceptedDeliveryAttempt, 10),
		strconv.FormatInt(dotNetTimestampTicks(command.AcceptedIssuedAt), 10),
		strconv.FormatInt(dotNetTimestampTicks(command.AcceptedExpiresAt), 10),
		strconv.FormatInt(dotNetTimestampTicks(command.AcceptedAt), 10),
		strconv.FormatUint(command.AcceptanceStreamSequence, 10),
		command.AcceptanceSignatureDigest.Sha256,
		strconv.FormatUint(command.AcceptanceJournalRevision, 10),
		command.ConvergenceIntentWorkloadId,
		strconv.FormatInt(command.ConvergenceIntentGeneration, 10),
		command.ConvergenceIntentWorkloadDigest.Sha256,
		command.PreviousConvergenceCheckpointDigest.Sha256,
		command.ConvergenceCheckpointDigest.Sha256,
		strconv.FormatInt(command.ConvergenceCheckpointSequence, 10),
		strconv.FormatUint(command.ConvergenceJournalRevision, 10),
		assignment.Cell.Value,
		assignment.WorkloadId.Value,
		assignment.AllocationId.Value,
		assignment.Node.Value,
		strconv.FormatUint(assignment.AssignmentGeneration.Value, 10),
		strconv.FormatUint(assignment.WorkloadGeneration.Value, 10),
		strconv.FormatUint(assignment.WriterEpoch.Value, 10),
		strconv.FormatUint(assignment.AcceptedGeneration.Value, 10),
		strconv.Itoa(int(assignment.Role)),
		strconv.Itoa(int(assignment.Driver)),
		strconv.Itoa(int(assignment.Architecture)),
		assignment.ArtifactDigest.Value,
		strconv.FormatInt(assignment.Resources.MemoryMaxBytes, 10),
		strconv.Itoa(assignment.Resources.TasksMax),
		strconv.Itoa(assignment.Resources.CpuQuotaPercent),
		strconv.Itoa(assignment.Resources.CpuWeight),
		strconv.Itoa(assignment.Resources.IoWeight),
		strconv.Itoa(assignment.Resources.Nice),
		assignment.ConfigId.Value,
		assignment.ExpectedPlanFingerprint.Value,
		command.Request.OperationKey.Value,
		command.Request.PlanFingerprint.Value,
		command.Request.AcceptedConvergenceDigest.Sha256,
		strconv.Itoa(int(command.Request.Action)),
		strconv.FormatUint(command.Request.WriterEpoch.Value, 10),
		command.Request.AuthorizationEvidenceDigest.Sha256,
		command.Request.DeadlineEvidence.Digest.Sha256,
		strconv.FormatUint(command.Request.DeadlineEvidence.Watermark, 10),
		strconv.FormatInt(dotNetTimestampTicks(assignment.Authorization.ExpiresAt), 10),
	}
	// The C# Add helper prefixes each list with its item count.
	values = append(values, strconv.Itoa(len(assignment.SecretVersions)))
	for _, value := range assignment.SecretVersions {
		values = append(values, value.Value)
	}
	values = append(values, strconv.Itoa(len(assignment.Volumes)))
	for _, value := range assignment.Volumes {
		values = append(values, value.VolumeId.Value+":"+strconv.Itoa(int(value.Retention)))
	}
	values = append(values, strconv.Itoa(len(assignment.Ports)))
	for _, value := range assignment.Ports {
		values = append(values, strconv.FormatUint(uint64(value.Value), 10))
	}
	return fingerprintCanonicalHash(values)
}
