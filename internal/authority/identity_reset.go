package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
)

const identityResetDomain = "terrascale.authority.identity-reset"

type IdentityResetAction string

const (
	IdentityResetDeleteKV       IdentityResetAction = "delete"
	IdentityResetReplaceKV      IdentityResetAction = "replace-kv"
	IdentityResetAppendHostHead IdentityResetAction = "append-host-head"
	maxIdentityResetBytes                           = 512 << 10
	maxIdentityResetRecords                         = 4096
)

var identityResetPolicy = trust.Policy{MaxLifetime: time.Hour}

// IdentityReset replaces the current lease without interpreting obsolete
// identity bytes. The root binds their exact digest and the observed log floor.
type IdentityReset struct {
	Version             int                       `json:"version"`
	OperationID         string                    `json:"operation_id"`
	DeploymentID        string                    `json:"deployment_id"`
	ClusterID           string                    `json:"cluster_id"`
	Scope               string                    `json:"scope"`
	Environment         string                    `json:"environment"`
	CheckpointSHA256    string                    `json:"checkpoint_sha256"`
	HostStatePlanSHA256 string                    `json:"host_state_plan_sha256"`
	LastSequence        uint64                    `json:"last_sequence"`
	PreviousSequence    uint64                    `json:"previous_sequence"`
	PreviousSHA256      string                    `json:"previous_sha256"`
	EpochFloor          uint64                    `json:"epoch_floor"`
	Epoch               uint64                    `json:"epoch"`
	GlobalLease         *IdentityResetGlobalLease `json:"global_lease,omitempty"`
	Records             []IdentityResetRecord     `json:"records"`
}

// IdentityResetRecord root-pins a closed typed destination and its opaque
// predecessor. Delete requires this operation's tombstone, never absence.
type IdentityResetRecord struct {
	Action            IdentityResetAction `json:"action"`
	Bucket            string              `json:"bucket"`
	Key               string              `json:"key"`
	PreviousRevision  uint64              `json:"previous_revision"`
	PreviousSHA256    string              `json:"previous_sha256"`
	PreviousOperation string              `json:"previous_operation,omitempty"`
	SHA256            string              `json:"sha256"`
}

// IdentityResetTarget comes from verified replacement acceptance, independently
// of the reset envelope. Replicas is the existing stream's required quorum.
type IdentityResetTarget struct {
	OperationID         string
	DeploymentID        string
	ClusterID           string
	Scope               string
	Environment         string
	CheckpointSHA256    string
	HostStatePlanSHA256 string
	Replicas            int
}

func (reset IdentityReset) Validate() error {
	if reset.Version != 1 || !entityid.Valid(reset.OperationID) || !entityid.Valid(reset.DeploymentID) ||
		!entityid.Valid(reset.ClusterID) || !natsToken.MatchString(reset.Scope) ||
		reset.Environment != "production" && reset.Environment != "canary" ||
		!validTerminalDigest(reset.CheckpointSHA256) || !validTerminalDigest(reset.HostStatePlanSHA256) || !validTerminalDigest(reset.PreviousSHA256) ||
		reset.PreviousSequence == 0 || reset.PreviousSequence > reset.LastSequence || reset.LastSequence == ^uint64(0) ||
		reset.EpochFloor == 0 || reset.Epoch <= reset.EpochFloor || reset.Epoch == ^uint64(0) || len(reset.Records) < 3 || len(reset.Records) > maxIdentityResetRecords {
		return errors.New("identity reset has invalid scope, predecessor or fencing floor")
	}
	if reset.GlobalLease != nil {
		if err := reset.GlobalLease.validate(reset); err != nil {
			return err
		}
	}
	keys := [3][2]string{{"TS_SERVICE_SET", "current"}, {"TS_TRUST_ROOTS", "chain"}, {"TS_TRUST_ROOTS", "material-generations"}}
	for index, record := range reset.Records {
		if record.PreviousRevision == ^uint64(0) || record.PreviousRevision == 0 && record.PreviousSHA256 != "" ||
			record.PreviousRevision != 0 && !validTerminalDigest(record.PreviousSHA256) ||
			record.PreviousOperation != "" && (record.Action == IdentityResetAppendHostHead || record.PreviousRevision == 0 ||
				record.PreviousSHA256 != resetDigest(nil) || record.PreviousOperation != "DEL" && record.PreviousOperation != "PURGE") {
			return errors.New("identity reset has invalid record predecessor pins")
		}
		if index < 3 {
			if record.Bucket == keys[index][0] && record.Key == keys[index][1] && record.Action == IdentityResetReplaceKV && validTerminalDigest(record.SHA256) {
				continue
			}
			return errors.New("identity reset must pin the exact spec, roots and material replacements in order")
		}
		if !allowedIdentityHostRecord(reset.Scope, record) || len(record.Key) > 512 ||
			record.Bucket == ControlStreamName && record.PreviousRevision > reset.LastSequence ||
			index > 3 && reset.Records[index-1].Bucket+"/"+reset.Records[index-1].Key >= record.Bucket+"/"+record.Key ||
			record.Action == IdentityResetDeleteKV && record.SHA256 != "" ||
			record.Action != IdentityResetDeleteKV && !validTerminalDigest(record.SHA256) {
			return errors.New("identity reset host records must be typed, scoped, sorted and exactly pinned")
		}
	}
	return nil
}

func allowedIdentityHostRecord(scope string, record IdentityResetRecord) bool {
	switch record.Bucket {
	case ControlStreamName:
		if record.Action != IdentityResetAppendHostHead {
			return false
		}
		prefix := controlSubjectRoot + "." + scope + ".host."
		tail, ok := strings.CutPrefix(record.Key, prefix)
		kind, key, found := strings.Cut(tail, ".")
		return ok && found && (HostMutationKind(kind) == MutationRegistration || HostMutationKind(kind) == MutationDesired || HostMutationKind(kind) == MutationRetirement) &&
			strings.HasPrefix(key, scope+".") && validateMutationKey(HostMutationKind(kind), key) == nil
	case "TS_HOST_ENROLLMENT":
		return record.Action == IdentityResetDeleteKV && validTerminalDigest(record.Key) || record.Action == IdentityResetReplaceKV && entityid.Valid(record.Key)
	case "TS_HOST_STATE":
		if record.Action == IdentityResetReplaceKV {
			return entityid.Valid(record.Key)
		}
		if record.Action != IdentityResetDeleteKV {
			return false
		}
		parts := strings.Split(record.Key, ".")
		if len(parts) < 2 || parts[1] != scope {
			return false
		}
		switch parts[0] {
		case "retirement-cutover":
			return len(parts) == 2
		case "session", "retired", "retirement-quarantine":
			return len(parts) == 3 && natsToken.MatchString(parts[2])
		case "cycle", "report", "desired":
			return len(parts) == 4 && natsToken.MatchString(parts[2]) && natsToken.MatchString(parts[3])
		case "terrabase-format":
			return len(parts) == 4 && natsToken.MatchString(parts[2]) && validTerminalDigest(parts[3])
		}
	}
	return false
}

func (reset IdentityReset) trustScope() trust.Scope {
	return trust.Scope{Domain: identityResetDomain, DeploymentID: reset.DeploymentID, Cell: reset.Scope,
		Environment: reset.Environment, Role: "authority", Slot: "identity-reset"}
}

func SignIdentityReset(reset IdentityReset, issuedAt, expiresAt time.Time, key ed25519.PrivateKey) (trust.Envelope, error) {
	if err := reset.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if expiresAt.Sub(issuedAt) > identityResetPolicy.MaxLifetime {
		return trust.Envelope{}, errors.New("identity reset authority exceeds one hour")
	}
	payload, err := trust.EncodePayload(reset)
	if err != nil {
		return trust.Envelope{}, err
	}
	if len(payload) > maxIdentityResetBytes {
		return trust.Envelope{}, errors.New("identity reset exceeds bounded root pin payload")
	}
	return trust.Sign(payload, reset.trustScope(), issuedAt, expiresAt, key)
}

func VerifyIdentityReset(envelope trust.Envelope, roots trust.Keyring, target IdentityResetTarget, now time.Time) (IdentityReset, error) {
	if target.Replicas < 1 || target.Replicas > 5 || target.Replicas%2 == 0 {
		return IdentityReset{}, errors.New("identity reset requires an existing odd replica quorum")
	}
	expected := IdentityReset{DeploymentID: target.DeploymentID, Scope: target.Scope, Environment: target.Environment}
	payload, err := trust.VerifyCurrent(envelope, expected.trustScope(), roots, now, identityResetPolicy)
	if err != nil {
		return IdentityReset{}, fmt.Errorf("verify root-signed identity reset: %w", err)
	}
	var reset IdentityReset
	if err := protocol.DecodeStrict(payload, &reset, maxIdentityResetBytes); err != nil {
		return IdentityReset{}, err
	}
	if err := reset.Validate(); err != nil {
		return IdentityReset{}, err
	}
	canonical, err := trust.EncodePayload(reset)
	if err != nil || !bytes.Equal(payload, canonical) {
		return IdentityReset{}, errors.New("identity reset payload must be canonical v1 JSON")
	}
	if reset.OperationID != target.OperationID || reset.DeploymentID != target.DeploymentID ||
		reset.ClusterID != target.ClusterID || reset.Scope != target.Scope || reset.Environment != target.Environment ||
		reset.CheckpointSHA256 != target.CheckpointSHA256 || reset.HostStatePlanSHA256 != target.HostStatePlanSHA256 {
		return IdentityReset{}, trust.ErrScopeMismatch
	}
	return reset, nil
}

// ResetIdentityLease appends a released barrier to the existing immutable log.
// It never deletes history or starts a runtime. Shared records must be replaced
// and read back before the new deployment starts acquiring normal authority.
// The caller must match the verified host plan and observe real writer shutdown.
func ResetIdentityLease(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget, now time.Time,
) (uint64, error) {
	reset, err := VerifyIdentityReset(envelope, roots, target, now)
	if err != nil {
		return 0, err
	}
	if js == nil {
		return 0, errors.New("identity reset requires JetStream")
	}
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return 0, fmt.Errorf("open existing identity reset stream: %w", err)
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return 0, err
	}
	if err := verifyControlStreamConfig(info.Config, target.Replicas); err != nil {
		return 0, err
	}
	subject := fmt.Sprintf("%s.%s.lease", controlSubjectRoot, reset.Scope)
	barrier, err := identityResetLease(reset, resetDigest(envelope.Payload))
	if err != nil {
		return 0, err
	}
	previous, err := stream.GetLastMsgForSubject(bounded, subject)
	if err != nil {
		return 0, err
	}
	if bytes.Equal(previous.Data, barrier) {
		if previous.Sequence != reset.LastSequence+1 {
			return 0, ErrConflict
		}
		if _, err := verifyCommittedIdentityReset(ctx, js, envelope, roots, target); err != nil {
			return 0, err
		}
		return previous.Sequence, nil
	}
	if info.State.LastSeq != reset.LastSequence || previous.Sequence != reset.PreviousSequence ||
		resetDigest(previous.Data) != reset.PreviousSHA256 {
		return 0, ErrConflict
	}
	if err := verifyIdentityResetGlobalPredecessor(bounded, stream, reset); err != nil {
		return 0, err
	}
	if err := verifyIdentityResetHostInventory(ctx, js, reset, target.Replicas); err != nil {
		return 0, err
	}
	if reset.GlobalLease != nil {
		return publishIdentityResetBatch(ctx, js, stream, reset, envelope, roots, target)
	}
	ack, publishErr := js.PublishMsg(bounded, controlMessage(subject, "lease", reset.OperationID, barrier),
		jetstream.WithExpectLastSequence(reset.LastSequence),
		jetstream.WithExpectLastSequenceForSubject(reset.PreviousSequence, subject))
	if isSequenceConflict(publishErr) {
		return 0, ErrConflict
	}
	// A lost publish reply is resolved only by leader-backed exact readback.
	probe, probeCancel := context.WithTimeout(context.WithoutCancel(ctx), authorityAPITimeout)
	defer probeCancel()
	readInfo, readErr := stream.Info(probe)
	if readErr == nil {
		readErr = verifyControlStreamConfig(readInfo.Config, target.Replicas)
	}
	if readErr != nil {
		return 0, fmt.Errorf("%w: identity reset policy readback: %w", ErrOutcomeUnknown, errors.Join(publishErr, readErr))
	}
	stored, readErr := stream.GetLastMsgForSubject(probe, subject)
	if readErr != nil {
		return 0, fmt.Errorf("%w: identity reset confirmation: %w", ErrOutcomeUnknown, errors.Join(publishErr, readErr))
	}
	if !bytes.Equal(stored.Data, barrier) || publishErr == nil && (ack == nil || stored.Sequence != ack.Sequence) {
		if publishErr != nil && stored.Sequence == reset.PreviousSequence {
			return 0, fmt.Errorf("identity reset publish: %w", publishErr)
		}
		return 0, ErrConflict
	}
	if _, err := verifyCommittedIdentityReset(probe, js, envelope, roots, target); err != nil {
		return 0, fmt.Errorf("%w: committed reset needs current-root recovery authorization: %w", ErrOutcomeUnknown, err)
	}
	return stored.Sequence, nil
}

// IdentityResetFloor is an opaque, leader-observed lease predecessor. The two
// existing CAS checks still decide whether a subsequently signed reset wins.
type IdentityResetFloor struct {
	LastSequence     uint64
	PreviousSequence uint64
	PreviousSHA256   string
}

func ObserveIdentityResetFloor(ctx context.Context, js jetstream.JetStream, scope string, replicas int) (IdentityResetFloor, error) {
	if js == nil || !natsToken.MatchString(scope) || replicas < 1 || replicas > 5 || replicas%2 == 0 {
		return IdentityResetFloor{}, ErrConflict
	}
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return IdentityResetFloor{}, err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return IdentityResetFloor{}, err
	}
	if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
		return IdentityResetFloor{}, err
	}
	previous, err := stream.GetLastMsgForSubject(bounded, fmt.Sprintf("%s.%s.lease", controlSubjectRoot, scope))
	if err != nil {
		return IdentityResetFloor{}, err
	}
	if previous.Sequence == 0 || previous.Sequence > info.State.LastSeq || info.State.LastSeq == ^uint64(0) {
		return IdentityResetFloor{}, ErrConflict
	}
	if lease, err := decodeLease(previous.Data); err == nil && lease.IdentityResetSHA256 != "" {
		return IdentityResetFloor{}, ErrConflict
	}
	return IdentityResetFloor{LastSequence: info.State.LastSeq, PreviousSequence: previous.Sequence,
		PreviousSHA256: resetDigest(previous.Data)}, nil
}

// VerifyIdentityResetUncommittable proves the original global CAS slot is
// permanently occupied by another non-barrier message. Errors prove nothing.
func VerifyIdentityResetUncommittable(ctx context.Context, js jetstream.JetStream, envelope trust.Envelope,
	roots trust.Keyring, target IdentityResetTarget, evidenceTime time.Time,
) error {
	reset, err := VerifyIdentityReset(envelope, roots, target, evidenceTime)
	if err != nil {
		return err
	}
	if js == nil {
		return ErrConflict
	}
	bounded, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	defer cancel()
	stream, err := js.Stream(bounded, ControlStreamName)
	if err != nil {
		return err
	}
	info, err := stream.Info(bounded)
	if err != nil {
		return err
	}
	if err := verifyControlStreamConfig(info.Config, target.Replicas); err != nil {
		return err
	}
	if info.State.LastSeq <= reset.LastSequence {
		return ErrConflict
	}
	occupied, err := stream.GetMsg(bounded, reset.LastSequence+1)
	if err != nil {
		return err
	}
	barrier, err := identityResetLease(reset, resetDigest(envelope.Payload))
	if err != nil {
		return err
	}
	if occupied.Sequence != reset.LastSequence+1 || bytes.Equal(occupied.Data, barrier) {
		return ErrConflict
	}
	if lease, err := decodeLease(occupied.Data); err == nil && lease.IdentityResetSHA256 != "" {
		return ErrConflict
	}
	return nil
}

func resetDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func identityResetLease(reset IdentityReset, pinID string) ([]byte, error) {
	return jsonMarshal(leaseRecord{Version: 1, Scope: reset.Scope, DeploymentID: reset.DeploymentID,
		CandidateID: reset.OperationID, OwnerID: reset.OperationID, TransitionID: reset.OperationID,
		Epoch: reset.Epoch, LeaseDuration: int64(defaultLeaseDuration), Released: true,
		IdentityResetSHA256: pinID})
}
