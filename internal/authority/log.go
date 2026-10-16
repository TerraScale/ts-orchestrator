package authority

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// ControlStreamName is the durable stream that orders lease barriers,
	// operation journal entries, and host registration/desired state.
	ControlStreamName = controlStreamName
)

// controlStreamSubject is the stream filter brokerauth also verifies; both
// read it from protocol so they cannot drift apart.
var controlStreamSubject = protocol.ControlStreamSubject()

type controlRecord struct {
	Version     int              `json:"version"`
	Kind        HostMutationKind `json:"kind"`
	Scope       string           `json:"scope"`
	SubjectKey  string           `json:"subject_key"`
	OperationID string           `json:"operation_id"`
	Epoch       uint64           `json:"epoch"`
	Payload     []byte           `json:"payload"`
}

const (
	authorityAPITimeout                = 5 * time.Second
	createdStreamInfoConvergenceWindow = 5 * time.Second
	createdStreamInfoRetryDelay        = 100 * time.Millisecond
)

func openControlStream(ctx context.Context, js jetstream.JetStream, replicas int) (jetstream.Stream, error) {
	config := jetstream.StreamConfig{
		Name:              ControlStreamName,
		Description:       "Fenced regional authority, operation, and host mutation log",
		Subjects:          []string{controlStreamSubject},
		Retention:         jetstream.LimitsPolicy,
		MaxConsumers:      -1,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: -1,
		Storage:           jetstream.FileStorage,
		Replicas:          replicas,
		DenyDelete:        true,
		DenyPurge:         true,
		// Lease reads must go through the stream leader; direct reads can be stale on followers.
		AllowDirect: false,
		Metadata:    map[string]string{"terrascale-contract": "authority-log-v1"},
	}
	// JetStream only applies its default API timeout when the caller has no
	// deadline. A long startup deadline must not let one lost reply consume the
	// entire attempt.
	createCtx, cancel := context.WithTimeout(ctx, authorityAPITimeout)
	stream, err := js.CreateStream(createCtx, config)
	cancel()
	created := err == nil
	if err != nil {
		if !errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) && !errors.Is(err, jetstream.ErrBucketExists) {
			return nil, fmt.Errorf("create authority stream: %w", err)
		}
		lookupCtx, lookupCancel := context.WithTimeout(ctx, authorityAPITimeout)
		stream, err = js.Stream(lookupCtx, ControlStreamName)
		lookupCancel()
		if err != nil {
			return nil, fmt.Errorf("lookup existing authority stream: %w", err)
		}
	}
	var info *jetstream.StreamInfo
	if created {
		info, err = inspectCreatedControlStream(ctx, stream, createdStreamInfoConvergenceWindow)
	} else {
		infoCtx, infoCancel := context.WithTimeout(ctx, authorityAPITimeout)
		info, err = stream.Info(infoCtx)
		infoCancel()
	}
	if err != nil {
		return nil, fmt.Errorf("inspect authority stream: %w", err)
	}
	if info == nil {
		return nil, errors.New("authority stream info is missing")
	}
	if err := verifyControlStreamConfig(info.Config, replicas); err != nil {
		return nil, err
	}
	return stream, nil
}

// A new R3 stream may be visible to CreateStream before its metadata leader
// serves Info. Retry only the exact stream-not-found API response at this one
// post-create boundary, within both the caller deadline and a short local cap.
func inspectCreatedControlStream(ctx context.Context, stream jetstream.Stream,
	convergenceWindow time.Duration,
) (*jetstream.StreamInfo, error) {
	windowCtx, cancel := context.WithTimeout(ctx, convergenceWindow)
	defer cancel()
	for {
		infoCtx, infoCancel := context.WithTimeout(windowCtx, authorityAPITimeout)
		info, err := stream.Info(infoCtx)
		infoCancel()
		if err == nil {
			return info, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		apiErr, ok := errors.AsType[*jetstream.APIError](err)
		if !ok || apiErr.Code != 404 || apiErr.ErrorCode != jetstream.JSErrCodeStreamNotFound {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-windowCtx.Done():
			return nil, err
		case <-time.After(createdStreamInfoRetryDelay):
		}
	}
}

func verifyControlStreamConfig(actual jetstream.StreamConfig, replicas int) error {
	if (replicas != 1 && replicas != 3 && replicas != 5) || actual.Name != ControlStreamName ||
		actual.Replicas != replicas || actual.Retention != jetstream.LimitsPolicy ||
		actual.Storage != jetstream.FileStorage || actual.MaxConsumers != -1 ||
		actual.MaxMsgs != -1 || actual.MaxBytes != -1 ||
		actual.MaxMsgsPerSubject != -1 || actual.MaxAge != 0 || actual.Discard != jetstream.DiscardOld ||
		actual.MaxMsgSize > 0 || actual.DiscardNewPerSubject || actual.AllowRollup ||
		actual.AllowDirect || actual.MirrorDirect || actual.NoAck || actual.Sealed ||
		!actual.DenyDelete || !actual.DenyPurge || len(actual.Subjects) != 1 ||
		actual.Subjects[0] != controlStreamSubject || actual.Mirror != nil || len(actual.Sources) != 0 ||
		actual.SubjectTransform != nil || actual.RePublish != nil || actual.AllowMsgTTL ||
		actual.SubjectDeleteMarkerTTL != 0 || actual.AllowMsgSchedules ||
		actual.Metadata["terrascale-contract"] != "authority-log-v1" {
		return errors.New("existing control log has incompatible consistency, durability, or subject configuration")
	}
	return nil
}

// CommitHostMutation appends a registration, retirement or desired record when
// both the global stream sequence and target record sequence still match. The
// lease check and append therefore have one durable order with epoch changes.
func (r *Runtime) CommitHostMutation(
	ctx context.Context,
	expectedEpoch uint64,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	expectedSubjectSequence uint64,
	payload []byte,
) (uint64, error) {
	if err := validateHostMutation(kind, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	return r.commitMutation(ctx, expectedEpoch, kind, subjectKey, operationID, expectedSubjectSequence, payload)
}

func (r *Runtime) CommitHostMutationVerified(
	ctx context.Context,
	expectedEpoch uint64,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	expectedSubjectSequence uint64,
	payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	if err := validateHostMutation(kind, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	if verify == nil {
		return 0, errors.New("verified host mutation requires a verifier")
	}
	return r.commitMutationVerified(ctx, expectedEpoch, kind, subjectKey, operationID,
		expectedSubjectSequence, payload, verify)
}

func (r *Runtime) commitMutation(
	ctx context.Context,
	expectedEpoch uint64,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	expectedSubjectSequence uint64,
	payload []byte,
) (uint64, error) {
	return r.commitMutationVerified(ctx, expectedEpoch, kind, subjectKey, operationID,
		expectedSubjectSequence, payload, nil)
}

func (r *Runtime) commitMutationVerified(
	ctx context.Context,
	expectedEpoch uint64,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	expectedSubjectSequence uint64,
	payload []byte,
	verify func(context.Context) error,
) (uint64, error) {
	if r == nil {
		return 0, ErrNotLeader
	}
	if r.checkClock() != nil {
		return 0, ErrClockUnhealthy
	}
	if err := validateMutation(kind, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Current()
	if !current.CanMutate() || current.Scope != r.config.Scope || current.DeploymentID != r.config.DeploymentID || current.CandidateID != r.config.CandidateID || current.OwnerID != r.ownerID {
		return 0, ErrNotLeader
	}
	if expectedEpoch == 0 || current.Epoch != expectedEpoch {
		return 0, ErrFenced
	}

	subject := mutationSubject(r.config.Scope, kind, subjectKey)
	for range 8 {
		info, err := r.stream.Info(ctx)
		if err != nil {
			return 0, fmt.Errorf("read control log sequence: %w", err)
		}
		if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
			return 0, fmt.Errorf("validate control log consistency: %w", err)
		}
		leaseEntry, err := r.stream.GetLastMsgForSubject(ctx, r.leaseSub)
		if err != nil {
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, DeploymentID: r.config.DeploymentID, CandidateID: r.config.CandidateID, Reason: "lease-unreadable"})
			return 0, err
		}
		if leaseEntry.Sequence > info.State.LastSeq {
			continue
		}
		lease, err := decodeLease(leaseEntry.Data)
		if err != nil {
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, DeploymentID: r.config.DeploymentID, CandidateID: r.config.CandidateID, Reason: "lease-corrupt"})
			return 0, ErrLeaseCorrupt
		}
		if lease.Scope != r.config.Scope || lease.DeploymentID != r.config.DeploymentID || lease.CandidateID != r.config.CandidateID || lease.OwnerID != r.ownerID || lease.Epoch != expectedEpoch || lease.Released ||
			!time.Now().Before(leaseEntry.Time.Add(time.Duration(lease.LeaseDuration))) {
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, DeploymentID: lease.DeploymentID, CandidateID: lease.CandidateID, Epoch: lease.Epoch, Revision: leaseEntry.Sequence, ObservedAt: time.Now(), Reason: "lease-fenced"})
			return 0, ErrFenced
		}

		existing, err := r.stream.GetLastMsgForSubject(ctx, subject)
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			existing = nil
		} else if err != nil {
			return 0, fmt.Errorf("read prior host mutation: %w", err)
		}
		if existing != nil && existing.Sequence > info.State.LastSeq {
			continue
		}
		if existing != nil {
			prior, decodeErr := decodeControlRecord(existing.Data)
			if decodeErr != nil {
				return 0, fmt.Errorf("decode prior host mutation: %w", decodeErr)
			}
			if prior.OperationID == operationID {
				if prior.Kind == kind && prior.SubjectKey == subjectKey && prior.Epoch == expectedEpoch && bytes.Equal(prior.Payload, payload) {
					return existing.Sequence, nil
				}
				return 0, ErrOperationConflict
			}
			if existing.Sequence != expectedSubjectSequence {
				return 0, ErrConflict
			}
		} else if expectedSubjectSequence != 0 {
			return 0, ErrConflict
		}
		if verify != nil {
			if err := verify(ctx); err != nil {
				return 0, err
			}
			if !time.Now().Before(leaseEntry.Time.Add(time.Duration(lease.LeaseDuration))) {
				return 0, ErrFenced
			}
		}

		record := controlRecord{
			Version: 1, Kind: kind, Scope: r.config.Scope, SubjectKey: subjectKey,
			OperationID: operationID, Epoch: expectedEpoch, Payload: bytes.Clone(payload),
		}
		data, err := json.Marshal(record)
		if err != nil {
			return 0, err
		}
		msg := controlMessage(subject, string(kind), operationID, data)
		ack, err := r.js.PublishMsg(ctx, msg,
			jetstream.WithExpectLastSequence(info.State.LastSeq),
			jetstream.WithExpectLastSequenceForSubject(expectedSubjectSequence, subject),
		)
		if err == nil {
			return ack.Sequence, nil
		}
		if isSequenceConflict(err) {
			latest, readErr := r.stream.GetLastMsgForSubject(ctx, subject)
			if readErr == nil {
				prior, decodeErr := decodeControlRecord(latest.Data)
				if decodeErr == nil && prior.OperationID == operationID {
					if prior.Kind == kind && prior.SubjectKey == subjectKey && prior.Epoch == expectedEpoch && bytes.Equal(prior.Payload, payload) {
						return latest.Sequence, nil
					}
					return 0, ErrOperationConflict
				}
				if latest.Sequence != expectedSubjectSequence {
					return 0, ErrConflict
				}
			}
			continue
		}
		return r.resolveUnknownMutation(ctx, subject, kind, subjectKey, operationID, expectedEpoch, payload, err)
	}
	return 0, ErrConflict
}

// ReadHostMutation reads the current committed host record.
func (r *Runtime) ReadHostMutation(ctx context.Context, kind HostMutationKind, subjectKey string) (LogEntry, error) {
	if r == nil {
		return LogEntry{}, ErrNotFound
	}
	if err := validateMutationKey(kind, subjectKey); err != nil {
		return LogEntry{}, err
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readMutation(ctx, r.readStream, r.config.Scope, kind, subjectKey)
}

func readMutation(ctx context.Context, stream jetstream.Stream, scope string, kind HostMutationKind, subjectKey string) (LogEntry, error) {
	subject := mutationSubject(scope, kind, subjectKey)
	entry, err := stream.GetLastMsgForSubject(ctx, subject)
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return LogEntry{}, ErrNotFound
	}
	if err != nil {
		return LogEntry{}, err
	}
	record, err := decodeControlRecord(entry.Data)
	if err != nil || record.Scope != scope || record.Kind != kind || record.SubjectKey != subjectKey || record.Epoch == 0 {
		return LogEntry{}, errors.New("host control log entry is invalid")
	}
	return LogEntry{
		Kind: record.Kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID,
		Epoch: record.Epoch, Sequence: entry.Sequence, CreatedAt: entry.Time, Payload: bytes.Clone(record.Payload),
	}, nil
}

func (r *Runtime) CommitPlacementIntent(
	ctx context.Context,
	expectedEpoch uint64,
	databaseID string,
	partitionID string,
	operationID string,
	expectedSequence uint64,
	payload []byte,
) (uint64, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if err := validateMutation(MutationPlacementIntent, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, expectedEpoch, MutationPlacementIntent,
		subjectKey, operationID, expectedSequence, payload, func(check context.Context) error {
			return r.requireNoActiveBackup(check, databaseID, partitionID)
		})
}

// ConfirmActivePlacementIntent linearizes an identical admission with the
// terminal marker. Guard appends a global-sequence lease barrier, then the
// final leader-backed marker read rejects a marker committed by another leader
// before confirmation. A later marker overlaps this read-only admission.
func (r *Runtime) ConfirmActivePlacementIntent(ctx context.Context, epoch uint64,
	databaseID, partitionID string, payload []byte,
) (uint64, error) {
	release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	current, err := r.ReadPlacementIntent(ctx, databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(current.Payload, payload) {
		return 0, ErrConflict
	}
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	return current.Sequence, nil
}

func (r *Runtime) workloadGate(scope WorkloadScope) *sync.RWMutex {
	r.terminalMu.Lock()
	defer r.terminalMu.Unlock()
	if r.terminalGates == nil {
		r.terminalGates = make(map[WorkloadScope]*sync.RWMutex)
	}
	gate := r.terminalGates[scope]
	if gate == nil {
		gate = new(sync.RWMutex)
		r.terminalGates[scope] = gate
	}
	return gate
}

func (r *Runtime) beginWorkloadGate(ctx context.Context, scope WorkloadScope) (func(), error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrFenced
	}
	if _, err := placementIntentSubjectKey(scope.DatabaseID, scope.PartitionID); err != nil {
		return nil, err
	}
	gate := r.workloadGate(scope)
	gate.RLock()
	if err := ctx.Err(); err != nil {
		gate.RUnlock()
		return nil, err
	}
	return sync.OnceFunc(gate.RUnlock), nil
}

func (r *Runtime) requireNoTerminalIntent(ctx context.Context, databaseID, partitionID string) error {
	_, err := r.ReadTerminalIntent(ctx, databaseID, partitionID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err == nil {
		return ErrFenced
	}
	return err
}

type workloadEffectContextKey struct{}

type workloadEffectContext struct {
	mu     sync.Mutex
	active map[WorkloadScope]*heldWorkloadEffect
}

type heldWorkloadEffect struct {
	runtime *Runtime
	epoch   uint64
	gate    *sync.RWMutex
	refs    int
}

// WithActiveWorkloadEffectContext lets nested components join one scope gate
// for the same leader epoch. The derived context must be passed to every
// nested call; a caller must still release each successful Begin call.
func WithActiveWorkloadEffectContext(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	if ctx.Value(workloadEffectContextKey{}) != nil {
		return ctx
	}
	return context.WithValue(ctx, workloadEffectContextKey{}, &workloadEffectContext{
		active: make(map[WorkloadScope]*heldWorkloadEffect),
	})
}

func (state *workloadEffectContext) release(scope WorkloadScope) {
	state.mu.Lock()
	defer state.mu.Unlock()
	held := state.active[scope]
	if held == nil {
		return
	}
	held.refs--
	if held.refs == 0 {
		delete(state.active, scope)
		held.gate.RUnlock()
	}
}

// BeginActiveWorkloadEffect guards an active workload effect until its journal,
// provider call, and readback are settled. Callers must invoke the returned
// release on every path. A committed terminal marker permanently fences it.
func (r *Runtime) BeginActiveWorkloadEffect(ctx context.Context, epoch uint64, scope WorkloadScope) (func(), error) {
	if ctx != nil {
		if state, ok := ctx.Value(workloadEffectContextKey{}).(*workloadEffectContext); ok {
			state.mu.Lock()
			if held := state.active[scope]; held != nil {
				if held.runtime != r || held.epoch != epoch {
					state.mu.Unlock()
					return nil, ErrFenced
				}
				held.refs++
				state.mu.Unlock()
				release := sync.OnceFunc(func() { state.release(scope) })
				if err := r.Guard(ctx, epoch); err != nil {
					release()
					return nil, err
				}
				return release, nil
			}
			gate := r.workloadGate(scope)
			gate.RLock()
			if err := r.requireNoTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
				gate.RUnlock()
				state.mu.Unlock()
				return nil, err
			}
			if err := r.Guard(ctx, epoch); err != nil {
				gate.RUnlock()
				state.mu.Unlock()
				return nil, err
			}
			state.active[scope] = &heldWorkloadEffect{runtime: r, epoch: epoch, gate: gate, refs: 1}
			state.mu.Unlock()
			return sync.OnceFunc(func() { state.release(scope) }), nil
		}
	}
	release, err := r.beginWorkloadGate(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err := r.requireNoTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
		release()
		return nil, err
	}
	if err := r.Guard(ctx, epoch); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// CommitTerminalIntent writes one immutable terminal marker under an exclusive
// scope gate. verifySettled must only read exact journal and OCI inventory; it
// must never issue a create, attach, or recovery mutation.
func (r *Runtime) CommitTerminalIntent(ctx context.Context, epoch uint64, scope WorkloadScope,
	operationID string, payload []byte, verifySettled func(context.Context) error,
) (uint64, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || verifySettled == nil {
		return 0, ErrFenced
	}
	subjectKey, err := placementIntentSubjectKey(scope.DatabaseID, scope.PartitionID)
	if err != nil {
		return 0, err
	}
	intent, err := decodeTerminalIntent(payload)
	if err != nil || intent.DatabaseID != scope.DatabaseID || intent.PartitionID != scope.PartitionID ||
		intent.Cell != r.config.Scope || intent.OperationID != operationID {
		return 0, errors.New("terminal marker payload differs from its authority scope")
	}
	gate := r.workloadGate(scope)
	gate.Lock()
	defer gate.Unlock()
	prior, err := r.ReadTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID)
	if err == nil {
		if prior.OperationID == operationID && bytes.Equal(prior.Payload, payload) {
			return prior.Sequence, nil
		}
		return 0, ErrOperationConflict
	}
	if !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	if err := r.requireNoActiveBackup(ctx, scope.DatabaseID, scope.PartitionID); err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, epoch, MutationTerminalIntent, subjectKey, operationID,
		0, payload, func(check context.Context) error {
			if err := r.requireNoRuntimeEffects(check, scope); err != nil {
				return err
			}
			if err := r.requireNoActiveBackup(check, scope.DatabaseID, scope.PartitionID); err != nil {
				return err
			}
			return verifySettled(check)
		})
}

func decodeTerminalIntent(payload []byte) (TerminalIntent, error) {
	var intent TerminalIntent
	if len(payload) == 0 || len(payload) > maxControlPayload {
		return TerminalIntent{}, errors.New("terminal marker payload size is invalid")
	}
	if err := json.Unmarshal(payload, &intent, json.RejectUnknownMembers(true)); err != nil {
		return TerminalIntent{}, err
	}
	canonical, err := json.Marshal(intent, json.Deterministic(true))
	if err != nil || !bytes.Equal(payload, canonical) || intent.Validate() != nil {
		return TerminalIntent{}, errors.New("terminal marker payload is not canonical or valid")
	}
	return intent, nil
}

// ReadTerminalIntent returns ErrNotFound only when no terminal marker exists.
// Every malformed or unreadable marker is a hold, never a missing marker.
func (r *Runtime) ReadTerminalIntent(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if r == nil {
		return LogEntry{}, ErrFenced
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	entry, err := readMutation(ctx, r.readStream, r.config.Scope, MutationTerminalIntent, subjectKey)
	if err != nil {
		return LogEntry{}, err
	}
	intent, err := decodeTerminalIntent(entry.Payload)
	if err != nil || intent.Cell != r.config.Scope || intent.DatabaseID != databaseID ||
		intent.PartitionID != partitionID || intent.OperationID != entry.OperationID {
		return LogEntry{}, errors.New("terminal control log identity is invalid")
	}
	return entry, nil
}

type enrollmentEffectPayload struct {
	InstanceID string `json:"instance_id"`
	Phase      string `json:"phase"`
}

func enrollmentEffectSubjectKey(scope WorkloadScope, effectID string) (string, error) {
	if _, err := placementIntentSubjectKey(scope.DatabaseID, scope.PartitionID); err != nil {
		return "", err
	}
	if len(effectID) > 55 || !entityid.Valid(effectID) {
		return "", errors.New("enrollment effect ID is invalid")
	}
	return scope.DatabaseID + "." + scope.PartitionID + "." + effectID, nil
}

func enrollmentEffectBytes(instanceID, phase string) ([]byte, error) {
	if !strings.HasPrefix(instanceID, "ocid1.instance.") || len(instanceID) > 255 ||
		strings.ContainsAny(instanceID, " \t\r\n") || phase != "pending" && phase != "settled" {
		return nil, errors.New("enrollment effect has invalid instance or phase")
	}
	return json.Marshal(enrollmentEffectPayload{InstanceID: instanceID, Phase: phase}, json.Deterministic(true))
}

func decodeEnrollmentEffect(entry LogEntry, scope WorkloadScope, effectID string) (EnrollmentEffect, error) {
	subjectKey, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil || entry.Kind != MutationEnrollmentEffect || entry.SubjectKey != subjectKey ||
		entry.Epoch == 0 || entry.Sequence == 0 ||
		entry.OperationID != effectID && entry.OperationID != entityid.Derive("enrollment-settled", effectID) {
		return EnrollmentEffect{}, errors.New("enrollment effect log identity is invalid")
	}
	var payload enrollmentEffectPayload
	if err := json.Unmarshal(entry.Payload, &payload, json.RejectUnknownMembers(true)); err != nil {
		return EnrollmentEffect{}, err
	}
	canonical, err := enrollmentEffectBytes(payload.InstanceID, payload.Phase)
	if err != nil || !bytes.Equal(canonical, entry.Payload) ||
		payload.Phase == "pending" && entry.OperationID != effectID ||
		payload.Phase == "settled" && entry.OperationID != entityid.Derive("enrollment-settled", effectID) {
		return EnrollmentEffect{}, errors.New("enrollment effect log payload is invalid")
	}
	return EnrollmentEffect{EffectID: effectID, InstanceID: payload.InstanceID,
		Epoch: entry.Epoch, Sequence: entry.Sequence, Phase: payload.Phase}, nil
}

// BeginEnrollmentEffect records a possible grant KV mutation in R3 before the
// caller's final lease guard and KV call. Every CAS retry rechecks the terminal
// marker, so a later marker cannot be followed by a new pending grant effect.
func (r *Runtime) BeginEnrollmentEffect(ctx context.Context, epoch uint64, scope WorkloadScope,
	effectID, instanceID string,
) (uint64, error) {
	subjectKey, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil {
		return 0, err
	}
	payload, err := enrollmentEffectBytes(instanceID, "pending")
	if err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, epoch, MutationEnrollmentEffect, subjectKey, effectID, 0, payload,
		func(ctx context.Context) error {
			return r.requireNoTerminalIntent(ctx, scope.DatabaseID, scope.PartitionID)
		})
}

// SettleEnrollmentEffect follows exact grant readback. A failed or unknown KV
// outcome must remain pending; terminal admission will hold across epochs.
func (r *Runtime) SettleEnrollmentEffect(ctx context.Context, epoch uint64, scope WorkloadScope,
	effectID, instanceID string, expectedSequence uint64,
) (uint64, error) {
	subjectKey, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil || expectedSequence == 0 {
		return 0, errors.New("enrollment effect settlement has no pending sequence")
	}
	prior, err := r.ReadHostMutation(ctx, MutationEnrollmentEffect, subjectKey)
	if err != nil {
		return 0, err
	}
	decoded, err := decodeEnrollmentEffect(prior, scope, effectID)
	if err != nil || decoded.InstanceID != instanceID || decoded.Epoch != epoch {
		return 0, errors.New("enrollment effect settlement differs from pending identity")
	}
	if decoded.Phase == "settled" {
		return decoded.Sequence, nil
	}
	if decoded.Sequence != expectedSequence {
		return 0, ErrConflict
	}
	payload, err := enrollmentEffectBytes(instanceID, "settled")
	if err != nil {
		return 0, err
	}
	return r.commitMutation(ctx, epoch, MutationEnrollmentEffect, subjectKey,
		entityid.Derive("enrollment-settled", effectID), expectedSequence, payload)
}

// SettleFencedEnrollmentEffect recovers a pending effect from a lost leader
// only after a current-leader verifier reads an exact disabled grant fence.
// The verifier runs before each global-sequence CAS attempt. GrantStore's
// per-key Create/Update ordering must make delayed old writes fail after that
// fence; absence by itself is never sufficient proof.
func (r *Runtime) SettleFencedEnrollmentEffect(ctx context.Context, currentEpoch uint64,
	scope WorkloadScope, effectID, instanceID string, expectedSequence uint64,
	verifyFence func(context.Context) error,
) (uint64, error) {
	subjectKey, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil || expectedSequence == 0 || verifyFence == nil {
		return 0, errors.New("prior-epoch enrollment settlement lacks an exact fence verifier")
	}
	prior, err := r.ReadHostMutation(ctx, MutationEnrollmentEffect, subjectKey)
	if err != nil {
		return 0, err
	}
	decoded, err := decodeEnrollmentEffect(prior, scope, effectID)
	if err != nil || decoded.Phase != "pending" || decoded.InstanceID != instanceID ||
		decoded.Epoch >= currentEpoch || decoded.Sequence != expectedSequence {
		return 0, errors.New("prior-epoch enrollment effect identity or sequence differs")
	}
	if err := r.Guard(ctx, currentEpoch); err != nil {
		return 0, err
	}
	payload, err := enrollmentEffectBytes(instanceID, "settled")
	if err != nil {
		return 0, err
	}
	return r.commitMutationVerified(ctx, currentEpoch, MutationEnrollmentEffect, subjectKey,
		entityid.Derive("enrollment-settled", effectID), expectedSequence, payload, verifyFence)
}

// ListPendingEnrollmentEffects reads all effects for one workload, including
// records from a previous epoch. A malformed or unreadable effect is a hold.
func (r *Runtime) ListPendingEnrollmentEffects(ctx context.Context, scope WorkloadScope) ([]EnrollmentEffect, error) {
	if r == nil || r.readStream == nil {
		return nil, ErrFenced
	}
	if _, err := placementIntentSubjectKey(scope.DatabaseID, scope.PartitionID); err != nil {
		return nil, err
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	prefix := fmt.Sprintf("%s.%s.placement.enrollment.%s.%s.", controlSubjectRoot,
		r.config.Scope, scope.DatabaseID, scope.PartitionID)
	info, err := r.readStream.Info(ctx, jetstream.WithSubjectFilter(prefix+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		return nil, err
	}
	// Stream.Info with a subject filter paginates through every matching
	// subject. Settled effects remain in R3 and must not impose a fixed lifetime
	// limit on later terminal admission.
	effectIDs := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		effectID, ok := strings.CutPrefix(subject, prefix)
		if !ok || strings.Contains(effectID, ".") || !entityid.Valid(effectID) {
			return nil, errors.New("enrollment effect subject is invalid")
		}
		effectIDs = append(effectIDs, effectID)
	}
	slices.Sort(effectIDs)
	pending := make([]EnrollmentEffect, 0, len(effectIDs))
	for _, effectID := range effectIDs {
		subjectKey, _ := enrollmentEffectSubjectKey(scope, effectID)
		entry, err := readMutation(ctx, r.readStream, r.config.Scope, MutationEnrollmentEffect, subjectKey)
		if err != nil {
			return nil, err
		}
		effect, err := decodeEnrollmentEffect(entry, scope, effectID)
		if err != nil {
			return nil, err
		}
		if effect.Phase == "pending" {
			pending = append(pending, effect)
		}
	}
	return pending, nil
}

func (r *Runtime) ReadPlacementIntent(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if r == nil {
		return LogEntry{}, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readMutation(ctx, r.readStream, r.config.Scope, MutationPlacementIntent, subjectKey)
}

func (r *Runtime) CommitMaterialReceipt(ctx context.Context, expectedEpoch uint64,
	databaseID, partitionID, operationID string, expectedSequence uint64, payload []byte,
) (uint64, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if err := validateMutation(MutationMaterialReceipt, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	return r.commitMutation(ctx, expectedEpoch, MutationMaterialReceipt, subjectKey, operationID, expectedSequence, payload)
}

func (r *Runtime) ReadMaterialReceipt(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if r == nil {
		return LogEntry{}, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readMutation(ctx, r.readStream, r.config.Scope, MutationMaterialReceipt, subjectKey)
}

func (r *Runtime) CommitClientCredentials(ctx context.Context, epoch uint64,
	databaseID, partitionID, operationID string, expectedSequence uint64, payload []byte,
) (uint64, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return 0, err
	}
	if err := validateMutation(MutationClientCredentials, subjectKey, operationID, payload); err != nil {
		return 0, err
	}
	release, err := r.beginWorkloadGate(ctx, WorkloadScope{DatabaseID: databaseID, PartitionID: partitionID})
	if err != nil {
		return 0, err
	}
	defer release()
	if err := r.requireNoTerminalIntent(ctx, databaseID, partitionID); err != nil {
		return 0, err
	}
	return r.commitMutation(ctx, epoch, MutationClientCredentials, subjectKey, operationID, expectedSequence, payload)
}

func (r *Runtime) ReadClientCredentials(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if r == nil {
		return LogEntry{}, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return readMutation(ctx, r.readStream, r.config.Scope, MutationClientCredentials, subjectKey)
}

// ListPlacementIntents reads the latest admitted record for each database and partition.
// The bound applies to current intent subjects, not retained lease history.
func (r *Runtime) ListPlacementIntents(ctx context.Context) ([]LogEntry, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	return listPlacementIntents(ctx, r.readStream, r.config.Scope)
}

// Reader is a read-only view of a control log. It deliberately implements the
// shared host store interface with writes denied so operator and follower paths
// can read committed host state without starting a lease candidate.
type Reader struct {
	stream jetstream.Stream
	scope  string
	mu     sync.Mutex
}

// OpenReader opens an existing control log without creating it or claiming a
// lease. It is suitable for operator and follower read paths.
func OpenReader(ctx context.Context, js jetstream.JetStream, scope string) (*Reader, error) {
	if js == nil {
		return nil, errors.New("JetStream is required")
	}
	if !natsToken.MatchString(scope) {
		return nil, errors.New("authority scope must be a canonical ULID")
	}
	stream, err := js.Stream(ctx, ControlStreamName)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return nil, err
	}
	return &Reader{stream: stream, scope: scope}, nil
}

func (r *Reader) CommitHostMutation(context.Context, uint64, HostMutationKind, string, string, uint64, []byte) (uint64, error) {
	return 0, ErrNotLeader
}

func (r *Reader) CommitHostMutationVerified(context.Context, uint64, HostMutationKind, string, string, uint64, []byte, func(context.Context) error) (uint64, error) {
	return 0, ErrNotLeader
}

func (r *Reader) ReadHostMutation(ctx context.Context, kind HostMutationKind, subjectKey string) (LogEntry, error) {
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrNotFound
	}
	if err := validateMutationKey(kind, subjectKey); err != nil {
		return LogEntry{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return readMutation(ctx, r.stream, r.scope, kind, subjectKey)
}

func (r *Reader) CommitPlacementIntent(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error) {
	return 0, ErrNotLeader
}

func (r *Reader) ReadTerminalIntent(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrFenced
	}
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := readMutation(ctx, r.stream, r.scope, MutationTerminalIntent, subjectKey)
	if err != nil {
		return LogEntry{}, err
	}
	intent, err := decodeTerminalIntent(entry.Payload)
	if err != nil || intent.Cell != r.scope || intent.DatabaseID != databaseID ||
		intent.PartitionID != partitionID || intent.OperationID != entry.OperationID {
		return LogEntry{}, errors.New("terminal control log identity is invalid")
	}
	return entry, nil
}

func (r *Reader) ReadPlacementIntent(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrNotFound
	}
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return readMutation(ctx, r.stream, r.scope, MutationPlacementIntent, subjectKey)
}

func (r *Reader) CommitMaterialReceipt(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error) {
	return 0, ErrNotLeader
}

func (r *Reader) ReadMaterialReceipt(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrNotFound
	}
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return readMutation(ctx, r.stream, r.scope, MutationMaterialReceipt, subjectKey)
}

func (r *Reader) CommitClientCredentials(context.Context, uint64, string, string, string, uint64, []byte) (uint64, error) {
	return 0, ErrFenced
}

func (r *Reader) ReadClientCredentials(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	subjectKey, err := placementIntentSubjectKey(databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return readMutation(ctx, r.stream, r.scope, MutationClientCredentials, subjectKey)
}

func (r *Reader) ListPlacementIntents(ctx context.Context) ([]LogEntry, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return listPlacementIntents(ctx, r.stream, r.scope)
}

func (r *Reader) ReadManagedUpdate(ctx context.Context, databaseID, partitionID string) (LogEntry, error) {
	if r == nil || r.stream == nil {
		return LogEntry{}, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, err := listManagedUpdateEntries(ctx, r.stream, r.scope, databaseID, partitionID)
	if err != nil {
		return LogEntry{}, err
	}
	if len(entries) == 0 {
		return LogEntry{}, ErrNotFound
	}
	return entries[len(entries)-1], nil
}

func (r *Reader) ReadManagedUpdateOperation(
	ctx context.Context,
	databaseID, partitionID, operationID string,
) ([]LogEntry, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return readManagedUpdateOperation(ctx, r.stream, r.scope,
		databaseID, partitionID, operationID)
}

func (r *Reader) ListManagedUpdates(ctx context.Context, databaseID, partitionID string) ([]LogEntry, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return listManagedUpdateEntries(ctx, r.stream, r.scope, databaseID, partitionID)
}

func listPlacementIntents(ctx context.Context, stream jetstream.Stream, scope string) ([]LogEntry, error) {
	prefix := fmt.Sprintf("%s.%s.placement.intent.", controlSubjectRoot, scope)
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(prefix+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, info.Config.Replicas); err != nil {
		return nil, err
	}
	if len(info.State.Subjects) == 0 {
		return []LogEntry{}, nil
	}
	if len(info.State.Subjects) > maxPlacementIntents {
		return nil, ErrListTooLarge
	}
	subjectKeys := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		subjectKey, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateMutationKey(MutationPlacementIntent, subjectKey) != nil {
			return nil, errors.New("placement log subject is invalid")
		}
		subjectKeys = append(subjectKeys, subjectKey)
	}
	slices.Sort(subjectKeys)
	result := make([]LogEntry, 0, len(subjectKeys))
	for _, subjectKey := range subjectKeys {
		entry, err := stream.GetLastMsgForSubject(ctx, mutationSubject(scope, MutationPlacementIntent, subjectKey))
		if err != nil {
			return nil, fmt.Errorf("read latest placement intent for %s: %w", subjectKey, err)
		}
		record, err := decodeControlRecord(entry.Data)
		if err != nil || record.Scope != scope || record.Kind != MutationPlacementIntent || record.SubjectKey != subjectKey {
			return nil, errors.New("placement log entry is invalid")
		}
		result = append(result, LogEntry{
			Kind: record.Kind, SubjectKey: record.SubjectKey, OperationID: record.OperationID,
			Epoch: record.Epoch, Sequence: entry.Sequence, CreatedAt: entry.Time, Payload: bytes.Clone(record.Payload),
		})
	}
	return result, nil
}

func (r *Runtime) resolveUnknownMutation(
	ctx context.Context,
	subject string,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	epoch uint64,
	payload []byte,
	original error,
) (uint64, error) {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	entry, err := r.stream.GetLastMsgForSubject(probeCtx, subject)
	if err == nil {
		record, decodeErr := decodeControlRecord(entry.Data)
		if decodeErr == nil && record.OperationID == operationID {
			if record.Kind == kind && record.SubjectKey == subjectKey && record.Epoch == epoch && bytes.Equal(record.Payload, payload) {
				return entry.Sequence, nil
			}
			return 0, ErrOperationConflict
		}
	}
	return 0, fmt.Errorf("%w: %v", ErrOutcomeUnknown, original)
}

func controlMessage(subject, kind, operationID string, data []byte) *nats.Msg {
	msg := &nats.Msg{Subject: subject, Data: data, Header: nats.Header{}}
	msg.Header.Set("TerraScale-Control-Kind", kind)
	if operationID != "" {
		msg.Header.Set("TerraScale-Operation-ID", operationID)
	}
	return msg
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func decodeControlRecord(data []byte) (controlRecord, error) {
	var record controlRecord
	if len(data) == 0 || len(data) > maxControlPayload+4096 {
		return record, errors.New("control log record size is invalid")
	}
	if err := json.Unmarshal(data, &record, json.RejectUnknownMembers(true)); err != nil {
		return record, err
	}
	if record.Version != 1 || record.Scope == "" || record.OperationID == "" || record.Epoch == 0 || len(record.Payload) > maxControlPayload {
		return record, errors.New("control log record fields are invalid")
	}
	return record, nil
}

func validateHostMutation(kind HostMutationKind, subjectKey, operationID string, payload []byte) error {
	if kind != MutationRegistration && kind != MutationDesired && kind != MutationRetirement {
		return errors.New("host mutation kind is not allowed")
	}
	return validateMutation(kind, subjectKey, operationID, payload)
}

func validateMutation(kind HostMutationKind, subjectKey, operationID string, payload []byte) error {
	if err := validateMutationKey(kind, subjectKey); err != nil {
		return err
	}
	if !entityid.Valid(operationID) {
		return errors.New("host mutation operation ID must be a canonical ULID")
	}
	if len(payload) == 0 || len(payload) > maxControlPayload {
		return errors.New("host mutation payload size is invalid")
	}
	return nil
}

func validateMutationKey(kind HostMutationKind, subjectKey string) error {
	parts := strings.Split(subjectKey, ".")
	want := 0
	switch kind {
	case MutationRegistration, MutationRetirement:
		want = 2
	case MutationDesired:
		want = 3
	case MutationPlacementIntent:
		want = 2
	case MutationMaterialReceipt:
		want = 2
	case MutationClientCredentials:
		want = 2
	case MutationTerminalIntent:
		want = 2
	case MutationEnrollmentEffect, MutationRuntimeEffect:
		want = 3
	case MutationManagedUpdate:
		want = 4
	case MutationBackupOperation:
		want = 2
	case MutationNetBirdState:
		want = 1
	case MutationFunctionIntent:
		want = 2
	case MutationFunctionGrant:
		want = 1
	default:
		return errors.New("host mutation kind is not allowed")
	}
	if len(parts) != want {
		return errors.New("host mutation subject key has the wrong shape")
	}
	for _, part := range parts {
		if !natsToken.MatchString(part) && !entityid.Valid(part) {
			return errors.New("host mutation subject key contains an invalid token")
		}
	}
	return nil
}

func mutationSubject(scope string, kind HostMutationKind, subjectKey string) string {
	if kind == MutationFunctionIntent || kind == MutationFunctionGrant {
		return fmt.Sprintf("%s.%s.function.%s.%s", controlSubjectRoot, scope, kind, subjectKey)
	}
	if kind == MutationNetBirdState {
		return fmt.Sprintf("%s.%s.netbird.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationPlacementIntent {
		return fmt.Sprintf("%s.%s.placement.intent.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationMaterialReceipt {
		return fmt.Sprintf("%s.%s.placement.material.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationClientCredentials {
		return fmt.Sprintf("%s.%s.placement.credentials.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationTerminalIntent {
		return fmt.Sprintf("%s.%s.placement.terminal.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationEnrollmentEffect {
		return fmt.Sprintf("%s.%s.placement.enrollment.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationRuntimeEffect {
		return fmt.Sprintf("%s.%s.placement.runtime.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationManagedUpdate {
		return fmt.Sprintf("%s.%s.placement.managed-update.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationBackupOperation {
		return fmt.Sprintf("%s.%s.placement.backup.%s", controlSubjectRoot, scope, subjectKey)
	}
	return fmt.Sprintf("%s.%s.host.%s.%s", controlSubjectRoot, scope, kind, subjectKey)
}

func placementIntentSubjectKey(databaseID, partitionID string) (string, error) {
	if !entityid.Valid(databaseID) || !entityid.Valid(partitionID) {
		return "", errors.New("placement intent database and partition IDs must be canonical ULIDs")
	}
	return databaseID + "." + partitionID, nil
}

func decodeLease(data []byte) (leaseRecord, error) {
	var lease leaseRecord
	if len(data) == 0 || len(data) > 4096 {
		return lease, ErrLeaseCorrupt
	}
	if err := json.Unmarshal(data, &lease, json.RejectUnknownMembers(true)); err != nil {
		return lease, err
	}
	if lease.Version != 1 || !natsToken.MatchString(lease.Scope) || !entityid.Valid(lease.DeploymentID) || !entityid.Valid(lease.CandidateID) ||
		!entityid.Valid(lease.OwnerID) || !entityid.Valid(lease.TransitionID) || lease.Epoch == 0 ||
		lease.LeaseDuration < int64(time.Second) || lease.LeaseDuration > int64(5*time.Minute) {
		return lease, ErrLeaseCorrupt
	}
	if lease.IdentityResetSHA256 != "" && (!validTerminalDigest(lease.IdentityResetSHA256) || !lease.Released ||
		lease.CandidateID != lease.OwnerID || lease.CandidateID != lease.TransitionID) {
		return lease, ErrLeaseCorrupt
	}
	return lease, nil
}

func isSequenceConflict(err error) bool {
	apiErr, ok := errors.AsType[*jetstream.APIError](err)
	return ok && (apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
		apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant)
}

var _ HostMutationStore = (*Runtime)(nil)
var _ HostMutationStore = (*Reader)(nil)
var _ PlacementIntentStore = (*Runtime)(nil)
var _ PlacementIntentStore = (*Reader)(nil)
var _ Fencer = (*Runtime)(nil)
