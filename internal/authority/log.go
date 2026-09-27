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

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// ControlStreamName is the durable stream that orders lease barriers,
	// operation journal entries, and host registration/desired state.
	ControlStreamName    = controlStreamName
	controlStreamSubject = "ts.control.*.>"
)

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

// CommitHostMutation appends a registration or desired-state record only when
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

func (r *Runtime) commitMutation(
	ctx context.Context,
	expectedEpoch uint64,
	kind HostMutationKind,
	subjectKey string,
	operationID string,
	expectedSubjectSequence uint64,
	payload []byte,
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
	if !current.CanMutate() || current.CandidateID != r.config.CandidateID || current.OwnerID != r.ownerID {
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
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, Reason: "lease-unreadable"})
			return 0, err
		}
		if leaseEntry.Sequence > info.State.LastSeq {
			continue
		}
		lease, err := decodeLease(leaseEntry.Data)
		if err != nil {
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: r.config.CandidateID, Reason: "lease-corrupt"})
			return 0, ErrLeaseCorrupt
		}
		if lease.CandidateID != r.config.CandidateID || lease.OwnerID != r.ownerID || lease.Epoch != expectedEpoch || lease.Released ||
			!time.Now().Before(leaseEntry.Time.Add(time.Duration(lease.LeaseDuration))) {
			r.publishSnapshot(Snapshot{Scope: r.config.Scope, CandidateID: lease.CandidateID, Epoch: lease.Epoch, Revision: leaseEntry.Sequence, ObservedAt: time.Now(), Reason: "lease-fenced"})
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

// ReadHostMutation reads the current committed registration or desired record.
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
	return r.commitMutation(ctx, expectedEpoch, MutationPlacementIntent, subjectKey, operationID, expectedSequence, payload)
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
		return nil, errors.New("authority scope must be a lowercase NATS token")
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

func (r *Reader) ListPlacementIntents(ctx context.Context) ([]LogEntry, error) {
	if r == nil || r.stream == nil {
		return nil, ErrNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return listPlacementIntents(ctx, r.stream, r.scope)
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
	if kind != MutationRegistration && kind != MutationDesired {
		return errors.New("host mutation kind is not allowed")
	}
	return validateMutation(kind, subjectKey, operationID, payload)
}

func validateMutation(kind HostMutationKind, subjectKey, operationID string, payload []byte) error {
	if err := validateMutationKey(kind, subjectKey); err != nil {
		return err
	}
	if !natsToken.MatchString(operationID) {
		return errors.New("host mutation operation ID must be a lowercase NATS token")
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
	case MutationRegistration:
		want = 2
	case MutationDesired:
		want = 3
	case MutationPlacementIntent:
		want = 2
	case MutationMaterialReceipt:
		want = 2
	default:
		return errors.New("host mutation kind is not allowed")
	}
	if len(parts) != want {
		return errors.New("host mutation subject key has the wrong shape")
	}
	for _, part := range parts {
		if !natsToken.MatchString(part) {
			return errors.New("host mutation subject key contains an invalid token")
		}
	}
	return nil
}

func mutationSubject(scope string, kind HostMutationKind, subjectKey string) string {
	if kind == MutationPlacementIntent {
		return fmt.Sprintf("%s.%s.placement.intent.%s", controlSubjectRoot, scope, subjectKey)
	}
	if kind == MutationMaterialReceipt {
		return fmt.Sprintf("%s.%s.placement.material.%s", controlSubjectRoot, scope, subjectKey)
	}
	return fmt.Sprintf("%s.%s.host.%s.%s", controlSubjectRoot, scope, kind, subjectKey)
}

func placementIntentSubjectKey(databaseID, partitionID string) (string, error) {
	if !natsToken.MatchString(databaseID) || !natsToken.MatchString(partitionID) {
		return "", errors.New("placement intent database and partition IDs must be lowercase NATS tokens")
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
	if lease.Version != 1 || !natsToken.MatchString(lease.Scope) || !natsToken.MatchString(lease.CandidateID) ||
		!natsToken.MatchString(lease.OwnerID) || !natsToken.MatchString(lease.TransitionID) || lease.Epoch == 0 ||
		lease.LeaseDuration < int64(time.Second) || lease.LeaseDuration > int64(5*time.Minute) {
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
