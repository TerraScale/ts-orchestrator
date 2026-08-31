package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ProviderOutcomeUnknownError means a mutating provider request may have been
// accepted, but its result could not be proved. Callers must reconcile or
// resume the same durable intent. They must not start a replacement intent.
type ProviderOutcomeUnknownError struct{ Message string }

func (e *ProviderOutcomeUnknownError) Error() string {
	if e == nil || e.Message == "" {
		return "provider mutation outcome is unknown"
	}
	return e.Message
}

type ProviderCapacityError struct{ Attempts int }

func (e *ProviderCapacityError) Error() string { return "provider capacity is unavailable" }

type ProviderMutationState string

const (
	MutationPrepared  ProviderMutationState = "prepared"
	MutationSubmitted ProviderMutationState = "submitted"
	MutationSucceeded ProviderMutationState = "succeeded"
	MutationFailed    ProviderMutationState = "failed"
	MutationUnknown   ProviderMutationState = "unknown"
)

// ProviderMutationIntent is the provider-neutral durable fence for a cloud
// mutation. Scope names the logical resource, while Fingerprint binds the
// complete immutable request. The same operation can resume at a newer
// controller epoch, but a different operation cannot replace an unresolved
// intent.
type ProviderMutationIntent struct {
	OperationID    ProviderOperationId    `json:"operationId"`
	Scope          string                 `json:"scope"`
	Action         string                 `json:"action"`
	Epoch          ProviderEpoch          `json:"epoch"`
	IdempotencyKey ProviderIdempotencyKey `json:"idempotencyKey"`
	Fingerprint    string                 `json:"fingerprint"`
}

type ProviderMutationResult struct {
	ResourceID    string `json:"resourceId,omitempty"`
	WorkRequestID string `json:"workRequestId,omitempty"`
	ETag          string `json:"etag,omitempty"`
}

type ProviderMutationRecord struct {
	Intent      ProviderMutationIntent `json:"intent"`
	State       ProviderMutationState  `json:"state"`
	Result      ProviderMutationResult `json:"result,omitempty"`
	FailureCode string                 `json:"failureCode,omitempty"`
	NextAttempt int                    `json:"nextAttempt,omitempty"`
}

// ProviderMutationJournal must durably CAS each logical scope. A process-local
// implementation is not safe for provider mutation.
type ProviderMutationJournal interface {
	AuthoritativeDurable() bool
	Prepare(context.Context, ProviderMutationIntent) (ProviderMutationRecord, error)
	MarkSubmitted(context.Context, ProviderMutationIntent) (ProviderMutationRecord, error)
	MarkAttemptRejected(context.Context, ProviderMutationIntent, int) (ProviderMutationRecord, error)
	MarkUnknown(context.Context, ProviderMutationIntent, ProviderMutationResult) (ProviderMutationRecord, error)
	MarkSucceeded(context.Context, ProviderMutationIntent, ProviderMutationResult) (ProviderMutationRecord, error)
	MarkFailed(context.Context, ProviderMutationIntent, string) (ProviderMutationRecord, error)
	MarkProviderFailed(context.Context, ProviderMutationIntent, ProviderMutationResult, string) (ProviderMutationRecord, error)
}

// ProviderMutationFingerprint builds the stable request binding stored in a
// durable intent. Callers must include every provider-visible immutable field.
func ProviderMutationFingerprint(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(strconv.Itoa(len(part))))
		_, _ = h.Write([]byte{':'})
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ProviderMutationScope derives the only accepted durable fence key for a
// logical resource. Adapters derive it from provider-neutral request fields,
// so callers cannot bypass a resource fence by choosing another journal key.
func ProviderMutationScope(kind string, parts ...string) string {
	return kind + "/" + ProviderMutationFingerprint(parts...)
}

func validateMutationIntent(intent ProviderMutationIntent) error {
	if intent.OperationID.Value == "" || intent.Epoch.Value == 0 || intent.IdempotencyKey.Value == "" {
		return &errs.Argument{Message: "provider mutation intent is incomplete"}
	}
	if len(intent.Scope) < 1 || len(intent.Scope) > 512 || strings.ContainsAny(intent.Scope, "\r\n") ||
		len(intent.Action) < 1 || len(intent.Action) > 96 || !tokenPattern.MatchString(intent.Action) {
		return &errs.Argument{Message: "provider mutation intent identity is invalid"}
	}
	if len(intent.Fingerprint) != sha256.Size*2 {
		return &errs.Argument{Message: "provider mutation fingerprint is invalid"}
	}
	if _, err := hex.DecodeString(intent.Fingerprint); err != nil || strings.ToLower(intent.Fingerprint) != intent.Fingerprint {
		return &errs.Argument{Message: "provider mutation fingerprint is invalid"}
	}
	return nil
}

func expectMutation(intent ProviderMutationIntent, action, scope string, parts ...string) error {
	if err := validateMutationIntent(intent); err != nil {
		return err
	}
	if intent.Action != action || intent.Scope != scope || intent.Fingerprint != ProviderMutationFingerprint(append([]string{action}, parts...)...) {
		return &InvalidOperationError{Message: "provider mutation does not match its durable fingerprint"}
	}
	return nil
}

// CASProviderMutationJournal persists one fenced record per logical resource
// using the same JetStream-compatible CAS seam as ownership records.
type CASProviderMutationJournal struct{ store OwnershipCASStore }

func NewCASProviderMutationJournal(store OwnershipCASStore) (*CASProviderMutationJournal, error) {
	if store == nil {
		return nil, &errs.Argument{Param: "store", Message: "provider mutation CAS store is required"}
	}
	return &CASProviderMutationJournal{store: store}, nil
}

func (j *CASProviderMutationJournal) AuthoritativeDurable() bool { return j != nil && j.store != nil }

func mutationJournalKey(scope string) string {
	h := sha256.Sum256([]byte(scope))
	return "provider.intent." + hex.EncodeToString(h[:])
}

func decodeMutationRecord(raw []byte, scope string) (ProviderMutationRecord, error) {
	var record ProviderMutationRecord
	if len(raw) == 0 || json.Unmarshal(raw, &record) != nil || record.Intent.Scope != scope || validateMutationIntent(record.Intent) != nil || record.NextAttempt < 0 {
		return ProviderMutationRecord{}, &InvalidDataError{Message: "provider mutation journal contains malformed data"}
	}
	switch record.State {
	case MutationPrepared, MutationSubmitted, MutationSucceeded, MutationFailed, MutationUnknown:
		return record, nil
	default:
		return ProviderMutationRecord{}, &InvalidDataError{Message: "provider mutation journal contains malformed state"}
	}
}

func encodeMutationRecord(record ProviderMutationRecord) ([]byte, error) {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > 32*1024 {
		return nil, &InvalidDataError{Message: "provider mutation intent cannot be persisted"}
	}
	return raw, nil
}

func sameMutation(a, b ProviderMutationIntent) bool {
	return a.OperationID == b.OperationID && a.Scope == b.Scope && a.Action == b.Action &&
		a.IdempotencyKey == b.IdempotencyKey && a.Fingerprint == b.Fingerprint
}

func terminalMutation(state ProviderMutationState) bool {
	return state == MutationSucceeded || state == MutationFailed
}

func (j *CASProviderMutationJournal) Prepare(ctx context.Context, intent ProviderMutationIntent) (ProviderMutationRecord, error) {
	if j == nil || j.store == nil {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation journal is unavailable"}
	}
	if ctx == nil {
		return ProviderMutationRecord{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := validateMutationIntent(intent); err != nil {
		return ProviderMutationRecord{}, err
	}
	key := mutationJournalKey(intent.Scope)
	for attempt := 0; attempt < 8; attempt++ {
		raw, revision, err := j.store.Get(ctx, key)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		next := ProviderMutationRecord{Intent: intent, State: MutationPrepared}
		if len(raw) != 0 {
			prior, err := decodeMutationRecord(raw, intent.Scope)
			if err != nil {
				return ProviderMutationRecord{}, err
			}
			if sameMutation(prior.Intent, intent) {
				if intent.Epoch.Value < prior.Intent.Epoch.Value {
					return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation controller epoch is stale"}
				}
				if intent.Epoch == prior.Intent.Epoch {
					return prior, nil
				}
				prior.Intent.Epoch = intent.Epoch
				next = prior
			} else {
				if intent.Epoch.Value < prior.Intent.Epoch.Value {
					return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation fence rejected a stale operation"}
				}
				if !terminalMutation(prior.State) {
					return ProviderMutationRecord{}, &ProviderOutcomeUnknownError{Message: "an unresolved provider mutation holds this resource fence"}
				}
			}
		}
		encoded, err := encodeMutationRecord(next)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		if err := j.store.CompareAndSwap(ctx, key, revision, encoded); err == nil {
			return next, nil
		} else if !isCASConflict(err) {
			return ProviderMutationRecord{}, err
		}
	}
	return ProviderMutationRecord{}, OwnershipCASConflict{}
}

func isCASConflict(err error) bool {
	var value OwnershipCASConflict
	var pointer *OwnershipCASConflict
	return errors.As(err, &value) || errors.As(err, &pointer)
}

func (j *CASProviderMutationJournal) transition(ctx context.Context, intent ProviderMutationIntent, state ProviderMutationState, result ProviderMutationResult, failure string, providerFailure bool) (ProviderMutationRecord, error) {
	if j == nil || j.store == nil {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation journal is unavailable"}
	}
	if ctx == nil {
		return ProviderMutationRecord{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := validateMutationIntent(intent); err != nil {
		return ProviderMutationRecord{}, err
	}
	if failure != "" && (len(failure) > 96 || !tokenPattern.MatchString(failure)) {
		return ProviderMutationRecord{}, &errs.Argument{Message: "provider mutation failure code is invalid"}
	}
	if len(result.ResourceID) > 2048 || len(result.WorkRequestID) > 256 || len(result.ETag) > 512 ||
		strings.ContainsAny(result.ResourceID+result.WorkRequestID+result.ETag, "\r\n") ||
		(result.WorkRequestID != "" && !validWorkRequestID(result.WorkRequestID)) {
		return ProviderMutationRecord{}, &errs.Argument{Message: "provider mutation result is invalid"}
	}
	if providerFailure && !validWorkRequestID(result.WorkRequestID) {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider-proven mutation failure has no valid work-request identity"}
	}
	key := mutationJournalKey(intent.Scope)
	for attempt := 0; attempt < 8; attempt++ {
		raw, revision, err := j.store.Get(ctx, key)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		prior, err := decodeMutationRecord(raw, intent.Scope)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		if !sameMutation(prior.Intent, intent) || prior.Intent.Epoch.Value > intent.Epoch.Value {
			return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation journal transition is fenced"}
		}
		if terminalMutation(prior.State) {
			if prior.State == state && prior.Result == result && prior.FailureCode == failure {
				return prior, nil
			}
			return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation terminal outcome cannot change"}
		}
		providerProvedUnknownFailure := prior.State == MutationUnknown && state == MutationFailed && providerFailure &&
			prior.Result == result && validWorkRequestID(result.WorkRequestID)
		if !validMutationTransition(intent.Action, prior.State, state) && !providerProvedUnknownFailure {
			return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation state transition is invalid"}
		}
		if prior.State == MutationUnknown && state == MutationUnknown {
			switch {
			case result == (ProviderMutationResult{}):
				result = prior.Result
			case prior.Result != (ProviderMutationResult{}) && prior.Result != result:
				return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation unknown outcome cannot change identity"}
			}
		}
		prior.Intent.Epoch = intent.Epoch
		prior.State, prior.Result, prior.FailureCode = state, result, failure
		encoded, err := encodeMutationRecord(prior)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		if err := j.store.CompareAndSwap(ctx, key, revision, encoded); err == nil {
			return prior, nil
		} else if !isCASConflict(err) {
			return ProviderMutationRecord{}, err
		}
	}
	return ProviderMutationRecord{}, OwnershipCASConflict{}
}

func validMutationTransition(action string, from, to ProviderMutationState) bool {
	if from == to {
		return true
	}
	switch from {
	case MutationPrepared:
		return to == MutationSubmitted || (to == MutationSucceeded && observedAbsentAction(action))
	case MutationSubmitted:
		return to == MutationSucceeded || to == MutationFailed || to == MutationUnknown
	case MutationUnknown:
		return to == MutationSucceeded
	default:
		return false
	}
}

func observedAbsentAction(action string) bool {
	switch action {
	case "volume.delete", "attachment.delete", "object.delete":
		return true
	default:
		return false
	}
}

func (j *CASProviderMutationJournal) MarkSubmitted(ctx context.Context, intent ProviderMutationIntent) (ProviderMutationRecord, error) {
	return j.transition(ctx, intent, MutationSubmitted, ProviderMutationResult{}, "", false)
}

// MarkAttemptRejected records one provider-proven retryable rejection and
// advances the durable cursor before an adapter tries another candidate.
func (j *CASProviderMutationJournal) MarkAttemptRejected(ctx context.Context, intent ProviderMutationIntent, attempt int) (ProviderMutationRecord, error) {
	if attempt < 0 {
		return ProviderMutationRecord{}, &errs.Argument{Message: "provider mutation attempt is invalid"}
	}
	if j == nil || j.store == nil {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation journal is unavailable"}
	}
	if ctx == nil {
		return ProviderMutationRecord{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return ProviderMutationRecord{}, err
	}
	if err := validateMutationIntent(intent); err != nil {
		return ProviderMutationRecord{}, err
	}
	key := mutationJournalKey(intent.Scope)
	for retry := 0; retry < 8; retry++ {
		raw, revision, err := j.store.Get(ctx, key)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		prior, err := decodeMutationRecord(raw, intent.Scope)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		if !sameMutation(prior.Intent, intent) || prior.Intent.Epoch.Value > intent.Epoch.Value {
			return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation journal transition is fenced"}
		}
		if prior.State != MutationSubmitted || prior.NextAttempt != attempt {
			return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation attempt transition is invalid"}
		}
		prior.Intent.Epoch = intent.Epoch
		prior.State = MutationPrepared
		prior.NextAttempt = attempt + 1
		encoded, err := encodeMutationRecord(prior)
		if err != nil {
			return ProviderMutationRecord{}, err
		}
		if err := j.store.CompareAndSwap(ctx, key, revision, encoded); err == nil {
			return prior, nil
		} else if !isCASConflict(err) {
			return ProviderMutationRecord{}, err
		}
	}
	return ProviderMutationRecord{}, OwnershipCASConflict{}
}

func (j *CASProviderMutationJournal) MarkUnknown(ctx context.Context, intent ProviderMutationIntent, result ProviderMutationResult) (ProviderMutationRecord, error) {
	return j.transition(ctx, intent, MutationUnknown, result, "", false)
}

func (j *CASProviderMutationJournal) MarkSucceeded(ctx context.Context, intent ProviderMutationIntent, result ProviderMutationResult) (ProviderMutationRecord, error) {
	return j.transition(ctx, intent, MutationSucceeded, result, "", false)
}

func (j *CASProviderMutationJournal) MarkFailed(ctx context.Context, intent ProviderMutationIntent, code string) (ProviderMutationRecord, error) {
	return j.transition(ctx, intent, MutationFailed, ProviderMutationResult{}, code, false)
}

func (j *CASProviderMutationJournal) MarkProviderFailed(ctx context.Context, intent ProviderMutationIntent, result ProviderMutationResult, code string) (ProviderMutationRecord, error) {
	if code != "provider-work-request-failed" && code != "provider-work-request-canceled" {
		return ProviderMutationRecord{}, &errs.Argument{Message: "provider-proven mutation failure code is invalid"}
	}
	return j.transition(ctx, intent, MutationFailed, result, code, true)
}

func prepareMutation(ctx context.Context, journal ProviderMutationJournal, intent ProviderMutationIntent) (ProviderMutationRecord, error) {
	if journal == nil || !journal.AuthoritativeDurable() {
		return ProviderMutationRecord{}, &InvalidOperationError{Message: "provider mutation requires an authoritative durable intent journal"}
	}
	return journal.Prepare(ctx, intent)
}

func completedMutation(record ProviderMutationRecord) (ProviderMutationResult, bool, error) {
	switch record.State {
	case MutationSucceeded:
		return record.Result, true, nil
	case MutationFailed:
		return ProviderMutationResult{}, true, &InvalidOperationError{Message: "provider mutation previously failed"}
	default:
		return ProviderMutationResult{}, false, nil
	}
}

// Provider-neutral automated resource contracts.
type ComputeProvider interface {
	LaunchInstance(context.Context, ComputeLaunchRequest) (ComputeInstance, error)
	GetInstance(context.Context, string) (ComputeInstance, bool, error)
	TerminateInstance(context.Context, ComputeTerminateRequest) error
}

type ComputeCapacityCandidate struct {
	AvailabilityDomain string
	FaultDomain        string
	SubnetID           string
	Shape              string
	OCPUs              float64
	MemoryGiB          float64
}

type ComputeLaunchRequest struct {
	Mutation        ProviderMutationIntent
	CompartmentID   string
	DisplayName     string
	ImageID         string
	NSGIDs          []string
	BootstrapBase64 string
	Candidates      []ComputeCapacityCandidate
	Tags            map[string]string
}

type ComputeTerminateRequest struct {
	Mutation   ProviderMutationIntent
	InstanceID string
	IfMatch    string
}

type ComputeInstance struct {
	ID                 string
	LifecycleState     string
	ETag               string
	WorkRequestID      string
	AvailabilityDomain string
	Shape              string
}

type BlockVolumeProvider interface {
	CreateVolume(context.Context, VolumeCreateRequest) (BlockVolume, error)
	GetBlockVolume(context.Context, string) (BlockVolume, bool, error)
	DeleteVolume(context.Context, VolumeDeleteRequest) error
}

type BlockVolumeExpansionProvider interface {
	Expand(context.Context, ProviderIntent) (VolumeExpansionResult, error)
}

type VolumeCreateRequest struct {
	Mutation           ProviderMutationIntent
	CompartmentID      string
	AvailabilityDomain string
	DisplayName        string
	SizeGiB            uint64
	VPUsPerGiB         uint64
	Tags               map[string]string
}

type VolumeDeleteRequest struct {
	Mutation ProviderMutationIntent
	VolumeID string
	IfMatch  string
}

type BlockVolume struct {
	ID             string
	CompartmentID  string
	LifecycleState string
	SizeGiB        uint64
	VPUsPerGiB     uint64
	ETag           string
	WorkRequestID  string
}

type VolumeAttachmentProvider interface {
	AttachVolume(context.Context, VolumeAttachRequest) (VolumeAttachment, error)
	GetVolumeAttachment(context.Context, string) (VolumeAttachment, bool, error)
	DetachVolume(context.Context, VolumeDetachRequest) error
}

type VolumeAttachRequest struct {
	Mutation      ProviderMutationIntent
	CompartmentID string
	InstanceID    string
	VolumeID      string
	DisplayName   string
	ReadOnly      bool
}

type VolumeDetachRequest struct {
	Mutation     ProviderMutationIntent
	AttachmentID string
	IfMatch      string
}

type VolumeAttachment struct {
	ID             string
	CompartmentID  string
	InstanceID     string
	VolumeID       string
	LifecycleState string
	ETag           string
	WorkRequestID  string
}

type RegistryPullProvider interface {
	PullManifest(context.Context, RegistryManifestRequest) (RegistryManifest, error)
	PullBlob(context.Context, RegistryBlobRequest) (io.ReadCloser, int64, error)
}

type RegistryManifestRequest struct{ Repository, Reference string }
type RegistryBlobRequest struct{ Repository, Digest string }
type RegistryManifest struct {
	Digest, MediaType string
	Content           []byte
}

type ObjectStorageProvider interface {
	PutObject(context.Context, ObjectPutRequest) (ObjectMetadata, error)
	HeadObject(context.Context, ObjectRef) (ObjectMetadata, bool, error)
	GetObject(context.Context, ObjectRef) (io.ReadCloser, ObjectMetadata, error)
	DeleteObject(context.Context, ObjectDeleteRequest) error
}

type ObjectRef struct{ Namespace, Bucket, Name string }

// ObjectStorageReservation is an exact durable catalog reservation. The
// catalog records generated ledger and backup object names before the
// provider adapter may read or mutate them.
type ObjectStorageReservation struct{ Object ObjectRef }

// DurableObjectStorageAuthority is the read-authority seam for Object
// Storage. Mutation fingerprints do not authorize HEAD, GET, or LIST, so the
// adapter requires a separate durable exact-name reservation for every call.
type DurableObjectStorageAuthority interface {
	AuthoritativeDurable() bool
	LookupObject(context.Context, ObjectRef) (ObjectStorageReservation, bool, error)
}

type ObjectPutRequest struct {
	Mutation ProviderMutationIntent
	Object   ObjectRef
	Content  []byte
	SHA256   string
}
type ObjectDeleteRequest struct {
	Mutation ProviderMutationIntent
	Object   ObjectRef
	IfMatch  string
}
type ObjectMetadata struct {
	ETag, SHA256 string
	Size         int64
}

type WorkRequestState string

const (
	WorkRequestNotVisible WorkRequestState = "not-visible"
	WorkRequestAccepted   WorkRequestState = "accepted"
	WorkRequestInProgress WorkRequestState = "in-progress"
	WorkRequestSucceeded  WorkRequestState = "succeeded"
	WorkRequestFailed     WorkRequestState = "failed"
	WorkRequestCanceled   WorkRequestState = "canceled"
)

type WorkRequest struct {
	ID              string
	State           WorkRequestState
	PercentComplete float64
}
type WorkRequestWaitPolicy struct {
	PollInterval          time.Duration
	MaxPolls, MaxNotFound int
}

type WorkRequestProvider interface {
	GetWorkRequest(context.Context, string) (WorkRequest, error)
	WaitWorkRequest(context.Context, string, WorkRequestWaitPolicy) (WorkRequest, error)
}

func mutationResultInstance(result ProviderMutationResult) (ComputeInstance, error) {
	if !isOCID(result.ResourceID, "instance") {
		return ComputeInstance{}, &InvalidDataError{Message: "durable compute result is invalid"}
	}
	return ComputeInstance{ID: result.ResourceID, ETag: result.ETag, WorkRequestID: result.WorkRequestID}, nil
}

func mutationResultVolume(result ProviderMutationResult) (BlockVolume, error) {
	if !isOCID(result.ResourceID, "volume") {
		return BlockVolume{}, &InvalidDataError{Message: "durable volume result is invalid"}
	}
	return BlockVolume{ID: result.ResourceID, ETag: result.ETag, WorkRequestID: result.WorkRequestID}, nil
}

func mutationResultAttachment(result ProviderMutationResult) (VolumeAttachment, error) {
	if !isOCID(result.ResourceID, "volumeattachment") {
		return VolumeAttachment{}, &InvalidDataError{Message: "durable attachment result is invalid"}
	}
	return VolumeAttachment{ID: result.ResourceID, ETag: result.ETag, WorkRequestID: result.WorkRequestID}, nil
}

func validateBoundedName(value, field string, max int) error {
	if len(value) < 1 || len(value) > max || strings.ContainsAny(value, "\r\n") {
		return &errs.Argument{Message: fmt.Sprintf("%s is invalid", field)}
	}
	return nil
}

var _ ProviderMutationJournal = (*CASProviderMutationJournal)(nil)
