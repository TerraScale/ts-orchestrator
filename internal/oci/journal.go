package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go/jetstream"
)

const (
	journalBucket       = "TS_OCI_OPERATIONS"
	journalSchema       = 1
	journalMaxValueSize = 64 << 10
)

// KVJournal stores operation intent and positive resource ownership in
// replicated JetStream KV. It never treats OCI tags by themselves as adoption
// authority.
type KVJournal struct {
	kv jetstream.KeyValue
}

type journalEntry struct {
	PoolCreateRequest  PoolCreateRequest        `json:"pool_create_request,omitzero"`
	PoolCreateResult   PoolCreateResult         `json:"pool_create_result,omitzero"`
	CapacityRequest    CapacityRequest          `json:"capacity_request,omitzero"`
	VolumeTermination  volumeTermination        `json:"volume_termination,omitzero"`
	FormatPermit       VolumeFormatPermitRecord `json:"format_permit,omitzero"`
	MountPermit        VolumeMountPermitRecord  `json:"mount_permit,omitzero"`
	SchemaVersion      int                      `json:"schema_version"`
	Kind               string                   `json:"kind"`
	Intent             OperationIntent          `json:"intent,omitzero"`
	Result             OperationResult          `json:"result,omitzero"`
	Identity           ResourceIdentity         `json:"identity,omitzero"`
	AttachmentIdentity AttachmentIdentity       `json:"attachment_identity,omitzero"`
	BootBinding        BootBinding              `json:"boot_binding,omitzero"`
}

func (journal *KVJournal) RecordBootBinding(ctx context.Context, binding BootBinding) error {
	if !validBootBinding(binding) {
		return errors.New("OCI boot binding is incomplete")
	}
	entry := journalEntry{SchemaVersion: journalSchema, Kind: "boot-binding", BootBinding: binding}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode OCI boot binding: %w", err)
	}
	key := ownershipKey("boot-binding", binding.InstanceID)
	if _, err := journal.kv.Create(ctx, key, data); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("persist OCI boot binding: %w", err)
	}
	current, err := journal.read(ctx, key)
	if err != nil {
		return err
	}
	if current.Kind != "boot-binding" || current.BootBinding != binding {
		return errors.New("OCI instance is already bound to a different boot volume")
	}
	return nil
}

func (journal *KVJournal) GetBootBinding(ctx context.Context, instanceID string) (BootBinding, bool, error) {
	if instanceID == "" {
		return BootBinding{}, false, errors.New("OCI boot binding requires instance ID")
	}
	entry, err := journal.read(ctx, ownershipKey("boot-binding", instanceID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return BootBinding{}, false, nil
	}
	if err != nil {
		return BootBinding{}, false, err
	}
	if entry.Kind != "boot-binding" || entry.BootBinding.InstanceID != instanceID || !validBootBinding(entry.BootBinding) {
		return BootBinding{}, false, errors.New("OCI boot binding is corrupt")
	}
	return entry.BootBinding, true, nil
}

func (journal *KVJournal) ListOperations(ctx context.Context) ([]OperationRecord, error) {
	keys, err := journal.kv.Keys(ctx)
	if errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list OCI journal keys: %w", err)
	}
	if len(keys) > 10_000 {
		return nil, errors.New("OCI journal operation inventory exceeds safety bound")
	}
	var records []OperationRecord
	for _, key := range keys {
		if !entityid.Valid(key) {
			return nil, errors.New("invalid OCI journal key")
		}
		entry, err := journal.read(ctx, key)
		if err != nil {
			return nil, err
		}
		if entry.Kind != "operation" {
			continue
		}
		if operationKey(entry.Intent) != key || validateIntent(entry.Intent) != nil {
			return nil, errors.New("OCI journal operation inventory is corrupt")
		}
		records = append(records, OperationRecord{Intent: entry.Intent, Result: entry.Result})
	}
	return records, nil
}

func validBootBinding(binding BootBinding) bool {
	return binding.InstanceID != "" && binding.BootVolumeID != "" && binding.Region != "" &&
		binding.Generation != 0 && binding.Owner != "" && binding.CreateKey != "" &&
		binding.CompartmentID != "" && binding.AvailabilityDomain != "" && binding.ImageID != "" &&
		binding.SizeGB > 0 && binding.VPUsPerGB > 0
}

// OpenJournal creates or opens the regional replicated OCI operation bucket.
// Replicas must match the regional controller quorum configuration.
func OpenJournal(ctx context.Context, js jetstream.JetStream, replicas int) (*KVJournal, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("OCI journal requires JetStream and one to five replicas")
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:       journalBucket,
		Description:  "Durable OCI mutation intent and resource ownership",
		MaxValueSize: journalMaxValueSize,
		History:      5,
		Storage:      jetstream.FileStorage,
		Replicas:     replicas,
		Compression:  true,
	})
	if err != nil {
		if !errors.Is(err, jetstream.ErrBucketExists) {
			return nil, fmt.Errorf("create OCI journal bucket: %w", err)
		}
		kv, err = js.KeyValue(ctx, journalBucket)
		if err != nil {
			return nil, fmt.Errorf("open existing OCI journal bucket: %w", err)
		}
		status, statusErr := kv.Status(ctx)
		if statusErr != nil {
			return nil, fmt.Errorf("inspect OCI journal bucket: %w", statusErr)
		}
		config := status.Config()
		if config.Replicas != replicas || config.Storage != jetstream.FileStorage || config.TTL != 0 || config.History < 2 || config.MaxValueSize > journalMaxValueSize {
			return nil, errors.New("existing OCI journal bucket has incompatible durability limits")
		}
	}
	return NewKVJournal(kv)
}

// NewKVJournal wraps a caller-provisioned regional JetStream KV bucket. The
// caller is responsible for using a durable, quorum-replicated bucket.
func NewKVJournal(kv jetstream.KeyValue) (*KVJournal, error) {
	if kv == nil {
		return nil, errors.New("OCI journal KV bucket is required")
	}
	return &KVJournal{kv: kv}, nil
}

func (journal *KVJournal) RecordIntent(ctx context.Context, intent OperationIntent) error {
	if err := validateIntent(intent); err != nil {
		return err
	}
	entry := journalEntry{SchemaVersion: journalSchema, Kind: "operation", Intent: intent}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode OCI operation intent: %w", err)
	}
	key := operationKey(intent)
	_, err = journal.kv.Create(ctx, key, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("persist OCI operation intent: %w", err)
	}
	current, err := journal.read(ctx, key)
	if err != nil {
		return err
	}
	if current.Kind != "operation" || !sameIntent(current.Intent, intent) {
		return errors.New("OCI operation key was reused for a different mutation")
	}
	return nil
}

func (journal *KVJournal) RecordResult(ctx context.Context, result OperationResult) error {
	if err := validateIntent(result.Intent); err != nil {
		return err
	}
	if result.Intent.Action == actionVolumeAttach && !result.Unknown && (result.ResourceID == "" || result.ETag == "") {
		return errors.New("confirmed OCI volume attachment result requires an attachment ID and ETag")
	}
	if result.Intent.Action == actionVolumeResize && !result.Unknown && result.ResourceID != result.Intent.VolumeID {
		return errors.New("confirmed OCI volume resize result must name its exact volume")
	}
	key := operationKey(result.Intent)
	if result.RecordedAt.IsZero() {
		result.RecordedAt = time.Now().UTC()
	}
	for range 4 {
		entry, err := journal.kv.Get(ctx, key)
		if err != nil {
			return fmt.Errorf("read OCI operation intent: %w", err)
		}
		current, err := decodeJournalEntry(entry.Value())
		if err != nil {
			return err
		}
		if current.Kind != "operation" || !sameIntent(current.Intent, result.Intent) {
			return errors.New("OCI operation result has no matching durable intent")
		}
		// The operation's first committed intent owns the retry window. A
		// retried caller's freshly generated CreatedAt must never refresh it.
		result.Intent = current.Intent
		if !current.Result.RecordedAt.IsZero() && !current.Result.Unknown {
			if result.Unknown {
				// A late timeout must not overwrite a confirmed provider result.
				return journal.repairOwnership(ctx, current.Result)
			}
			if !sameResult(current.Result, result) {
				return errors.New("OCI operation already has a different confirmed result")
			}
			return journal.repairOwnership(ctx, current.Result)
		}
		current.Result = result
		data, err := json.Marshal(current)
		if err != nil {
			return fmt.Errorf("encode OCI operation result: %w", err)
		}
		if _, err := journal.kv.Update(ctx, key, data, entry.Revision()); err != nil {
			if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				continue
			}
			// The write outcome can be unknown. Re-read on the next call rather
			// than changing the accepted identity using a fresh revision here.
			return fmt.Errorf("record OCI operation result: %w", err)
		}
		return journal.repairOwnership(ctx, result)
	}
	return errors.New("OCI operation result CAS did not converge")
}

// GetResult reports whether an operation has a durable provider result. An
// Unknown result is distinct from a fresh intent so callers can safely retry
// a stable OCI token without treating matching tags as ownership proof.
func (journal *KVJournal) GetResult(ctx context.Context, intent OperationIntent) (OperationResult, bool, error) {
	if err := validateIntent(intent); err != nil {
		return OperationResult{}, false, err
	}
	entry, err := journal.read(ctx, operationKey(intent))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return OperationResult{}, false, nil
	}
	if err != nil {
		return OperationResult{}, false, err
	}
	if entry.Kind != "operation" || !sameIntent(entry.Intent, intent) {
		return OperationResult{}, false, errors.New("OCI result lookup has no matching durable intent")
	}
	result := entry.Result
	if result.RecordedAt.IsZero() {
		result.Intent = entry.Intent
		return result, false, nil
	}
	result.Intent = entry.Intent
	return result, true, nil
}

// GetOperation returns the first committed intent for an exact operation key,
// including when the provider has not yet produced a durable result. Only the
// immutable key scope is supplied by the retrying caller; mutation details are
// recovered from the journal rather than reconstructed.
func (journal *KVJournal) GetOperation(ctx context.Context, scope OperationScope) (OperationIntent, bool, error) {
	if scope.Action == "" || scope.Key == "" || scope.Generation == 0 || scope.Owner == "" {
		return OperationIntent{}, false, errors.New("OCI operation lookup scope is incomplete")
	}
	if _, err := scope.Region.OCIRegion(); err != nil {
		return OperationIntent{}, false, err
	}
	keyIntent := OperationIntent{
		Action: scope.Action, Key: scope.Key, Region: scope.Region,
		Generation: scope.Generation, Owner: scope.Owner,
	}
	entry, err := journal.read(ctx, operationKey(keyIntent))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return OperationIntent{}, false, nil
	}
	if err != nil {
		return OperationIntent{}, false, err
	}
	intent := entry.Intent
	if entry.Kind != "operation" || intent.Action != scope.Action || intent.Key != scope.Key ||
		intent.Region != scope.Region || intent.Generation != scope.Generation || intent.Owner != scope.Owner {
		return OperationIntent{}, false, errors.New("OCI operation lookup has no matching durable intent")
	}
	return intent, true, nil
}

func (journal *KVJournal) IsOwnedInstance(ctx context.Context, identity ResourceIdentity) (bool, error) {
	return journal.isOwned(ctx, "instance", identity)
}

func (journal *KVJournal) IsOwnedVolume(ctx context.Context, identity ResourceIdentity) (bool, error) {
	return journal.isOwned(ctx, "volume", identity)
}

func (journal *KVJournal) IsOwnedAttachment(ctx context.Context, identity AttachmentIdentity) (bool, error) {
	if !validAttachmentIdentity(identity) {
		return false, nil
	}
	entry, err := journal.read(ctx, ownershipKey("attachment", identity.ID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if entry.SchemaVersion != journalSchema || entry.Kind != "attachment" || entry.AttachmentIdentity != identity ||
		entry.Intent.Action != actionVolumeAttach || entry.Result.Unknown || entry.Result.RecordedAt.IsZero() ||
		entry.Result.ResourceID != identity.ID || entry.Result.ETag != identity.ETag ||
		!sameIntent(entry.Intent, entry.Result.Intent) || !entry.Intent.CreatedAt.Equal(entry.Result.Intent.CreatedAt) ||
		!sameAttachmentIntentIdentity(entry.Intent, identity) {
		return false, nil
	}
	operation, err := journal.read(ctx, operationKey(entry.Intent))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if operation.Kind != "operation" || !sameIntent(operation.Intent, entry.Intent) ||
		!operation.Intent.CreatedAt.Equal(entry.Intent.CreatedAt) || operation.Result.Unknown ||
		operation.Result.RecordedAt.IsZero() || !sameResult(operation.Result, entry.Result) ||
		!operation.Result.Intent.CreatedAt.Equal(entry.Intent.CreatedAt) {
		return false, nil
	}
	return true, nil
}

func (journal *KVJournal) recordOwnership(ctx context.Context, resourceKind string, identity ResourceIdentity) error {
	entry := journalEntry{SchemaVersion: journalSchema, Kind: resourceKind, Identity: identity}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode OCI %s ownership: %w", resourceKind, err)
	}
	key := ownershipKey(resourceKind, identity.ID)
	_, err = journal.kv.Create(ctx, key, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("persist OCI %s ownership: %w", resourceKind, err)
	}
	existing, err := journal.read(ctx, key)
	if err != nil {
		return err
	}
	if existing.Kind != resourceKind || existing.Identity != identity {
		return fmt.Errorf("OCI %s is already owned by another controller identity", resourceKind)
	}
	return nil
}

func (journal *KVJournal) recordAttachmentOwnership(ctx context.Context, identity AttachmentIdentity, result OperationResult) error {
	if !validAttachmentIdentity(identity) || result.Unknown || result.RecordedAt.IsZero() ||
		result.ResourceID != identity.ID || result.ETag != identity.ETag || result.Intent.Action != actionVolumeAttach ||
		!sameAttachmentIntentIdentity(result.Intent, identity) {
		return errors.New("OCI attachment ownership does not match a confirmed attach operation")
	}
	entry := journalEntry{
		SchemaVersion: journalSchema, Kind: "attachment", Intent: result.Intent,
		Result: result, AttachmentIdentity: identity,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode OCI attachment ownership: %w", err)
	}
	key := ownershipKey("attachment", identity.ID)
	if _, err := journal.kv.Create(ctx, key, data); err == nil {
		return nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return fmt.Errorf("persist OCI attachment ownership: %w", err)
	}
	existing, err := journal.read(ctx, key)
	if err != nil {
		return err
	}
	if existing.Kind != "attachment" || existing.AttachmentIdentity != identity ||
		!sameIntent(existing.Intent, result.Intent) || !sameResult(existing.Result, result) {
		return errors.New("OCI attachment ID is already bound to a different durable operation")
	}
	return nil
}

func (journal *KVJournal) isOwned(ctx context.Context, kind string, identity ResourceIdentity) (bool, error) {
	if identity.ID == "" || identity.Generation == 0 || identity.Owner == "" || identity.CreateKey == "" {
		return false, nil
	}
	entry, err := journal.read(ctx, ownershipKey(kind, identity.ID))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return journal.repairOwnershipFromOperation(ctx, kind, identity)
	}
	if err != nil {
		return false, err
	}
	if entry.SchemaVersion != journalSchema || entry.Kind != kind {
		return false, nil
	}
	if entry.Identity == identity {
		return true, nil
	}
	if kind == "volume" && staleVolumeOwnership(entry.Identity, identity) {
		// A confirmed resize whose ownership advance was interrupted left the
		// record at a smaller size; finish the advance from the receipt.
		owned, err := journal.advanceFromConfirmedResize(ctx, identity)
		if err != nil || owned {
			return owned, err
		}
		// A resize this controller journaled and OCI applied, whose receipt
		// was never confirmed (the re-observation failed or the process
		// stopped first), leaves the same stale record. Without this the
		// create/recover path rejects the grown volume before the resize
		// path can confirm its receipt.
		return journal.advanceFromAppliedResizeIntent(ctx, entry.Identity, identity)
	}
	return false, nil
}

// advanceFromAppliedResizeIntent advances the ownership record of a volume
// observed at exactly the target of this controller's own unconfirmed resize
// intent, whose recorded predecessor is exactly the current ownership record.
// Every scope field must match; any other size stays not owned. The receipt
// itself is still confirmed only by ResizeRetainedVolume.
func (journal *KVJournal) advanceFromAppliedResizeIntent(ctx context.Context, recorded, identity ResourceIdentity) (bool, error) {
	attempts, err := journal.resizeAttempts(ctx, identity)
	if err != nil {
		return false, err
	}
	for _, entry := range attempts {
		resize := entry.Intent
		if resize.PreviousSizeGB != recorded.SizeGB || !entry.Result.RecordedAt.IsZero() && !entry.Result.Unknown {
			continue
		}
		if err := journal.advanceVolumeOwnership(ctx, OperationResult{Intent: resize}); err != nil {
			if errors.Is(err, errVolumeOwnershipMismatch) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// resizeAttempts reads the journaled attempts to resize identity.ID to
// exactly identity.SizeGB, in attempt order, keeping only intents that match
// identity in every scope field. Attempts are written in order, so the first
// missing key ends the bounded lookup.
func (journal *KVJournal) resizeAttempts(ctx context.Context, identity ResourceIdentity) ([]journalEntry, error) {
	var attempts []journalEntry
	for attempt := 1; attempt <= maxVolumeResizeAttempts; attempt++ {
		key := OperationIntent{
			Action: actionVolumeResize, Key: volumeResizeAttemptKey(identity.ID, identity.SizeGB, attempt),
			Region: identity.Region, Generation: identity.Generation, Owner: identity.Owner,
		}
		entry, err := journal.read(ctx, operationKey(key))
		if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
			return attempts, nil
		}
		if err != nil {
			return nil, err
		}
		resize := entry.Intent
		if entry.Kind != "operation" || resize.Action != actionVolumeResize || resize.Key != key.Key ||
			resize.Region != identity.Region || resize.Generation != identity.Generation || resize.Owner != identity.Owner ||
			resize.VolumeID != identity.ID || resize.CreateKey != identity.CreateKey ||
			resize.AvailabilityDomain != identity.AvailabilityDomain || resize.SizeGB != identity.SizeGB {
			continue
		}
		attempts = append(attempts, entry)
	}
	return attempts, nil
}

// staleVolumeOwnership reports a recorded volume identity that differs from
// observed only by a smaller size.
func staleVolumeOwnership(recorded, observed ResourceIdentity) bool {
	smaller := observed
	smaller.SizeGB = recorded.SizeGB
	return recorded == smaller && recorded.SizeGB < observed.SizeGB
}

// advanceFromConfirmedResize completes an interrupted ownership advance: the
// confirmed resize to exactly identity.SizeGB moves the record from its
// recorded predecessor size by CAS. Anything else stays not owned.
func (journal *KVJournal) advanceFromConfirmedResize(ctx context.Context, identity ResourceIdentity) (bool, error) {
	result, found, err := journal.confirmedResize(ctx, identity)
	if err != nil || !found {
		return false, err
	}
	if err := journal.advanceVolumeOwnership(ctx, result); err != nil {
		if errors.Is(err, errVolumeOwnershipMismatch) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (journal *KVJournal) read(ctx context.Context, key string) (journalEntry, error) {
	entry, err := journal.kv.Get(ctx, key)
	if err != nil {
		return journalEntry{}, err
	}
	return decodeJournalEntry(entry.Value())
}

func decodeJournalEntry(data []byte) (journalEntry, error) {
	var record journalEntry
	if err := json.Unmarshal(data, &record, json.RejectUnknownMembers(true)); err != nil {
		return journalEntry{}, fmt.Errorf("decode OCI journal record: %w", err)
	}
	if record.SchemaVersion != journalSchema {
		return journalEntry{}, errors.New("OCI journal record has unsupported schema version")
	}
	return record, nil
}

func (journal *KVJournal) repairOwnership(ctx context.Context, result OperationResult) error {
	if result.Unknown || result.ResourceID == "" {
		return nil
	}
	identity := ResourceIdentity{
		ID: result.ResourceID, Region: result.Intent.Region, Generation: result.Intent.Generation,
		Owner: result.Intent.Owner, CreateKey: result.Intent.CreateKey,
	}
	switch result.Intent.Action {
	case actionLaunch:
		return journal.recordOwnership(ctx, "instance", identity)
	case actionVolumeCreate:
		identity.AvailabilityDomain = result.Intent.AvailabilityDomain
		identity.SizeGB = result.Intent.SizeGB
		return journal.recordOwnership(ctx, "volume", identity)
	case actionVolumeAttach:
		return journal.recordAttachmentOwnership(ctx, attachmentIdentityFromResult(result), result)
	case actionVolumeResize:
		return journal.advanceVolumeOwnership(ctx, result)
	default:
		return nil
	}
}

// errVolumeOwnershipMismatch reports a volume ownership record that is
// neither the resize predecessor nor its target.
var errVolumeOwnershipMismatch = errors.New("OCI volume ownership does not match the resize predecessor")

// advanceVolumeOwnership moves the volume ownership record from the exact
// predecessor size to the confirmed resized size with a revision CAS. Any
// other recorded identity is a conflict; a missing record is rebuilt only by
// repairOwnershipFromOperation from the create and resize operations.
func (journal *KVJournal) advanceVolumeOwnership(ctx context.Context, result OperationResult) error {
	intent := result.Intent
	next := ResourceIdentity{
		ID: intent.VolumeID, Region: intent.Region, Generation: intent.Generation, Owner: intent.Owner,
		CreateKey: intent.CreateKey, AvailabilityDomain: intent.AvailabilityDomain, SizeGB: intent.SizeGB,
	}
	previous := next
	previous.SizeGB = intent.PreviousSizeGB
	key := ownershipKey("volume", intent.VolumeID)
	for range 4 {
		raw, err := journal.kv.Get(ctx, key)
		if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
			return errors.New("OCI volume resize has no predecessor ownership record")
		}
		if err != nil {
			return err
		}
		current, err := decodeJournalEntry(raw.Value())
		if err != nil {
			return err
		}
		if current.Kind != "volume" {
			return errors.New("OCI volume ownership record is corrupt")
		}
		switch current.Identity {
		case next:
			return nil
		case previous:
		default:
			return errVolumeOwnershipMismatch
		}
		data, err := json.Marshal(journalEntry{SchemaVersion: journalSchema, Kind: "volume", Identity: next})
		if err != nil {
			return fmt.Errorf("encode OCI volume ownership: %w", err)
		}
		if _, err := journal.kv.Update(ctx, key, data, raw.Revision()); err != nil {
			if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				continue
			}
			return fmt.Errorf("advance OCI volume ownership: %w", err)
		}
		return nil
	}
	return errors.New("OCI volume ownership CAS did not converge")
}

func attachmentIdentityFromResult(result OperationResult) AttachmentIdentity {
	intent := result.Intent
	return AttachmentIdentity{
		ID: result.ResourceID, InstanceID: intent.ResourceID, VolumeID: intent.VolumeID,
		Device: intent.Device, ETag: result.ETag, Region: intent.Region,
		Generation: intent.Generation, Owner: intent.Owner, CreateKey: intent.CreateKey,
		IsReadOnly: intent.IsReadOnly, IsShareable: intent.IsShareable,
		IsPvEncryptionInTransitEnabled: intent.IsPvEncryptionInTransitEnabled,
	}
}

func sameAttachmentIntentIdentity(intent OperationIntent, identity AttachmentIdentity) bool {
	return intent.ResourceID == identity.InstanceID && intent.VolumeID == identity.VolumeID &&
		intent.Device == identity.Device && intent.Region == identity.Region &&
		intent.Generation == identity.Generation && intent.Owner == identity.Owner &&
		intent.CreateKey == identity.CreateKey && intent.IsReadOnly == identity.IsReadOnly &&
		intent.IsShareable == identity.IsShareable &&
		intent.IsPvEncryptionInTransitEnabled == identity.IsPvEncryptionInTransitEnabled
}

func validAttachmentIdentity(identity AttachmentIdentity) bool {
	return identity.ID != "" && identity.InstanceID != "" && identity.VolumeID != "" &&
		validDevicePath(identity.Device) && identity.ETag != "" && identity.Region != "" &&
		identity.Generation != 0 && identity.Owner != "" && identity.CreateKey != "" &&
		identity.IsReadOnly == retainedVolumeReadOnly && identity.IsShareable == retainedVolumeShareable &&
		identity.IsPvEncryptionInTransitEnabled == retainedVolumeEncryptionInTransit
}

func (journal *KVJournal) repairOwnershipFromOperation(ctx context.Context, kind string, identity ResourceIdentity) (bool, error) {
	action := ""
	switch kind {
	case "instance":
		action = actionLaunch
	case "volume":
		action = actionVolumeCreate
	default:
		return false, nil
	}
	intent := OperationIntent{
		Action: action, Key: identity.CreateKey, Region: identity.Region,
		Generation: identity.Generation, Owner: identity.Owner, CreateKey: identity.CreateKey,
	}
	entry, err := journal.read(ctx, operationKey(intent))
	if errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if entry.Kind != "operation" || entry.Intent.Action != action || entry.Intent.Key != identity.CreateKey ||
		entry.Intent.Region != identity.Region || entry.Intent.Generation != identity.Generation ||
		entry.Intent.Owner != identity.Owner || entry.Intent.CreateKey != identity.CreateKey || entry.Result.RecordedAt.IsZero() ||
		entry.Result.Unknown || entry.Result.ResourceID != identity.ID {
		return false, nil
	}
	if kind == "volume" && entry.Intent.AvailabilityDomain != identity.AvailabilityDomain {
		return false, nil
	}
	if kind == "volume" && entry.Intent.SizeGB != identity.SizeGB {
		return journal.repairResizedVolumeOwnership(ctx, identity)
	}
	if err := journal.repairOwnership(ctx, entry.Result); err != nil {
		return false, err
	}
	return true, nil
}

// repairResizedVolumeOwnership rebuilds a missing ownership record of a grown
// volume. The confirmed create already proved ownership of identity.ID; a
// confirmed resize to exactly identity.SizeGB proves the current size.
func (journal *KVJournal) repairResizedVolumeOwnership(ctx context.Context, identity ResourceIdentity) (bool, error) {
	if _, found, err := journal.confirmedResize(ctx, identity); err != nil || !found {
		return false, err
	}
	if err := journal.recordOwnership(ctx, "volume", identity); err != nil {
		return false, err
	}
	return true, nil
}

// confirmedResize returns the confirmed resize of identity.ID to exactly
// identity.SizeGB when its intent matches identity in every scope field.
func (journal *KVJournal) confirmedResize(ctx context.Context, identity ResourceIdentity) (OperationResult, bool, error) {
	attempts, err := journal.resizeAttempts(ctx, identity)
	if err != nil {
		return OperationResult{}, false, err
	}
	for _, entry := range attempts {
		if !entry.Result.RecordedAt.IsZero() && !entry.Result.Unknown && entry.Result.ResourceID == identity.ID {
			return entry.Result, true, nil
		}
	}
	return OperationResult{}, false, nil
}

func validateIntent(intent OperationIntent) error {
	if intent.Action == "" || intent.Key == "" || intent.Region == "" || intent.Generation == 0 || intent.Owner == "" ||
		intent.CreatedAt.IsZero() || intent.CreatedAt.Location() != time.UTC {
		return errors.New("OCI operation intent is incomplete")
	}
	if intent.Action == actionLaunch && (intent.CreateKey == "" || !validManagedPrivateIP(intent.PrivateIP) || !validComputeProfile(intent.Shape,
		intent.WholeOCPUs, intent.MemoryInGBs, intent.PlacementProfileDigest, intent.PlacementGeneration)) {
		return errors.New("OCI launch intent requires a complete signed compute profile")
	}
	if intent.Action == actionLaunch {
		if _, err := launchIntentDescriptor(intent); err != nil {
			return fmt.Errorf("OCI launch intent requires an exact public boot descriptor: %w", err)
		}
	}
	if intent.Action == actionVolumeAttach && (intent.ResourceID == "" || intent.VolumeID == "" ||
		intent.CreateKey == "" || !validDevicePath(intent.Device) ||
		intent.IsReadOnly != retainedVolumeReadOnly || intent.IsShareable != retainedVolumeShareable ||
		intent.IsPvEncryptionInTransitEnabled != retainedVolumeEncryptionInTransit) {
		return errors.New("OCI volume attachment intent requires a fixed device and attachment policy")
	}
	if intent.Action == actionVolumeResize && (intent.ResourceID == "" || intent.VolumeID != intent.ResourceID ||
		intent.CreateKey == "" || intent.ExpectedETag == "" || intent.AvailabilityDomain == "" ||
		intent.PreviousSizeGB <= 0 || intent.SizeGB <= intent.PreviousSizeGB || !validVolumeResizeKey(intent.Key, intent.VolumeID, intent.SizeGB)) {
		return errors.New("OCI volume resize intent requires an exact grow-only volume target")
	}
	if intent.Action != actionVolumeResize && intent.PreviousSizeGB != 0 {
		return errors.New("only OCI volume resize intents carry a previous size")
	}
	return nil
}

// validComputeProfile checks signed-profile completeness and exact SDK numeric
// representation. OCI remains authoritative for per-shape platform bounds;
// launch rejection stays unknown and cannot produce positive ownership.
func validComputeProfile(shape string, wholeOCPUs, memoryInGBs uint32, profileDigest string, placementGeneration uint64) bool {
	if !shapePattern.MatchString(shape) || wholeOCPUs == 0 || memoryInGBs == 0 || placementGeneration == 0 ||
		!isLowerHexSHA256(profileDigest) {
		return false
	}
	_, ocpusExact := exactFloat32(wholeOCPUs)
	_, memoryExact := exactFloat32(memoryInGBs)
	return ocpusExact && memoryExact
}

func exactFloat32(value uint32) (float32, bool) {
	converted := float32(value)
	return converted, float64(converted) == float64(value)
}

func isLowerHexSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func sameIntent(a, b OperationIntent) bool {
	return a.Action == b.Action && a.Key == b.Key && a.Region == b.Region && a.Generation == b.Generation &&
		a.Owner == b.Owner && a.ResourceID == b.ResourceID && a.CreateKey == b.CreateKey &&
		a.ExpectedETag == b.ExpectedETag && a.FaultDomain == b.FaultDomain && a.PrivateIP == b.PrivateIP && a.Shape == b.Shape &&
		a.WholeOCPUs == b.WholeOCPUs && a.MemoryInGBs == b.MemoryInGBs &&
		a.PlacementProfileDigest == b.PlacementProfileDigest && a.PlacementGeneration == b.PlacementGeneration &&
		a.ImageID == b.ImageID && a.BootDescriptor == b.BootDescriptor &&
		a.BootDescriptorSHA256 == b.BootDescriptorSHA256 &&
		a.VolumeID == b.VolumeID &&
		a.AvailabilityDomain == b.AvailabilityDomain && a.SizeGB == b.SizeGB && a.PreviousSizeGB == b.PreviousSizeGB &&
		a.Device == b.Device &&
		a.IsReadOnly == b.IsReadOnly && a.IsShareable == b.IsShareable &&
		a.IsPvEncryptionInTransitEnabled == b.IsPvEncryptionInTransitEnabled
}

func sameResult(a, b OperationResult) bool {
	return a.Intent.Action == b.Intent.Action && a.Intent.Key == b.Intent.Key && a.ResourceID == b.ResourceID &&
		a.ETag == b.ETag && a.Unknown == b.Unknown
}

func operationKey(intent OperationIntent) string {
	return entityid.Derive("oci-operation", intent.Owner, string(intent.Region), fmt.Sprint(intent.Generation), intent.Action, intent.Key)
}

func ownershipKey(kind, id string) string {
	return entityid.Derive("oci-ownership", kind, id)
}

func digest(parts ...string) string {
	hasher := sha256.New()
	for _, part := range parts {
		hasher.Write([]byte{0})
		hasher.Write([]byte(part))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
