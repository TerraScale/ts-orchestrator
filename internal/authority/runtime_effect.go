package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

const (
	RuntimeEffectHeld    = "held"
	RuntimeEffectClosing = "closing"
	RuntimeEffectSettled = "settled"
)

var runtimeObjectID = regexp.MustCompile(`^[a-z0-9]{25}$`)

// RuntimeEffect is a retained execution hold, not task scheduling state. Epoch
// is the original grant epoch, even when a later leader closes or settles it.
type RuntimeEffect struct {
	EffectID               string        `json:"effect_id"`
	Scope                  WorkloadScope `json:"scope"`
	RegistrationID         string        `json:"registration_id"`
	HostSessionID          string        `json:"host_session_id"`
	WorkerPublicKey        string        `json:"worker_public_key"`
	NATSUserPublicKey      string        `json:"nats_user_public_key"`
	RegistrationGeneration uint64        `json:"registration_generation"`
	InstanceID             string        `json:"instance_id"`
	NodeID                 string        `json:"node_id"`
	TaskID                 string        `json:"task_id"`
	ServiceID              string        `json:"service_id"`
	TaskSHA256             string        `json:"task_sha256"`
	AdmissionSHA256        string        `json:"admission_sha256"`
	Material               []byte        `json:"material"`
	MaterialSHA256         string        `json:"material_sha256"`
	Epoch                  uint64        `json:"epoch"`
	IssuedAt               time.Time     `json:"issued_at"`
	ExpiresAt              time.Time     `json:"expires_at"`
	Phase                  string        `json:"phase"`
	Sequence               uint64        `json:"-"`
}

func (effect RuntimeEffect) validate() error {
	if _, err := enrollmentEffectSubjectKey(effect.Scope, effect.EffectID); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(effect.WorkerPublicKey)
	materialDigest := sha256.Sum256(effect.Material)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != effect.WorkerPublicKey ||
		!nkeys.IsValidPublicUserKey(effect.NATSUserPublicKey) || !entityid.Valid(effect.RegistrationID) || !entityid.Valid(effect.HostSessionID) || effect.RegistrationGeneration == 0 ||
		!strings.HasPrefix(effect.InstanceID, "ocid1.instance.") || len(effect.InstanceID) > 255 || strings.ContainsAny(effect.InstanceID, " \t\r\n") ||
		!runtimeObjectID.MatchString(effect.NodeID) || !runtimeObjectID.MatchString(effect.TaskID) || !runtimeObjectID.MatchString(effect.ServiceID) ||
		!validTerminalDigest(effect.TaskSHA256) || !validTerminalDigest(effect.AdmissionSHA256) || effect.Epoch == 0 ||
		len(effect.Material) == 0 || len(effect.Material) > maxControlPayload || hex.EncodeToString(materialDigest[:]) != effect.MaterialSHA256 ||
		effect.IssuedAt.IsZero() || effect.IssuedAt.Location() != time.UTC || effect.ExpiresAt.Location() != time.UTC || !effect.ExpiresAt.After(effect.IssuedAt) ||
		effect.Phase != RuntimeEffectHeld && effect.Phase != RuntimeEffectClosing && effect.Phase != RuntimeEffectSettled {
		return errors.New("runtime effect identity, lifetime or phase is invalid")
	}
	return nil
}

func runtimeEffectBytes(effect RuntimeEffect) ([]byte, string, error) {
	if err := effect.validate(); err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(effect, json.Deterministic(true))
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(payload)
	return payload, entityid.Derive("runtime-effect", effect.EffectID, hex.EncodeToString(digest[:])), nil
}

func decodeRuntimeEffect(entry LogEntry, scope WorkloadScope, effectID string) (RuntimeEffect, error) {
	key, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil || entry.Kind != MutationRuntimeEffect || entry.SubjectKey != key || entry.Sequence == 0 {
		return RuntimeEffect{}, errors.New("runtime effect log identity is invalid")
	}
	var effect RuntimeEffect
	if err := json.Unmarshal(entry.Payload, &effect, json.RejectUnknownMembers(true)); err != nil {
		return RuntimeEffect{}, err
	}
	payload, operationID, err := runtimeEffectBytes(effect)
	if err != nil || !bytes.Equal(payload, entry.Payload) || operationID != entry.OperationID || effect.Scope != scope || effect.EffectID != effectID ||
		entry.Epoch < effect.Epoch || effect.Phase == RuntimeEffectHeld && entry.Epoch != effect.Epoch {
		return RuntimeEffect{}, errors.New("runtime effect payload differs from its durable identity")
	}
	effect.Sequence = entry.Sequence
	return effect, nil
}

func (r *Runtime) readRuntimeEffect(ctx context.Context, scope WorkloadScope, effectID string) (RuntimeEffect, error) {
	key, err := enrollmentEffectSubjectKey(scope, effectID)
	if err != nil {
		return RuntimeEffect{}, err
	}
	entry, err := r.ReadHostMutation(ctx, MutationRuntimeEffect, key)
	if err != nil {
		return RuntimeEffect{}, err
	}
	return decodeRuntimeEffect(entry, scope, effectID)
}

func (r *Runtime) runtimeEffectLease(effect RuntimeEffect, epoch uint64) error {
	current := r.Current()
	if !current.CanMutate() || current.Epoch != epoch || effect.Epoch != epoch || effect.IssuedAt.After(time.Now()) ||
		!time.Now().Before(effect.ExpiresAt) || effect.ExpiresAt.After(current.ExpiresAt) {
		return ErrFenced
	}
	return nil
}

func (r *Runtime) writeRuntimeEffect(ctx context.Context, epoch uint64, effect RuntimeEffect, expected uint64, verify func(context.Context) error) (uint64, error) {
	payload, operationID, err := runtimeEffectBytes(effect)
	if err != nil {
		return 0, err
	}
	key, _ := enrollmentEffectSubjectKey(effect.Scope, effect.EffectID)
	return r.commitMutationVerified(ctx, epoch, MutationRuntimeEffect, key, operationID, expected, payload, verify)
}

// BeginRuntimeEffect journals a possible execution before its grant is delivered.
// Overlapping unresolved host or task sessions cannot escape an earlier hold.
func (r *Runtime) BeginRuntimeEffect(ctx context.Context, epoch uint64, effect RuntimeEffect) (uint64, error) {
	effect.Material = bytes.Clone(effect.Material)
	if effect.Phase != RuntimeEffectHeld || effect.Sequence != 0 {
		return 0, errors.New("runtime effect must begin held without a committed sequence")
	}
	if err := effect.validate(); err != nil {
		return 0, err
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	if err := r.runtimeEffectLease(effect, epoch); err != nil {
		return 0, err
	}
	return r.writeRuntimeEffect(ctx, epoch, effect, 0, func(check context.Context) error {
		if err := r.runtimeEffectLease(effect, epoch); err != nil {
			return err
		}
		if err := r.requireNoTerminalIntent(check, effect.Scope.DatabaseID, effect.Scope.PartitionID); err != nil {
			return err
		}
		pending, err := r.ListUnresolvedRuntimeEffects(check, effect.Scope)
		if err != nil {
			return err
		}
		for _, prior := range pending {
			if prior.EffectID != effect.EffectID && (prior.RegistrationID == effect.RegistrationID || prior.InstanceID == effect.InstanceID ||
				prior.NodeID == effect.NodeID || prior.TaskID == effect.TaskID) {
				return ErrOperationConflict
			}
		}
		return r.runtimeEffectLease(effect, epoch)
	})
}

// RenewRuntimeEffect extends only a still-live grant in its original epoch.
func (r *Runtime) RenewRuntimeEffect(ctx context.Context, epoch uint64, effect RuntimeEffect, expected uint64) (uint64, error) {
	effect.Material = bytes.Clone(effect.Material)
	prior, err := r.readRuntimeEffect(ctx, effect.Scope, effect.EffectID)
	if err != nil {
		return 0, err
	}
	identity := prior
	identity.ExpiresAt, identity.Sequence = effect.ExpiresAt, effect.Sequence
	if expected == 0 || effect.Phase != RuntimeEffectHeld || prior.Phase != RuntimeEffectHeld || prior.Epoch != epoch ||
		!reflect.DeepEqual(identity, effect) || effect.ExpiresAt.Before(prior.ExpiresAt) || !time.Now().Before(prior.ExpiresAt) {
		return 0, ErrFenced
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	if err := r.runtimeEffectLease(effect, epoch); err != nil {
		return 0, err
	}
	return r.writeRuntimeEffect(ctx, epoch, effect, expected, func(check context.Context) error {
		if !time.Now().Before(prior.ExpiresAt) {
			return ErrFenced
		}
		if err := r.runtimeEffectLease(effect, epoch); err != nil {
			return err
		}
		if err := r.requireNoTerminalIntent(check, effect.Scope.DatabaseID, effect.Scope.PartitionID); err != nil {
			return err
		}
		if !time.Now().Before(prior.ExpiresAt) {
			return ErrFenced
		}
		return r.runtimeEffectLease(effect, epoch)
	})
}

// CloseRuntimeEffect permanently prevents renewal but retains the execution hold.
func (r *Runtime) CloseRuntimeEffect(ctx context.Context, epoch uint64, scope WorkloadScope, effectID string, expected uint64) (uint64, error) {
	effect, err := r.readRuntimeEffect(ctx, scope, effectID)
	if err != nil {
		return 0, err
	}
	if expected == 0 || effect.Phase == RuntimeEffectSettled {
		return 0, ErrFenced
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	if effect.Phase == RuntimeEffectClosing {
		if effect.Sequence != expected {
			return 0, ErrConflict
		}
		return effect.Sequence, nil
	}
	effect.Phase = RuntimeEffectClosing
	return r.writeRuntimeEffect(ctx, epoch, effect, expected, func(check context.Context) error {
		return r.requireNoTerminalIntent(check, scope.DatabaseID, scope.PartitionID)
	})
}

// SettleRuntimeEffect requires expiration and independent stopped proof on every
// global CAS attempt. Closing, an absent task or an expired grant alone is no proof.
func (r *Runtime) SettleRuntimeEffect(ctx context.Context, epoch uint64, scope WorkloadScope, effectID string, expected uint64,
	verifyStopped func(context.Context, RuntimeEffect) error,
) (uint64, error) {
	if expected == 0 || verifyStopped == nil {
		return 0, errors.New("runtime effect settlement requires its sequence and stopped verifier")
	}
	effect, err := r.readRuntimeEffect(ctx, scope, effectID)
	if err != nil {
		return 0, err
	}
	if err := r.Guard(ctx, epoch); err != nil {
		return 0, err
	}
	if effect.Phase == RuntimeEffectSettled {
		return effect.Sequence, nil
	}
	if effect.Sequence != expected {
		return 0, ErrConflict
	}
	if time.Now().Before(effect.ExpiresAt) {
		return 0, ErrFenced
	}
	proof := effect
	effect.Phase = RuntimeEffectSettled
	return r.writeRuntimeEffect(ctx, epoch, effect, expected, func(check context.Context) error {
		return verifyStopped(check, proof)
	})
}

// ListUnresolvedRuntimeEffects includes every held or closing effect across epochs.
// Unreadable or malformed retained records fail closed, including settled history.
func (r *Runtime) ListUnresolvedRuntimeEffects(ctx context.Context, scope WorkloadScope) ([]RuntimeEffect, error) {
	effects, err := r.ListRuntimeEffectHistory(ctx, scope)
	return slices.DeleteFunc(effects, func(effect RuntimeEffect) bool { return effect.Phase == RuntimeEffectSettled }), err
}

// ListRuntimeEffectHistory returns each effect's latest retained record,
// including settled material needed to recover prior possible writers.
func (r *Runtime) ListRuntimeEffectHistory(ctx context.Context, scope WorkloadScope) ([]RuntimeEffect, error) {
	if _, err := placementIntentSubjectKey(scope.DatabaseID, scope.PartitionID); err != nil {
		return nil, err
	}
	return r.listRuntimeEffects(ctx, scope.DatabaseID+"."+scope.PartitionID+".")
}

// ListAllUnresolvedRuntimeEffects recovers holds even after their host's
// registration has retired or disappeared from the live host inventory.
func (r *Runtime) ListAllUnresolvedRuntimeEffects(ctx context.Context) ([]RuntimeEffect, error) {
	effects, err := r.listRuntimeEffects(ctx, "")
	return slices.DeleteFunc(effects, func(effect RuntimeEffect) bool { return effect.Phase == RuntimeEffectSettled }), err
}

func (r *Runtime) listRuntimeEffects(ctx context.Context, scopeFilter string) ([]RuntimeEffect, error) {
	if r == nil || r.readStream == nil {
		return nil, ErrFenced
	}
	r.readMu.Lock()
	defer r.readMu.Unlock()
	prefix := fmt.Sprintf("%s.%s.placement.runtime.", controlSubjectRoot, r.config.Scope)
	info, err := r.readStream.Info(ctx, jetstream.WithSubjectFilter(prefix+scopeFilter+">"))
	if err != nil {
		return nil, err
	}
	if err := verifyControlStreamConfig(info.Config, r.config.Replicas); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		key, ok := strings.CutPrefix(subject, prefix)
		if !ok || validateMutationKey(MutationRuntimeEffect, key) != nil {
			return nil, errors.New("runtime effect subject is invalid")
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var effects []RuntimeEffect
	for _, key := range keys {
		parts := strings.Split(key, ".")
		scope := WorkloadScope{DatabaseID: parts[0], PartitionID: parts[1]}
		entry, err := readMutation(ctx, r.readStream, r.config.Scope, MutationRuntimeEffect, key)
		if err != nil {
			return nil, err
		}
		effect, err := decodeRuntimeEffect(entry, scope, parts[2])
		if err != nil {
			return nil, err
		}
		effects = append(effects, effect)
	}
	return effects, nil
}

func (r *Runtime) requireNoRuntimeEffects(ctx context.Context, scope WorkloadScope) error {
	effects, err := r.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil {
		return err
	}
	if len(effects) != 0 {
		return ErrFenced
	}
	return nil
}
