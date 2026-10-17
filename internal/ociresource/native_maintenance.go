package ociresource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// NativeMaintenanceWorkflow records provenance only. Constructing or validating
// this metadata never admits a caller or authorizes a maintenance effect.
type NativeMaintenanceWorkflow struct {
	OperationID   string    `json:"operationId"`
	Cell          string    `json:"cell"`
	Unit          string    `json:"unit"`
	InstanceID    string    `json:"instanceId"`
	SourceSHA256  string    `json:"sourceSha256"`
	ChannelSHA256 string    `json:"channelSha256"`
	FromDigest    string    `json:"fromDigest"`
	ToDigest      string    `json:"toDigest"`
	StartedAt     time.Time `json:"startedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type NativeMaintenancePhaseKind string

const (
	NativeMaintenanceDrain          NativeMaintenancePhaseKind = "drain"
	NativeMaintenanceDrainObserved  NativeMaintenancePhaseKind = "drain_observed"
	NativeMaintenancePrepared       NativeMaintenancePhaseKind = "prepared"
	NativeMaintenanceRestart        NativeMaintenancePhaseKind = "restart"
	NativeMaintenanceTargetObserved NativeMaintenancePhaseKind = "target_observed"
	NativeMaintenanceRestore        NativeMaintenancePhaseKind = "restore"
	NativeMaintenanceSettled        NativeMaintenancePhaseKind = "settled"
)

// NativeMaintenancePhase retains one reservation's first caller and deadline.
// Drain/restore request hashes bind ONE actual SDK wire attempt; restart binds
// the exact correlated Activation. Outcomes require independent genuine sources.
type NativeMaintenancePhase struct {
	Kind              NativeMaintenancePhaseKind `json:"kind"`
	PhaseID           string                     `json:"phaseId"`
	RequestSHA256     string                     `json:"requestSha256,omitempty"`
	PredecessorSHA256 string                     `json:"predecessorSha256,omitempty"`
	CallSHA256        string                     `json:"callSha256"`
	CandidateID       string                     `json:"candidateId"`
	Epoch             uint64                     `json:"epoch"`
	SourceSHA256      string                     `json:"sourceSha256"`
	ReservedAt        time.Time                  `json:"reservedAt"`
	DispatchBefore    time.Time                  `json:"dispatchBefore"`
	PossibleSendAt    time.Time                  `json:"possibleSendAt,omitzero"`
	AcknowledgedAt    time.Time                  `json:"acknowledgedAt,omitzero"`
	AmbiguousAt       time.Time                  `json:"ambiguousAt,omitzero"`
	SucceededAt       time.Time                  `json:"succeededAt,omitzero"`
	EvidenceSHA256    string                     `json:"evidenceSha256,omitempty"`
}

// NativeMaintenanceProgress lives only inside the existing protected foundation
// object. It is neither a source witness nor a transferable phase capability.
type NativeMaintenanceProgress struct {
	Revision         uint64                    `json:"revision"`
	Workflow         NativeMaintenanceWorkflow `json:"workflow"`
	ActivationID     string                    `json:"activationId,omitempty"`
	ActivationSHA256 string                    `json:"activationSha256,omitempty"`
	Phases           []NativeMaintenancePhase  `json:"phases"`
}

func (kind NativeMaintenancePhaseKind) order() int {
	switch kind {
	case NativeMaintenanceDrain:
		return 0
	case NativeMaintenanceDrainObserved:
		return 1
	case NativeMaintenancePrepared:
		return 2
	case NativeMaintenanceRestart:
		return 3
	case NativeMaintenanceTargetObserved:
		return 4
	case NativeMaintenanceRestore:
		return 5
	case NativeMaintenanceSettled:
		return 6
	default:
		return -1
	}
}

func (kind NativeMaintenancePhaseKind) effect() bool {
	return kind == NativeMaintenanceDrain || kind == NativeMaintenanceRestart || kind == NativeMaintenanceRestore
}

func nativeMaintenanceDigest(value string) bool {
	wire, err := hex.DecodeString(value)
	return err == nil && len(wire) == sha256.Size && hex.EncodeToString(wire) == value
}

func nativeMaintenancePhaseSHA256(phase NativeMaintenancePhase) (string, error) {
	wire, err := json.Marshal(phase, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// Validate checks retained metadata, including expired history, without turning
// an acknowledged dispatch or a missing old process into terminal success.
func (progress NativeMaintenanceProgress) Validate() error {
	w := progress.Workflow
	if progress.Revision == 0 || !entityid.Valid(w.OperationID) || w.Cell == "" || len(w.Cell) > 16 ||
		w.Unit != "terrascale-orchestrator-controller.service" || !strings.HasPrefix(w.InstanceID, "ocid1.instance.") || len(w.InstanceID) > 512 ||
		!nativeMaintenanceDigest(w.SourceSHA256) || !nativeMaintenanceDigest(w.ChannelSHA256) ||
		!nativeMaintenanceDigest(w.FromDigest) || !nativeMaintenanceDigest(w.ToDigest) || w.FromDigest == w.ToDigest ||
		w.StartedAt.IsZero() || !w.ExpiresAt.After(w.StartedAt) || len(progress.Phases) == 0 {
		return errors.New("native maintenance has invalid original workflow metadata")
	}
	if w.OperationID != entityid.Derive("native-orchestrator-maintenance", w.Cell, w.Unit, w.InstanceID, w.SourceSHA256, w.ChannelSHA256, w.FromDigest, w.ToDigest) {
		return errors.New("native maintenance changed its original workflow identity")
	}
	if (progress.ActivationID == "") != (progress.ActivationSHA256 == "") ||
		progress.ActivationID != "" && (!entityid.Valid(progress.ActivationID) || !nativeMaintenanceDigest(progress.ActivationSHA256)) {
		return errors.New("native maintenance has invalid activation correlation")
	}
	seen := make(map[string]bool)
	prepared := false
	for index, phase := range progress.Phases {
		order := phase.Kind.order()
		if order < 0 || !entityid.Valid(phase.PhaseID) || seen[phase.PhaseID] ||
			!nativeMaintenanceDigest(phase.CallSHA256) || !entityid.Valid(phase.CandidateID) || phase.Epoch == 0 ||
			!nativeMaintenanceDigest(phase.SourceSHA256) || phase.ReservedAt.Before(w.StartedAt) ||
			!phase.DispatchBefore.After(phase.ReservedAt) || phase.DispatchBefore.After(w.ExpiresAt) {
			return errors.New("native maintenance reservation lost its original caller, source or deadline")
		}
		seen[phase.PhaseID] = true
		if phase.PhaseID != entityid.Derive("native-maintenance-phase", w.OperationID, string(phase.Kind), phase.RequestSHA256) {
			return errors.New("native maintenance reservation changed its exact request identity")
		}
		if index == 0 {
			if phase.Kind != NativeMaintenanceDrain || phase.PredecessorSHA256 != "" {
				return errors.New("native maintenance must begin with its original drain reservation")
			}
		} else {
			previous := progress.Phases[index-1]
			previousHash, err := nativeMaintenancePhaseSHA256(previous)
			repeated := order == previous.Kind.order() && (phase.Kind == NativeMaintenanceDrain || phase.Kind == NativeMaintenanceRestore)
			if err != nil || previous.SucceededAt.IsZero() || phase.PredecessorSHA256 != previousHash ||
				phase.ReservedAt.Before(previous.SucceededAt) || !repeated && order != previous.Kind.order()+1 {
				return errors.New("native maintenance lacks exact terminal predecessor readback")
			}
		}
		if phase.Kind.effect() {
			if !nativeMaintenanceDigest(phase.RequestSHA256) {
				return errors.New("native maintenance effect lacks its exact original request")
			}
			if phase.Kind == NativeMaintenanceRestart && (progress.ActivationID == "" || phase.RequestSHA256 != progress.ActivationSHA256) {
				return errors.New("native restart lacks the prepared activation correlation")
			}
		} else if phase.RequestSHA256 != "" || !phase.PossibleSendAt.IsZero() || !phase.AcknowledgedAt.IsZero() || !phase.AmbiguousAt.IsZero() {
			return errors.New("native maintenance observation cannot dispatch an effect")
		}
		if phase.Kind == NativeMaintenancePrepared && progress.ActivationID == "" {
			return errors.New("native maintenance preparation lacks an activation identity")
		}
		prepared = prepared || phase.Kind == NativeMaintenancePrepared
		if !phase.PossibleSendAt.IsZero() && (phase.PossibleSendAt.Before(phase.ReservedAt) || !phase.PossibleSendAt.Before(phase.DispatchBefore)) {
			return errors.New("native maintenance send exceeds its original reservation deadline")
		}
		for _, outcome := range []time.Time{phase.AcknowledgedAt, phase.AmbiguousAt} {
			if !outcome.IsZero() && (phase.PossibleSendAt.IsZero() || outcome.Before(phase.PossibleSendAt) || outcome.After(w.ExpiresAt)) {
				return errors.New("native maintenance outcome lacks its original possible-send checkpoint")
			}
		}
		if phase.SucceededAt.IsZero() != (phase.EvidenceSHA256 == "") || !phase.SucceededAt.IsZero() &&
			(!nativeMaintenanceDigest(phase.EvidenceSHA256) || phase.SucceededAt.Before(phase.ReservedAt) || phase.SucceededAt.After(w.ExpiresAt) ||
				phase.Kind.effect() && (phase.PossibleSendAt.IsZero() || phase.SucceededAt.Before(phase.PossibleSendAt))) {
			return errors.New("native maintenance success lacks independent terminal evidence")
		}
	}
	if prepared != (progress.ActivationID != "") {
		return errors.New("native maintenance activation correlation precedes its preparation")
	}
	return nil
}

// ValidateNativeMaintenanceTransition checks only immutable history. Production
// writers must separately derive and guard actual opaque sources before a CAS.
func ValidateNativeMaintenanceTransition(previous, next NativeMaintenanceProgress) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if previous.Workflow != next.Workflow || next.Revision <= previous.Revision || len(next.Phases) < len(previous.Phases) ||
		previous.ActivationID != "" && (previous.ActivationID != next.ActivationID || previous.ActivationSHA256 != next.ActivationSHA256) {
		return errors.New("native maintenance original workflow, activation or history changed")
	}
	for index, retained := range previous.Phases {
		current := next.Phases[index]
		if !retained.SucceededAt.IsZero() && !reflect.DeepEqual(retained, current) {
			return errors.New("native maintenance terminal predecessor evidence changed")
		}
		for _, field := range []struct{ before, after time.Time }{
			{retained.PossibleSendAt, current.PossibleSendAt}, {retained.AcknowledgedAt, current.AcknowledgedAt},
			{retained.AmbiguousAt, current.AmbiguousAt}, {retained.SucceededAt, current.SucceededAt},
		} {
			if !field.before.IsZero() && !field.before.Equal(field.after) {
				return errors.New("native maintenance original outcome was removed or replaced")
			}
		}
		retained.PossibleSendAt, current.PossibleSendAt = time.Time{}, time.Time{}
		retained.AcknowledgedAt, current.AcknowledgedAt = time.Time{}, time.Time{}
		retained.AmbiguousAt, current.AmbiguousAt = time.Time{}, time.Time{}
		retained.SucceededAt, current.SucceededAt = time.Time{}, time.Time{}
		retained.EvidenceSHA256, current.EvidenceSHA256 = "", ""
		if !reflect.DeepEqual(retained, current) {
			return errors.New("native maintenance original request, caller, source or first deadline changed")
		}
	}
	return nil
}

// ValidateNativeMaintenanceHistory prevents another protected-resource update
// from removing or replacing an unresolved native operation, even after expiry.
func ValidateNativeMaintenanceHistory(previous, next ProtectedJournal) error {
	for operation, retained := range previous.NativeMaintenance {
		current, found := next.NativeMaintenance[operation]
		if !found {
			return errors.New("protected native maintenance history was removed")
		}
		if reflect.DeepEqual(retained, current) {
			continue
		}
		if err := ValidateNativeMaintenanceTransition(retained, current); err != nil {
			return err
		}
	}
	return nil
}
