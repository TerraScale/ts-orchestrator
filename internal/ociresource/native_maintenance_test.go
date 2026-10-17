package ociresource

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// These are inert metadata fixtures; they supply no positive source, SDK wire,
// dispatch, native process, Activation or protected writer authority.
func nativeMaintenanceMetadata(t *testing.T) NativeMaintenanceProgress {
	t.Helper()
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	w := NativeMaintenanceWorkflow{Cell: "GRU", Unit: "terrascale-orchestrator-controller.service", InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.metadata",
		SourceSHA256: strings.Repeat("a", 64), ChannelSHA256: strings.Repeat("b", 64), FromDigest: strings.Repeat("c", 64), ToDigest: strings.Repeat("d", 64),
		StartedAt: now, ExpiresAt: now.Add(time.Minute)}
	w.OperationID = entityid.Derive("native-orchestrator-maintenance", w.Cell, w.Unit, w.InstanceID, w.SourceSHA256, w.ChannelSHA256, w.FromDigest, w.ToDigest)
	phase := NativeMaintenancePhase{Kind: NativeMaintenanceDrain, RequestSHA256: strings.Repeat("e", 64),
		CallSHA256: strings.Repeat("1", 64), CandidateID: entityid.Derive("metadata-candidate"), Epoch: 1, SourceSHA256: strings.Repeat("f", 64),
		ReservedAt: now, DispatchBefore: now.Add(time.Second)}
	phase.PhaseID = entityid.Derive("native-maintenance-phase", w.OperationID, string(phase.Kind), phase.RequestSHA256)
	progress := NativeMaintenanceProgress{Revision: 1, Workflow: w, Phases: []NativeMaintenancePhase{phase}}
	if err := progress.Validate(); err != nil {
		t.Fatal(err)
	}
	return progress
}

func TestNativeMaintenanceMetadataRetainsOriginalEffectReservation(t *testing.T) {
	previous := nativeMaintenanceMetadata(t)
	for _, field := range []string{"deadline", "caller", "candidate", "epoch", "request", "source", "workflow", "prune"} {
		t.Run(field, func(t *testing.T) {
			next := previous
			next.Revision++
			next.Phases = slices.Clone(previous.Phases)
			switch field {
			case "deadline":
				next.Phases[0].DispatchBefore = next.Phases[0].DispatchBefore.Add(time.Second)
			case "caller":
				next.Phases[0].CallSHA256 = strings.Repeat("2", 64)
			case "candidate":
				next.Phases[0].CandidateID = entityid.Derive("successor-metadata-candidate")
			case "epoch":
				next.Phases[0].Epoch++
			case "request":
				next.Phases[0].RequestSHA256 = strings.Repeat("3", 64)
				next.Phases[0].PhaseID = entityid.Derive("native-maintenance-phase", next.Workflow.OperationID, string(next.Phases[0].Kind), next.Phases[0].RequestSHA256)
			case "source":
				next.Phases[0].SourceSHA256 = strings.Repeat("4", 64)
			case "workflow":
				next.Workflow.ExpiresAt = next.Workflow.ExpiresAt.Add(time.Second)
			case "prune":
				next.Phases = nil
			}
			if err := ValidateNativeMaintenanceTransition(previous, next); err == nil {
				t.Fatal("successor replaced original native reservation metadata")
			}
		})
	}
}

func TestNativeMaintenanceMetadataCannotAdvanceFromAcknowledgement(t *testing.T) {
	progress := nativeMaintenanceMetadata(t)
	phase := &progress.Phases[0]
	phase.PossibleSendAt = phase.ReservedAt.Add(100 * time.Millisecond)
	phase.AcknowledgedAt = phase.PossibleSendAt.Add(100 * time.Millisecond)
	phase.AmbiguousAt = phase.AcknowledgedAt
	if err := progress.Validate(); err != nil {
		t.Fatal(err)
	}
	observed := NativeMaintenancePhase{Kind: NativeMaintenanceDrainObserved, CallSHA256: phase.CallSHA256,
		CandidateID: phase.CandidateID, Epoch: phase.Epoch, SourceSHA256: phase.SourceSHA256,
		ReservedAt: phase.DispatchBefore, DispatchBefore: phase.DispatchBefore.Add(time.Second)}
	observed.PhaseID = entityid.Derive("native-maintenance-phase", progress.Workflow.OperationID, string(observed.Kind), "")
	var err error
	observed.PredecessorSHA256, err = nativeMaintenancePhaseSHA256(*phase)
	if err != nil {
		t.Fatal(err)
	}
	progress.Phases = append(progress.Phases, observed)
	if err := progress.Validate(); err == nil {
		t.Fatal("acknowledgement and ambiguity fabricated a terminal predecessor")
	}
	progress.Phases[0].SucceededAt = phase.AcknowledgedAt
	progress.Phases[0].EvidenceSHA256 = strings.Repeat("5", 64)
	progress.Phases[1].PredecessorSHA256, err = nativeMaintenancePhaseSHA256(progress.Phases[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := progress.Validate(); err != nil {
		t.Fatal(err)
	}
	progress.Phases[1].PossibleSendAt = progress.Phases[1].ReservedAt
	if err := progress.Validate(); err == nil {
		t.Fatal("observational phase acquired dispatch metadata")
	}
}

func TestNativeMaintenanceMetadataPreservesExpiredUnsettledHistory(t *testing.T) {
	progress := nativeMaintenanceMetadata(t)
	source := ResourceSource{ControllerConfigSHA256: strings.Repeat("6", 64), GrantSHA256: strings.Repeat("7", 64)}
	previous := ProtectedJournal{Revision: 1, Source: source, NativeMaintenance: map[string]NativeMaintenanceProgress{progress.Workflow.OperationID: progress}}
	if err := previous.Validate("GRU"); err != nil {
		t.Fatal(err)
	}
	next := previous
	next.Revision++
	next.NativeMaintenance = nil
	if err := ValidateNativeMaintenanceHistory(previous, next); err == nil {
		t.Fatal("expired unknown native operation was pruned")
	}
	next.NativeMaintenance = maps.Clone(previous.NativeMaintenance)
	other := progress
	other.Workflow.ChannelSHA256 = strings.Repeat("8", 64)
	w := other.Workflow
	other.Workflow.OperationID = entityid.Derive("native-orchestrator-maintenance", w.Cell, w.Unit, w.InstanceID, w.SourceSHA256, w.ChannelSHA256, w.FromDigest, w.ToDigest)
	other.Phases = slices.Clone(progress.Phases)
	other.Phases[0].PhaseID = entityid.Derive("native-maintenance-phase", other.Workflow.OperationID, string(other.Phases[0].Kind), other.Phases[0].RequestSHA256)
	next.NativeMaintenance[other.Workflow.OperationID] = other
	if err := next.Validate("GRU"); err == nil {
		t.Fatal("new channel bypassed the expired unsettled physical target")
	}
	delete(next.NativeMaintenance, other.Workflow.OperationID)
	if err := ValidateNativeMaintenanceHistory(previous, next); err != nil {
		t.Fatal(err)
	}
}

func TestNativeMaintenanceMetadataRetainsPossibleSendWithoutReplay(t *testing.T) {
	previous := nativeMaintenanceMetadata(t)
	previous.Phases[0].PossibleSendAt = previous.Phases[0].ReservedAt.Add(100 * time.Millisecond)
	previous.Phases[0].AmbiguousAt = previous.Phases[0].PossibleSendAt.Add(100 * time.Millisecond)
	for _, field := range []string{"remove send", "replace send", "remove ambiguity", "new caller"} {
		t.Run(field, func(t *testing.T) {
			next := previous
			next.Revision++
			next.Phases = slices.Clone(previous.Phases)
			switch field {
			case "remove send":
				next.Phases[0].PossibleSendAt = time.Time{}
			case "replace send":
				next.Phases[0].PossibleSendAt = next.Phases[0].PossibleSendAt.Add(time.Millisecond)
			case "remove ambiguity":
				next.Phases[0].AmbiguousAt = time.Time{}
			case "new caller":
				replayed := previous.Phases[0]
				replayed.CallSHA256 = strings.Repeat("9", 64)
				next.Phases = append(next.Phases, replayed)
			}
			if err := ValidateNativeMaintenanceTransition(previous, next); err == nil {
				t.Fatal("unknown original dispatch was removed or reserved again")
			}
		})
	}
}

func TestNativeMaintenanceMetadataRestartBindsPreparedActivation(t *testing.T) {
	progress := nativeMaintenanceMetadata(t)
	for _, kind := range []NativeMaintenancePhaseKind{NativeMaintenanceDrainObserved, NativeMaintenancePrepared, NativeMaintenanceRestart} {
		previous := &progress.Phases[len(progress.Phases)-1]
		if previous.Kind.effect() {
			previous.PossibleSendAt = previous.ReservedAt.Add(100 * time.Millisecond)
		}
		previous.SucceededAt = previous.ReservedAt.Add(200 * time.Millisecond)
		previous.EvidenceSHA256 = strings.Repeat("9", 64)
		hash, err := nativeMaintenancePhaseSHA256(*previous)
		if err != nil {
			t.Fatal(err)
		}
		phase := NativeMaintenancePhase{Kind: kind, PredecessorSHA256: hash, CallSHA256: previous.CallSHA256,
			CandidateID: previous.CandidateID, Epoch: previous.Epoch, SourceSHA256: previous.SourceSHA256,
			ReservedAt: previous.DispatchBefore, DispatchBefore: previous.DispatchBefore.Add(time.Second)}
		if kind == NativeMaintenancePrepared {
			progress.ActivationID = entityid.Derive("metadata-activation")
			progress.ActivationSHA256 = strings.Repeat("8", 64)
		}
		if kind == NativeMaintenanceRestart {
			phase.RequestSHA256 = progress.ActivationSHA256
		}
		phase.PhaseID = entityid.Derive("native-maintenance-phase", progress.Workflow.OperationID, string(kind), phase.RequestSHA256)
		progress.Phases = append(progress.Phases, phase)
	}
	if err := progress.Validate(); err != nil {
		t.Fatal(err)
	}
	restart := &progress.Phases[len(progress.Phases)-1]
	restart.RequestSHA256 = strings.Repeat("7", 64)
	restart.PhaseID = entityid.Derive("native-maintenance-phase", progress.Workflow.OperationID, string(restart.Kind), restart.RequestSHA256)
	if err := progress.Validate(); err == nil {
		t.Fatal("restart metadata substituted another local activation")
	}
}
