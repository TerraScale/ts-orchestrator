package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type terminalTestControl struct {
	*placementAdmissionTestControl
	pending []authority.EnrollmentEffect
}

func (control terminalTestControl) ListPendingEnrollmentEffects(context.Context, authority.WorkloadScope) ([]authority.EnrollmentEffect, error) {
	return control.pending, nil
}

func (control terminalTestControl) CommitTerminalIntent(ctx context.Context, epoch uint64,
	scope authority.WorkloadScope, operationID string, payload []byte, settled func(context.Context) error,
) (uint64, error) {
	if epoch != control.snapshot.Epoch {
		return 0, authority.ErrFenced
	}
	key := scope.DatabaseID + "." + scope.PartitionID
	if _, exists := control.terminal[key]; exists {
		return 0, authority.ErrOperationConflict
	}
	if err := settled(ctx); err != nil {
		return 0, err
	}
	control.nextSeq++
	control.terminal[key] = authority.LogEntry{Kind: authority.MutationTerminalIntent,
		SubjectKey: key, OperationID: operationID, Epoch: epoch, Sequence: control.nextSeq,
		Payload: bytes.Clone(payload)}
	return control.nextSeq, nil
}

type terminalTestMembers struct {
	states []placement.VersionedMemberState
}

func (members terminalTestMembers) ListMembers(context.Context, string, string) ([]placement.VersionedMemberState, error) {
	return members.states, nil
}

type terminalTestInventory struct{ verifies int }

func (*terminalTestInventory) DiscoverTerminalTargets(_ context.Context, intent authority.TerminalIntent) ([]authority.TerminalTarget, error) {
	return intent.Targets, nil
}

func (inventory *terminalTestInventory) VerifyTerminalInventorySettled(_ context.Context, intent authority.TerminalIntent) error {
	inventory.verifies++
	return intent.Validate()
}

func (*terminalTestInventory) InspectTerminalStatus(context.Context, authority.TerminalIntent) (oci.TerminalStatus, error) {
	return oci.TerminalStatus{Phase: "complete"}, nil
}

func (*terminalTestInventory) ReconcileTerminal(context.Context, authority.TerminalIntent, uint64) (oci.TerminalStatus, error) {
	return oci.TerminalStatus{}, errors.New("status must not reconcile")
}

func TestTerminalPlanApplyAndStatusRequireSignedExactInventory(t *testing.T) {
	ctx := t.Context()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := buildSignerPolicy(Config{NATS: natscell.Config{Cell: "gru"},
		Controller: ControllerConfig{TrustedSigners: []TrustedSignerConfig{{
			Actor: "ops", PublicKey: base64.StdEncoding.EncodeToString(public),
			Roles: []string{"terrabase"}, Environments: []string{"production"}, CanTeardownTerraBase: true,
		}}}})
	if err != nil {
		t.Fatal(err)
	}
	placed := testManagedPlacementIntent()
	placementPayload, err := protocol.EncodeJSON(placed)
	if err != nil {
		t.Fatal(err)
	}
	control := terminalTestControl{placementAdmissionTestControl: newPlacementAdmissionControl()}
	control.entries[placed.DatabaseID+"."+placed.PartitionID] = authority.LogEntry{
		Kind: authority.MutationPlacementIntent, SubjectKey: placed.DatabaseID + "." + placed.PartitionID,
		OperationID: placed.OperationID(), Epoch: control.snapshot.Epoch, Sequence: 2, Payload: placementPayload,
	}
	region := oci.RegionConfig{Region: oci.RegionGRU, Generation: 1, Owner: "owner-a",
		CompartmentID: "ocid1.compartment.oc1..terminaltest",
		FaultDomains:  []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}}
	inventory := &terminalTestInventory{}
	request := terminalRequest{DatabaseID: placed.DatabaseID, PartitionID: placed.PartitionID,
		OperationID: "0000000000YTXFV0CFVPJ6FSQ7", Nonce: entityid.New()}
	sign := func(action, operationID string, generation uint64, payload any, issued, expires time.Time) []byte {
		t.Helper()
		encoded, err := protocol.EncodeJSON(payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.SignEnvelope(encoded, protocol.EnvelopeScope{
			Region: "gru", Kind: "placement.terminal." + action, Actor: "ops",
			OperationID: operationID, Generation: generation, Epoch: control.snapshot.Epoch,
		}, issued, expires, private)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.EncodeJSON(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	now := time.Now().UTC()
	fenceCalls := 0
	fence := func(context.Context, uint64, authority.TerminalIntent) error {
		fenceCalls++
		return nil
	}
	grantOK := func(context.Context, authority.TerminalIntent) error { return nil }
	proof := terminalGrantProof(grantOK)
	planWire := sign("plan", request.OperationID, 1, request, now, now.Add(time.Minute))
	plan, err := handleTerminalRequest(ctx, planWire, "plan", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK)
	if err != nil || plan.Intent == nil || len(plan.Intent.Targets) != 2 || plan.Intent.DisposableWorkload ||
		plan.Intent.AcknowledgePermanentDataLoss || plan.Intent.AuthorizeForcedStop || inventory.verifies != 0 {
		t.Fatalf("read-only terminal plan: %+v, %v", plan, err)
	}
	approved := *plan.Intent
	approved.DisposableWorkload = true
	approved.AcknowledgePermanentDataLoss = true
	approved.AuthorizeForcedStop = true
	tampered := approved
	tampered.Owner = "other-owner"
	badWire := sign("apply", tampered.OperationID, tampered.PlacementGeneration, tampered, now, now.Add(time.Minute))
	if _, err := handleTerminalRequest(ctx, badWire, "apply", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK); err == nil {
		t.Fatal("signed terminal grant with changed fleet owner was admitted")
	}
	expired := sign("apply", approved.OperationID, approved.PlacementGeneration, approved,
		now.Add(-10*time.Minute), now.Add(-9*time.Minute))
	if _, err := handleTerminalRequest(ctx, expired, "apply", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK); err == nil {
		t.Fatal("expired signed terminal grant was admitted")
	}
	if fenceCalls != 0 {
		t.Fatal("plan or rejected signed apply disabled grants before admission")
	}
	applyWire := sign("apply", approved.OperationID, approved.PlacementGeneration, approved, now, now.Add(time.Minute))
	control.pending = []authority.EnrollmentEffect{{EffectID: "0000000000F637JQA32HGV7PS4", InstanceID: "ocid1.instance.oc1..old",
		Epoch: 2, Sequence: 9, Phase: "pending"}}
	if _, err := handleTerminalRequest(ctx, applyWire, "apply", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK); err == nil {
		t.Fatal("terminal marker ignored an old-epoch pending enrollment effect")
	}
	control.pending = nil
	applied, err := handleTerminalRequest(ctx, applyWire, "apply", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK)
	if err != nil || applied.MarkerSequence == 0 || inventory.verifies != 1 {
		t.Fatalf("commit exact terminal marker: %+v, %v", applied, err)
	}
	if fenceCalls != 2 {
		t.Fatalf("exact grant fence calls = %d, want one held attempt and one accepted attempt", fenceCalls)
	}
	if _, err := handleTerminalRequest(ctx, planWire, "plan", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("new plan after marker = %v, want fenced", err)
	}
	statusRequest := terminalRequest{DatabaseID: request.DatabaseID, PartitionID: request.PartitionID,
		OperationID: "0000000000E4VAM0DX058W0Q36", Nonce: entityid.New()}
	statusWire := sign("status", statusRequest.OperationID, 1, statusRequest, now, now.Add(time.Minute))
	status, err := handleTerminalRequest(ctx, statusWire, "status", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof,
		func(context.Context, authority.TerminalIntent) error { return errors.New("grant remains active") })
	if err != nil || status.Status == nil || status.Status.Phase != "held" {
		t.Fatalf("status reported complete before grant disable: %+v, %v", status, err)
	}
	status, err = handleTerminalRequest(ctx, statusWire, "status", "gru", policy, control,
		region, terminalTestMembers{}, inventory, fence, proof, grantOK)
	if err != nil || status.Status == nil || status.Status.Phase != "complete" {
		t.Fatalf("status did not report verified completion: %+v, %v", status, err)
	}
}
