package computeplan

import (
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func testComputeBinding() ComputeBinding {
	return ComputeBinding{
		Cell:                ComputeCellId{Value: "gru"},
		NodeClass:           NodeClassId{Value: "api"},
		Template:            NodeTemplateId{Value: "api-a1"},
		Shape:               ComputeShapeId{Value: "VM.Standard.A1.Flex"},
		Domain:              PlacementDomainId{Value: "AD-1"},
		Artifact:            ComputeArtifactId{Value: "database-api:v2"},
		ArtifactDigest:      ComputeDigestId{Value: "sha256:abcdef"},
		Demand:              DemandObservationId{Value: "demand-1"},
		Operation:           ComputeOperationId{Value: "scale-out-1"},
		ProviderFingerprint: ProviderFingerprintId{Value: "oci-gru"},
		Generation:          7,
		ControllerEpoch:     11,
	}
}

func testResourceEnvelope() ResourceEnvelope {
	return ResourceEnvelope{Ocpus: 2, MemoryMib: 8192, StorageGib: 50, EstimatedHourlyCostMicros: 42000}
}

func testScaleOutRequest() ScaleOutRequest {
	binding := testComputeBinding()
	resources := testResourceEnvelope()
	return ScaleOutRequest{
		Binding: binding,
		State:   ScaleOutStateDemandObserved,
		Demand: DemandEvidence{
			Binding:              binding,
			Trigger:              ComputeTriggerUnschedulable,
			ObservationSequence:  100,
			FreshThroughSequence: 100,
			RequiredNodes:        2,
			ExplicitDemand:       true,
			Sustained:            true,
		},
		Plan: ScaleOutPlan{
			Binding:      binding,
			Resources:    resources,
			DesiredNodes: 2,
			PlanIdentity: ComputeProofId{Value: "plan-proof"},
		},
		EvaluationSequence:    100,
		MaximumIdentityLength: 128,
	}
}

func testPersistedPlan(request *ScaleOutRequest) *PersistedScaleOutPlan {
	return &PersistedScaleOutPlan{Plan: request.Plan, PersistenceProof: ComputeProofId{Value: "persist-proof"}}
}

func testCapacityAuthorization(request *ScaleOutRequest) *CapacityAuthorization {
	return &CapacityAuthorization{
		Binding:           request.Binding,
		Resources:         request.Plan.Resources,
		AuthorizedNodes:   request.Plan.DesiredNodes,
		BudgetProof:       ComputeProofId{Value: "budget-proof"},
		QuotaProof:        ComputeProofId{Value: "quota-proof"},
		CapacityProof:     ComputeProofId{Value: "capacity-proof"},
		CostProof:         ComputeProofId{Value: "cost-proof"},
		PlacementProof:    ComputeProofId{Value: "placement-proof"},
		BudgetAllowed:     true,
		QuotaAllowed:      true,
		CapacityAvailable: true,
		CostAllowed:       true,
		PlacementAllowed:  true,
	}
}

func testCreateEvidence(request *ScaleOutRequest, status ProviderCreateStatus) *ProviderCreateEvidence {
	evidence := &ProviderCreateEvidence{
		Binding:          request.Binding,
		CreateKey:        ProviderCreateKey{Value: "create-key-1"},
		Status:           status,
		ObservationProof: ComputeProofId{Value: "create-observation"},
	}
	if status == ProviderCreateStatusOutcomeUnknown {
		workRequest := WorkRequestId{Value: "work-request-1"}
		evidence.WorkRequest = &workRequest
	}
	if status == ProviderCreateStatusCreated {
		resource := ProviderResourceId{Value: "instance-1"}
		workRequest := WorkRequestId{Value: "work-request-1"}
		evidence.Resource = &resource
		evidence.WorkRequest = &workRequest
	}
	return evidence
}

func proof(value string) *ComputeProofId {
	return &ComputeProofId{Value: value}
}

func testScaleOutProgress(request *ScaleOutRequest, state ScaleOutState) *ScaleOutProgress {
	resource := ProviderResourceId{Value: "instance-1"}
	node := ComputeNodeId{Value: "node-1"}
	progress := &ScaleOutProgress{Binding: request.Binding, Resource: &resource, Node: &node}
	if state >= ScaleOutStateInstanceCreated {
		progress.IdentityAttested = true
		progress.IdentityProof = proof("identity-proof")
	}
	if state >= ScaleOutStateEnrolled {
		progress.Enrolled = true
		progress.EnrollmentProof = proof("enrollment-proof")
		progress.BootstrapPassed = true
		progress.BootstrapProof = proof("bootstrap-proof")
		progress.DiskPassed = true
		progress.DiskProof = proof("disk-proof")
	}
	if state >= ScaleOutStateReady {
		progress.PlacementComplete = true
		progress.PlacementProof = proof("placement-proof")
		progress.ServiceHealthy = true
		progress.HealthProof = proof("health-proof")
	}
	return progress
}

func decisionIntentAction(t *testing.T, decision *ComputeDecision) ComputeAction {
	t.Helper()
	if decision == nil || len(decision.Intents) != 1 {
		t.Fatalf("decision has %d intents, want 1", len(decision.Intents))
	}
	return decision.Intents[0].computeIntentAction()
}

func assertHeld(t *testing.T, decision *ComputeDecision, code ComputeErrorCode) {
	t.Helper()
	if decision == nil || len(decision.Errors) != 1 || decision.Errors[0].Code != code {
		t.Fatalf("decision errors = %#v, want one error with code %d", decision.Errors, code)
	}
	if action := decisionIntentAction(t, decision); action != ComputeActionHold {
		t.Fatalf("held decision action = %d, want hold", action)
	}
}

func TestScaleOutReconciliationProgressesOneIntentAtATime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		state   ScaleOutState
		prepare func(*ScaleOutRequest)
		action  ComputeAction
	}{
		{name: "persist plan", state: ScaleOutStateDemandObserved, action: ComputeActionPersistPlan},
		{name: "authorize capacity", state: ScaleOutStatePlanPersisted, prepare: func(r *ScaleOutRequest) {
			r.PersistedPlan = testPersistedPlan(r)
		}, action: ComputeActionAuthorize},
		{name: "request create", state: ScaleOutStateAuthorized, prepare: func(r *ScaleOutRequest) {
			r.PersistedPlan = testPersistedPlan(r)
			r.Authorization = testCapacityAuthorization(r)
			r.CreateEvidence = testCreateEvidence(r, ProviderCreateStatusProvenAbsent)
		}, action: ComputeActionRequestCreate},
		{name: "observe unknown create", state: ScaleOutStateRequestRecorded, prepare: func(r *ScaleOutRequest) {
			r.PersistedPlan = testPersistedPlan(r)
			r.Authorization = testCapacityAuthorization(r)
			r.CreateEvidence = testCreateEvidence(r, ProviderCreateStatusOutcomeUnknown)
		}, action: ComputeActionObserve},
		{name: "enroll created node", state: ScaleOutStateInstanceCreated, prepare: func(r *ScaleOutRequest) {
			r.PersistedPlan = testPersistedPlan(r)
			r.Authorization = testCapacityAuthorization(r)
			r.CreateEvidence = testCreateEvidence(r, ProviderCreateStatusCreated)
			r.Progress = testScaleOutProgress(r, ScaleOutStateInstanceCreated)
		}, action: ComputeActionEnroll},
		{name: "ready enrolled node", state: ScaleOutStateEnrolled, prepare: func(r *ScaleOutRequest) {
			r.PersistedPlan = testPersistedPlan(r)
			r.Authorization = testCapacityAuthorization(r)
			r.CreateEvidence = testCreateEvidence(r, ProviderCreateStatusCreated)
			r.Progress = testScaleOutProgress(r, ScaleOutStateEnrolled)
		}, action: ComputeActionReady},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := testScaleOutRequest()
			request.State = test.state
			if test.prepare != nil {
				test.prepare(&request)
			}
			decision, err := ComputeEngine.DecideScaleOut(&request)
			if err != nil {
				t.Fatalf("DecideScaleOut returned error: %v", err)
			}
			if len(decision.Errors) != 0 {
				t.Fatalf("decision errors = %#v", decision.Errors)
			}
			if action := decisionIntentAction(t, decision); action != test.action {
				t.Fatalf("intent action = %d, want %d", action, test.action)
			}
			if decision.AcceptedScaleOutRequest != &request {
				t.Fatal("successful scale-out decision did not retain the accepted request")
			}
		})
	}
}

func TestScaleOutReadyAndCompletedStatesAreTerminal(t *testing.T) {
	t.Parallel()

	for _, state := range []ScaleOutState{ScaleOutStateReady, ScaleOutStateCompleted} {
		request := testScaleOutRequest()
		request.State = state
		request.PersistedPlan = testPersistedPlan(&request)
		request.Authorization = testCapacityAuthorization(&request)
		request.CreateEvidence = testCreateEvidence(&request, ProviderCreateStatusCreated)
		request.Progress = testScaleOutProgress(&request, ScaleOutStateReady)
		decision, err := ComputeEngine.DecideScaleOut(&request)
		if err != nil {
			t.Fatalf("state %d returned error: %v", state, err)
		}
		if len(decision.Intents) != 0 || len(decision.Errors) != 0 || len(decision.Trace) != 1 ||
			decision.Trace[0].Code != ComputeTraceCodeCompleted {
			t.Fatalf("state %d did not produce a completed decision: %#v", state, decision)
		}
	}
}

func TestScaleOutFailsClosedOnMissingOrDeniedEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*ScaleOutRequest)
		code   ComputeErrorCode
	}{
		{name: "invalid binding", change: func(r *ScaleOutRequest) { r.Binding.Cell.Value = "" }, code: ComputeErrorCodeInvalidInput},
		{name: "unspecified trigger", change: func(r *ScaleOutRequest) { r.Demand.Trigger = ComputeTriggerUnspecified }, code: ComputeErrorCodeInvalidInput},
		{name: "stale demand", change: func(r *ScaleOutRequest) {
			r.Demand.ObservationSequence = 99
			r.Demand.FreshThroughSequence = 99
		}, code: ComputeErrorCodeEvidenceStale},
		{name: "demand not sustained", change: func(r *ScaleOutRequest) { r.Demand.Sustained = false }, code: ComputeErrorCodeMissingProof},
		{name: "plan demand mismatch", change: func(r *ScaleOutRequest) { r.Plan.DesiredNodes = 3 }, code: ComputeErrorCodeEvidenceMismatch},
		{name: "unexpected persisted evidence", change: func(r *ScaleOutRequest) { r.PersistedPlan = testPersistedPlan(r) }, code: ComputeErrorCodeEvidenceMismatch},
		{name: "budget denied", change: func(r *ScaleOutRequest) {
			r.State = ScaleOutStateAuthorized
			r.PersistedPlan = testPersistedPlan(r)
			r.Authorization = testCapacityAuthorization(r)
			r.Authorization.BudgetAllowed = false
			r.CreateEvidence = testCreateEvidence(r, ProviderCreateStatusProvenAbsent)
		}, code: ComputeErrorCodeBudgetDenied},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := testScaleOutRequest()
			test.change(&request)
			decision, err := ComputeEngine.DecideScaleOut(&request)
			if err != nil {
				t.Fatalf("DecideScaleOut returned error: %v", err)
			}
			assertHeld(t, decision, test.code)
		})
	}
}

func TestScaleOutAllowsFreshBoundedSafetyReplacement(t *testing.T) {
	t.Parallel()

	request := testScaleOutRequest()
	request.Demand.Trigger = ComputeTriggerFailedHostReplacement
	request.Demand.ObservationSequence = request.EvaluationSequence - 1
	request.Demand.FreshThroughSequence = request.EvaluationSequence - 1
	request.Demand.Sustained = false
	request.Demand.SafetyBounded = true
	decision, err := ComputeEngine.DecideScaleOut(&request)
	if err != nil {
		t.Fatalf("DecideScaleOut returned error: %v", err)
	}
	if action := decisionIntentAction(t, decision); action != ComputeActionPersistPlan {
		t.Fatalf("bounded safety replacement action = %d", action)
	}
}

func TestScaleOutRejectsNilRequest(t *testing.T) {
	t.Parallel()
	if decision, err := ComputeEngine.DecideScaleOut(nil); err == nil || decision != nil {
		t.Fatalf("nil request result = decision %#v error %v", decision, err)
	} else {
		var argument *errs.Argument
		if !errors.As(err, &argument) || argument.Param != "request" ||
			argument.Error() != "Value cannot be null. (Parameter 'request')" {
			t.Fatalf("nil request error = %#v", err)
		}
	}
}
