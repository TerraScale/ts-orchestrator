package computeplan

import (
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func testScaleInRequest() ScaleInRequest {
	compute := testComputeBinding()
	binding := ScaleInBinding{
		Compute:                  compute,
		Node:                     ComputeNodeId{Value: "node-1"},
		Resource:                 ProviderResourceId{Value: "instance-1"},
		LoadBalancerRegistration: LoadBalancerRegistrationId{Value: "backend-1"},
		Volume:                   ComputeVolumeId{Value: "boot-volume-1"},
		Role:                     ComputeNodeRoleElasticStateless,
	}
	authorization := ScaleInAuthorization{
		Binding:                binding,
		LowUseObservation:      DemandObservationId{Value: "low-use-1"},
		ObservationSequence:    200,
		FreshThroughSequence:   200,
		CurrentCount:           5,
		MinimumCount:           2,
		ReplacementCapacity:    2,
		AvailabilityHeadroom:   2,
		LowUseProof:            ComputeProofId{Value: "low-use-proof"},
		CooldownProof:          ComputeProofId{Value: "cooldown-proof"},
		LifetimeProof:          ComputeProofId{Value: "lifetime-proof"},
		CostBenefitProof:       ComputeProofId{Value: "cost-benefit-proof"},
		ControlHealthProof:     ComputeProofId{Value: "control-health-proof"},
		NatsHealthProof:        ComputeProofId{Value: "nats-health-proof"},
		AvailabilityProof:      ComputeProofId{Value: "availability-proof"},
		StatefulDisposition:    StatefulDispositionNotStateful,
		StatefulProof:          ComputeProofId{Value: "stateless-proof"},
		SustainedLowUse:        true,
		CooldownPassed:         true,
		LifetimePassed:         true,
		CostBenefitPassed:      true,
		RegionalControlHealthy: true,
		NatsHealthy:            true,
	}
	return ScaleInRequest{
		Binding:               binding,
		State:                 ScaleInStateCandidateSelected,
		Authorization:         authorization,
		Progress:              ScaleInProgress{Binding: binding, VolumeDisposition: VolumeDispositionDetachedEphemeral},
		EvaluationSequence:    200,
		MaximumIdentityLength: 128,
	}
}

func applyScaleInProgress(request *ScaleInRequest, state ScaleInState) {
	request.State = state
	progress := ScaleInProgress{Binding: request.Binding, VolumeDisposition: VolumeDispositionDetachedEphemeral}
	if state >= ScaleInStateCordoned {
		progress.Cordoned = true
		progress.CordonProof = proof("cordon-proof")
	}
	if state >= ScaleInStateDrained {
		progress.Drained = true
		progress.DrainProof = proof("drain-proof")
	}
	if state >= ScaleInStateDeregistered {
		progress.Deregistered = true
		progress.DeregistrationProof = proof("deregistration-proof")
	}
	if state >= ScaleInStateStorageHandled {
		progress.VolumeHandled = true
		progress.VolumeProof = proof("volume-proof")
	}
	if state >= ScaleInStateRevoked {
		progress.Revoked = true
		progress.RevocationProof = proof("revocation-proof")
	}
	if state >= ScaleInStateTerminated {
		progress.ExactInstanceTerminated = true
		progress.TerminationProof = proof("termination-proof")
		progress.BootVolumeAbsent = true
		progress.BootAbsenceProof = proof("boot-absence-proof")
	}
	if state >= ScaleInStateAudited {
		progress.OrphanAuditPassed = true
		progress.OrphanAuditProof = proof("orphan-audit-proof")
	}
	request.Progress = progress
}

func TestScaleInReconciliationProgressesOneIntentAtATime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  ScaleInState
		action ComputeAction
	}{
		{name: "cordon", state: ScaleInStateCandidateSelected, action: ComputeActionCordon},
		{name: "drain", state: ScaleInStateCordoned, action: ComputeActionDrain},
		{name: "deregister", state: ScaleInStateDrained, action: ComputeActionDeregister},
		{name: "detach", state: ScaleInStateDeregistered, action: ComputeActionDetach},
		{name: "revoke", state: ScaleInStateStorageHandled, action: ComputeActionRevoke},
		{name: "terminate", state: ScaleInStateRevoked, action: ComputeActionTerminate},
		{name: "audit", state: ScaleInStateTerminated, action: ComputeActionAudit},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := testScaleInRequest()
			applyScaleInProgress(&request, test.state)
			decision, err := ComputeEngine.DecideScaleIn(&request)
			if err != nil {
				t.Fatalf("DecideScaleIn returned error: %v", err)
			}
			if len(decision.Errors) != 0 {
				t.Fatalf("decision errors = %#v", decision.Errors)
			}
			if action := decisionIntentAction(t, decision); action != test.action {
				t.Fatalf("intent action = %d, want %d", action, test.action)
			}
		})
	}
}

func TestScaleInAuditedAndCompletedStatesAreTerminal(t *testing.T) {
	t.Parallel()

	for _, state := range []ScaleInState{ScaleInStateAudited, ScaleInStateCompleted} {
		request := testScaleInRequest()
		applyScaleInProgress(&request, state)
		decision, err := ComputeEngine.DecideScaleIn(&request)
		if err != nil {
			t.Fatalf("state %d returned error: %v", state, err)
		}
		if len(decision.Intents) != 0 || len(decision.Errors) != 0 ||
			len(decision.Trace) != 1 || decision.Trace[0].Code != ComputeTraceCodeCompleted {
			t.Fatalf("state %d did not produce completed decision: %#v", state, decision)
		}
	}
}

func TestScaleInFailsClosedOnUnsafeCapacityAndFencing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*ScaleInRequest)
		code   ComputeErrorCode
	}{
		{name: "unspecified role", change: func(r *ScaleInRequest) {
			r.Binding.Role = ComputeNodeRoleUnspecified
			r.Authorization.Binding = r.Binding
			r.Progress.Binding = r.Binding
		}, code: ComputeErrorCodeInvalidInput},
		{name: "stale evidence", change: func(r *ScaleInRequest) { r.Authorization.FreshThroughSequence-- }, code: ComputeErrorCodeEvidenceStale},
		{name: "conflicting operation", change: func(r *ScaleInRequest) { r.Authorization.ConflictingOperation = true }, code: ComputeErrorCodeConflictingOperation},
		{name: "cooldown missing", change: func(r *ScaleInRequest) { r.Authorization.CooldownPassed = false }, code: ComputeErrorCodeMissingProof},
		{name: "no cost benefit", change: func(r *ScaleInRequest) { r.Authorization.CostBenefitPassed = false }, code: ComputeErrorCodeCostDenied},
		{name: "control unhealthy", change: func(r *ScaleInRequest) { r.Authorization.RegionalControlHealthy = false }, code: ComputeErrorCodeAvailabilityDenied},
		{name: "at replica floor", change: func(r *ScaleInRequest) { r.Authorization.CurrentCount = r.Authorization.MinimumCount }, code: ComputeErrorCodeFloorDenied},
		{name: "stateful veto", change: func(r *ScaleInRequest) { r.Authorization.StatefulDisposition = StatefulDispositionVetoed }, code: ComputeErrorCodeStatefulVeto},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := testScaleInRequest()
			test.change(&request)
			decision, err := ComputeEngine.DecideScaleIn(&request)
			if err != nil {
				t.Fatalf("DecideScaleIn returned error: %v", err)
			}
			assertHeld(t, decision, test.code)
		})
	}
}

func TestScaleInStatefulRolesRequireRetainedOwnedStorage(t *testing.T) {
	t.Parallel()

	request := testScaleInRequest()
	request.Binding.Role = ComputeNodeRoleTerraBase
	request.Authorization.Binding = request.Binding
	request.Authorization.CurrentCount = 4
	request.Authorization.MinimumCount = 3
	request.Authorization.StatefulDisposition = StatefulDispositionApproved
	request.Authorization.StatefulApproved = true
	request.Progress.Binding = request.Binding
	decision, err := ComputeEngine.DecideScaleIn(&request)
	if err != nil {
		t.Fatalf("DecideScaleIn returned error: %v", err)
	}
	assertHeld(t, decision, ComputeErrorCodeStatefulVeto)

	owner := StatefulOwnerId{Value: "database-shard-1"}
	request.Progress.VolumeDisposition = VolumeDispositionRetainedStateful
	request.Progress.StatefulOwner = &owner
	decision, err = ComputeEngine.DecideScaleIn(&request)
	if err != nil {
		t.Fatalf("DecideScaleIn returned error: %v", err)
	}
	if action := decisionIntentAction(t, decision); action != ComputeActionCordon {
		t.Fatalf("stateful candidate action = %d, want cordon", action)
	}
}

func testSurvivalBundle(t *testing.T) *RegionalSurvivalBundle {
	t.Helper()
	bundle, err := NewRegionalSurvivalBundle(
		SurvivalBundleId{Value: "bundle-7"},
		ComputeCellId{Value: "gru"},
		7,
		ProviderFingerprintId{Value: "oci-gru"},
		ComputeArtifactId{Value: "database-api:v2"},
		ComputeDigestId{Value: "sha256:accepted"},
		ComputeProofId{Value: "accepted-signature"},
		ComputeArtifactId{Value: "database-api:v1"},
		ComputeDigestId{Value: "sha256:rollback"},
		ComputeProofId{Value: "rollback-signature"},
		[]SecretVersionId{{Value: "secret-v1"}, {Value: "secret-v2"}},
		[]SurvivalNodeTemplate{{
			NodeClass: NodeClassId{Value: "api"},
			Template:  NodeTemplateId{Value: "api-a1"},
			Shape:     ComputeShapeId{Value: "VM.Standard.A1.Flex"},
			Domain:    PlacementDomainId{Value: "AD-1"},
		}},
		TrustReferenceId{Value: "trust-1"},
		NatsReferenceId{Value: "nats-1"},
		DnsReferenceId{Value: "dns-1"},
		BackupReferenceId{Value: "backup-1"},
		11, 100, 90, 120, 140,
	)
	if err != nil {
		t.Fatalf("NewRegionalSurvivalBundle returned error: %v", err)
	}
	return bundle
}

func testSurvivalRequest(t *testing.T) SurvivalRequest {
	t.Helper()
	bundle := testSurvivalBundle(t)
	return SurvivalRequest{
		Required: bundle,
		Evidence: SurvivalBundleEvidence{
			Observed:          bundle,
			BundleSignature:   ComputeProofId{Value: "bundle-signature"},
			EncryptionProof:   ComputeProofId{Value: "encryption-proof"},
			SignatureValid:    true,
			MetadataEncrypted: true,
			ArtifactsLocal:    true,
			SecretsLocal:      true,
			ProviderReady:     true,
			TrustReady:        true,
			NatsReady:         true,
			DnsReady:          true,
			BackupReady:       true,
		},
		Authority: RegionalAuthorityProof{
			Cell:                bundle.Cell,
			AuthorityEpoch:      bundle.AuthorityEpoch,
			JournalPosition:     bundle.JournalPosition,
			Proof:               ComputeProofId{Value: "authority-proof"},
			QuorumAuthoritative: true,
		},
		CurrentAcceptedGeneration: bundle.Generation,
		EvaluationPosition:        110,
		MaximumIdentityLength:     128,
	}
}

func TestSurvivalReconciliationRequiresCompleteFreshAuthority(t *testing.T) {
	t.Parallel()

	request := testSurvivalRequest(t)
	decision, err := ComputeEngine.DecideSurvival(&request)
	if err != nil {
		t.Fatalf("DecideSurvival returned error: %v", err)
	}
	if action := decisionIntentAction(t, decision); action != ComputeActionReady {
		t.Fatalf("ready bundle action = %d", action)
	}

	tests := []struct {
		name   string
		change func(*SurvivalRequest)
		code   ComputeErrorCode
	}{
		{name: "signature invalid", change: func(r *SurvivalRequest) { r.Evidence.SignatureValid = false }, code: ComputeErrorCodeBundleIncomplete},
		{name: "bundle expired", change: func(r *SurvivalRequest) { r.EvaluationPosition = r.Required.ExpiresAfterPosition + 1 }, code: ComputeErrorCodeBundleExpired},
		{name: "authority cell mismatch", change: func(r *SurvivalRequest) { r.Authority.Cell.Value = "sfo" }, code: ComputeErrorCodeAuthorityDenied},
		{name: "authority not quorum", change: func(r *SurvivalRequest) { r.Authority.QuorumAuthoritative = false }, code: ComputeErrorCodeAuthorityDenied},
		{name: "unexpected target", change: func(r *SurvivalRequest) { target := testReplacementTarget(r.Required); r.ReplacementTarget = &target }, code: ComputeErrorCodeEvidenceMismatch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := testSurvivalRequest(t)
			test.change(&candidate)
			decision, err := ComputeEngine.DecideSurvival(&candidate)
			if err != nil {
				t.Fatalf("DecideSurvival returned error: %v", err)
			}
			assertHeld(t, decision, test.code)
		})
	}
}

func testReplacementTarget(bundle *RegionalSurvivalBundle) SurvivalReplacementTarget {
	template := bundle.Templates[0]
	return SurvivalReplacementTarget{
		Cell:                bundle.Cell,
		NodeClass:           template.NodeClass,
		Template:            template.Template,
		Shape:               template.Shape,
		Domain:              template.Domain,
		Artifact:            bundle.AcceptedArtifact,
		ArtifactDigest:      bundle.AcceptedDigest,
		Operation:           ComputeOperationId{Value: "replace-node-1"},
		ProviderFingerprint: bundle.ProviderFingerprint,
		CreateKey:           ProviderCreateKey{Value: "create-replacement-1"},
		BundleGeneration:    bundle.Generation,
		ControllerEpoch:     bundle.AuthorityEpoch,
	}
}

func TestSurvivalReplacementIsFencedToAcceptedBundle(t *testing.T) {
	t.Parallel()

	request := testSurvivalRequest(t)
	target := testReplacementTarget(request.Required)
	request.DisconnectedReplacementRequested = true
	request.ReplacementTarget = &target
	decision, err := ComputeEngine.DecideSurvival(&request)
	if err != nil {
		t.Fatalf("DecideSurvival returned error: %v", err)
	}
	if action := decisionIntentAction(t, decision); action != ComputeActionAuthorize {
		t.Fatalf("replacement action = %d, want authorize", action)
	}

	target.ControllerEpoch--
	request.ReplacementTarget = &target
	decision, err = ComputeEngine.DecideSurvival(&request)
	if err != nil {
		t.Fatalf("DecideSurvival returned error: %v", err)
	}
	assertHeld(t, decision, ComputeErrorCodeInvalidInput)
}

func TestSurvivalBundleOwnsInputSlices(t *testing.T) {
	t.Parallel()

	secrets := []SecretVersionId{{Value: "secret-v1"}}
	templates := []SurvivalNodeTemplate{{NodeClass: NodeClassId{Value: "api"}, Template: NodeTemplateId{Value: "api-a1"}, Shape: ComputeShapeId{Value: "shape"}, Domain: PlacementDomainId{Value: "domain"}}}
	bundle, err := NewRegionalSurvivalBundle(SurvivalBundleId{Value: "bundle"}, ComputeCellId{Value: "gru"}, 1,
		ProviderFingerprintId{Value: "provider"}, ComputeArtifactId{Value: "accepted"}, ComputeDigestId{Value: "accepted-digest"}, ComputeProofId{Value: "accepted-signature"},
		ComputeArtifactId{Value: "rollback"}, ComputeDigestId{Value: "rollback-digest"}, ComputeProofId{Value: "rollback-signature"},
		secrets, templates, TrustReferenceId{Value: "trust"}, NatsReferenceId{Value: "nats"}, DnsReferenceId{Value: "dns"}, BackupReferenceId{Value: "backup"},
		1, 2, 1, 3, 4)
	if err != nil {
		t.Fatalf("NewRegionalSurvivalBundle returned error: %v", err)
	}
	secrets[0].Value = "changed"
	templates[0].Template.Value = "changed"
	if bundle.EncryptedSecretVersions[0].Value != "secret-v1" || bundle.Templates[0].Template.Value != "api-a1" {
		t.Fatal("survival bundle retained caller slices")
	}
}

func TestComputeIdentityValidationAndSnapshotBounds(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "has space", "line\nbreak", "control\x7f"} {
		if computeValid(value, 128) {
			t.Fatalf("unsafe identity %q accepted", value)
		}
	}
	if !computeValid("valid-id", 128) || computeValid("too-long", 3) {
		t.Fatal("identity length validation is incorrect")
	}
	if _, err := computeInputSnapshotCopy[int](nil, 1, "items", "items"); err == nil {
		t.Fatal("nil input snapshot accepted")
	} else {
		var argument *errs.Argument
		if !errors.As(err, &argument) || argument.Param != "items" ||
			argument.Error() != "Value cannot be null. (Parameter 'items')" {
			t.Fatalf("nil input snapshot error = %#v", err)
		}
	}
	if _, err := computeInputSnapshotCopy([]int{1, 2}, 1, "items", "items"); err == nil {
		t.Fatal("oversized input snapshot accepted")
	} else {
		var argument *errs.Argument
		if !errors.As(err, &argument) || argument.Param != "items" ||
			argument.Error() != "items exceeds the technical snapshot bound." {
			t.Fatalf("oversized input snapshot error = %#v", err)
		}
	}
	source := []int{1}
	copyOfSource, err := computeInputSnapshotCopy(source, 1, "items", "items")
	if err != nil {
		t.Fatalf("valid input snapshot rejected: %v", err)
	}
	source[0] = 2
	if copyOfSource[0] != 1 {
		t.Fatal("input snapshot retained caller slice")
	}
}
