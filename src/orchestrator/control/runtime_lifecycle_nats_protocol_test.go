package control

import (
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/runtime"
)

func legacyV1TerraBaseCheckpoint(t *testing.T) RuntimeLifecycleCheckpoint {
	t.Helper()
	checkpoint := RuntimeLifecycleCheckpoint{
		SchemaVersion:               RuntimeLifecycleContractSchemaVersion,
		OperationKey:                RuntimeLifecycleOperationKey{Value: strings.Repeat("a", 64)},
		Cell:                        RuntimeLifecycleCellId{RuntimeToken{Value: "gru"}},
		Node:                        RuntimeNodeId{RuntimeToken{Value: "node-1"}},
		AllocationId:                "terrabase-1",
		WorkloadGeneration:          RuntimeGeneration{PositiveRuntimeNumber{Value: 1}},
		AcceptedConvergenceDigest:   RuntimeDigest{Sha256: strings.Repeat("b", 64)},
		PlanFingerprint:             RuntimeLifecyclePlanFingerprint{Value: strings.Repeat("c", 64)},
		Driver:                      runtime.RuntimeDriverNativeSystemd,
		Role:                        HostRole(1),
		Action:                      LifecycleActionConverge,
		Phase:                       RuntimeLifecyclePhaseProposed,
		WriterEpoch:                 RuntimeEpoch{PositiveRuntimeNumber{Value: 1}},
		AuthorizationEvidenceDigest: RuntimeDigest{Sha256: strings.Repeat("d", 64)},
		ExecutorAttempt:             RuntimeAttempt{PositiveRuntimeNumber{Value: 1}},
		DispatchToken:               RuntimeDigest{Sha256: strings.Repeat("e", 64)},
		CallStatus:                  RuntimeLifecycleCallStatusNotCalled,
		DeadlineEvidence: RuntimeLifecycleDeadlineEvidence{
			Digest: RuntimeDigest{Sha256: strings.Repeat("f", 64)}, Watermark: 1,
		},
		CompensationPolicy:  RuntimeLifecycleCompensationPolicyNone,
		JournalRevision:     1,
		PreviousEventDigest: RuntimeDigest{Sha256: strings.Repeat("0", 64)},
		TerminalStatus:      RuntimeLifecycleTerminalStatusNone,
		ErrorCode:           RuntimeLifecycleErrorCodeNone,
	}
	digest, err := RuntimeLifecycleFingerprint.Event(checkpoint)
	if err != nil {
		t.Fatalf("legacy checkpoint digest: %v", err)
	}
	checkpoint.EventDigest = digest
	return checkpoint
}

func TestLegacyV1CheckpointKeepsTerraBaseRoleMeaning(t *testing.T) {
	checkpoint := legacyV1TerraBaseCheckpoint(t)
	const legacyEventDigest = "a9e8c64a7d8fd09388e26f79bddffdd999bbdbb4f16fb5bc1d231b5704e3b1ac"
	if checkpoint.EventDigest.Sha256 != legacyEventDigest {
		t.Fatalf("legacy event digest = %s, want %s", checkpoint.EventDigest.Sha256, legacyEventDigest)
	}
	encoded, err := RuntimeLifecycleNatsProtocol.Serialize(checkpoint)
	if err != nil {
		t.Fatalf("serialize legacy checkpoint: %v", err)
	}
	if !strings.Contains(encoded, `"Role":1`) {
		t.Fatalf("legacy TerraBase role was not encoded as 1: %s", encoded)
	}

	restored, ok := RuntimeLifecycleNatsProtocol.TryDeserialize(encoded)
	if !ok {
		t.Fatal("legacy checkpoint did not deserialize")
	}
	if restored.Role != runtime.AdmittedRoleTerraBaseMember {
		t.Fatalf("legacy role 1 restored as %v", restored.Role)
	}
	if !RuntimeLifecycleNatsProtocol.IsCheckpoint(&restored, "gru",
		RuntimeLifecycleNatsProtocol.Key(restored.OperationKey), 1) {
		t.Fatal("legacy TerraBase checkpoint failed validation")
	}
}

func TestRetiredV1RoleValueDoesNotAcquireNewMeaning(t *testing.T) {
	checkpoint := legacyV1TerraBaseCheckpoint(t)
	checkpoint.Role = HostRole(4)
	digest, err := RuntimeLifecycleFingerprint.Event(checkpoint)
	if err != nil {
		t.Fatalf("retired-role checkpoint digest: %v", err)
	}
	checkpoint.EventDigest = digest

	encoded, err := RuntimeLifecycleNatsProtocol.Serialize(checkpoint)
	if err != nil {
		t.Fatalf("serialize retired-role checkpoint: %v", err)
	}
	restored, ok := RuntimeLifecycleNatsProtocol.TryDeserialize(encoded)
	if !ok {
		t.Fatal("canonical retired-role checkpoint did not deserialize")
	}
	if RuntimeLifecycleNatsProtocol.IsCheckpoint(&restored, "gru",
		RuntimeLifecycleNatsProtocol.Key(restored.OperationKey), 1) {
		t.Fatal("retired v1 role 4 was admitted as a new workload role")
	}
}

func TestV1DigestAndLifecycleLengthsUseUTF16CodeUnits(t *testing.T) {
	writer := newDigestWriter()
	writer.WriteString("a\U0001F680")
	if got, want := writer.Finish(), "S3:a\U0001F680;"; got != want {
		t.Fatalf("digest encoding = %q, want %q", got, want)
	}

	var canonical strings.Builder
	canonicalStrings(&canonical, []string{"a\U0001F680"})
	if got, want := canonical.String(), "3:a\U0001F680;"; got != want {
		t.Fatalf("lifecycle encoding = %q, want %q", got, want)
	}
}
