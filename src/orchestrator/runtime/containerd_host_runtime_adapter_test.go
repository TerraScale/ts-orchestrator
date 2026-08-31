package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordingContainerdClient struct {
	operations   []string
	pulledDigest string
	created      *ContainerdCreateRequest
	observation  ContainerdAllocationObservation
}

func newRecordingContainerdClient() *recordingContainerdClient {
	absent := "terrascale-gru-platform-1"
	return &recordingContainerdClient{
		pulledDigest: hostRuntimePlanDigest,
		observation: ContainerdAllocationObservation{
			ContainerId: absent,
			State:       ContainerdAllocationStateAbsent,
			Detail:      "absent",
		},
	}
}

func (c *recordingContainerdClient) Observe(ctx context.Context, namespace, containerId string) (ContainerdAllocationObservation, error) {
	c.operations = append(c.operations, "observe")
	return c.observation, nil
}

func (c *recordingContainerdClient) Pull(ctx context.Context, namespace, imageReference, platform string) (string, error) {
	c.operations = append(c.operations, "pull")
	return c.pulledDigest, nil
}

func (c *recordingContainerdClient) Create(ctx context.Context, request ContainerdCreateRequest) error {
	c.operations = append(c.operations, "create")
	created := request
	c.created = &created
	return nil
}

func (c *recordingContainerdClient) Start(ctx context.Context, namespace, containerId string) error {
	c.operations = append(c.operations, "start")
	return nil
}

func (c *recordingContainerdClient) Stop(ctx context.Context, namespace, containerId string) error {
	c.operations = append(c.operations, "stop")
	return nil
}

func (c *recordingContainerdClient) Delete(ctx context.Context, namespace, containerId string) error {
	c.operations = append(c.operations, "delete")
	return nil
}

func (c *recordingContainerdClient) operationsEqual(expected []string) bool {
	if len(c.operations) != len(expected) {
		return false
	}
	counts := map[string]int{}
	for _, operation := range c.operations {
		counts[operation]++
	}
	for _, operation := range expected {
		counts[operation]--
		if counts[operation] < 0 {
			return false
		}
	}
	return true
}

func containerdTestOciPlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleDashboard,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "gru-dashboard-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func TestAbsentAllocationIsPulledByDigestCreatedWithSecurityAndStarted(t *testing.T) {
	client := newRecordingContainerdClient()
	plan := containerdTestOciPlan(t)

	adapter := NewContainerdHostRuntimeAdapter(client)
	if err := adapter.Converge(context.Background(), plan); err != nil {
		t.Fatalf("converge: %v", err)
	}

	if !client.operationsEqual([]string{"observe", "pull", "create", "start"}) {
		t.Fatalf("unexpected operations %v", client.operations)
	}
	if client.created.Namespace != "terrascale" {
		t.Fatalf("unexpected namespace %q", client.created.Namespace)
	}
	if !strings.Contains(client.created.ImageReference, "@sha256:") {
		t.Fatalf("unexpected image reference %q", client.created.ImageReference)
	}
	if client.created.Security.RunAsUser != 65532 {
		t.Fatalf("unexpected run-as user %d", client.created.Security.RunAsUser)
	}
	if !client.created.Security.NoNewPrivileges || !client.created.Security.ReadOnlyRootFileSystem {
		t.Fatal("created allocation must be hardened")
	}
	if len(client.created.Security.DroppedCapabilities) != 1 || client.created.Security.DroppedCapabilities[0] != "ALL" {
		t.Fatalf("unexpected dropped capabilities %v", client.created.Security.DroppedCapabilities)
	}
	if client.created.Resources != plan.Resources {
		t.Fatalf("resources mismatch: %+v", client.created.Resources)
	}
	if client.created.Resources.MemorySwapMaxBytes() != 0 {
		t.Fatal("swap must be zero")
	}
	if len(client.created.PlanFingerprint) != 64 {
		t.Fatalf("fingerprint must be 64 hex chars, got %d", len(client.created.PlanFingerprint))
	}
}

func TestExistingForeignAllocationIsFencedInsteadOfReplaced(t *testing.T) {
	plan := containerdTestOciPlan(t)
	imageReference := plan.Oci.ImageReference
	platform := plan.Oci.Platform
	containerId := plan.Oci.ContainerId
	fingerprint := "foreign"
	client := newRecordingContainerdClient()
	client.observation = ContainerdAllocationObservation{
		ContainerId:     containerId,
		State:           ContainerdAllocationStateRunning,
		ImageReference:  &imageReference,
		Platform:        &platform,
		PlanFingerprint: &fingerprint,
		ProcessId:       ptrInt(123),
		Detail:          "running",
	}

	adapter := NewContainerdHostRuntimeAdapter(client)
	var operationError *InvalidOperationError
	err := adapter.Converge(context.Background(), plan)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if !client.operationsEqual([]string{"observe"}) {
		t.Fatalf("unexpected operations %v", client.operations)
	}
}

func TestExistingAllocationWithADifferentContainerIdIsFenced(t *testing.T) {
	plan := containerdTestOciPlan(t)
	imageReference := plan.Oci.ImageReference
	platform := plan.Oci.Platform
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	otherID := "terrascale-other-allocation"
	client := newRecordingContainerdClient()
	client.observation = ContainerdAllocationObservation{
		ContainerId:     otherID,
		State:           ContainerdAllocationStateRunning,
		ImageReference:  &imageReference,
		Platform:        &platform,
		PlanFingerprint: &fingerprint,
	}
	var operationError *InvalidOperationError
	if err := NewContainerdHostRuntimeAdapter(client).Converge(context.Background(), plan); !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
}

func ptrInt(value int) *int { return &value }

func TestPulledManifestMustMatchTheRequestedImmutableDigest(t *testing.T) {
	client := newRecordingContainerdClient()
	client.pulledDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	adapter := NewContainerdHostRuntimeAdapter(client)
	var operationError *InvalidOperationError
	err := adapter.Converge(context.Background(), containerdTestOciPlan(t))
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if !client.operationsEqual([]string{"observe", "pull"}) {
		t.Fatalf("unexpected operations %v", client.operations)
	}
}

func TestCanonicalFingerprintChangesWhenSecurityIsTampered(t *testing.T) {
	original := containerdTestOciPlan(t)
	tampered := original
	tamperedOci := *original.Oci
	tamperedSecurity := original.Oci.Security
	tamperedSecurity.NoNewPrivileges = false
	tamperedOci.Security = tamperedSecurity
	tampered.Oci = &tamperedOci

	originalFingerprint, err := CanonicalPlanFingerprint.Compute(original)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	tamperedFingerprint, err := CanonicalPlanFingerprint.Compute(tampered)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if originalFingerprint == tamperedFingerprint {
		t.Fatal("tampering the security plan must change the fingerprint")
	}
	adapter := NewContainerdHostRuntimeAdapter(newRecordingContainerdClient())
	var operationError *InvalidOperationError
	if err := adapter.Converge(context.Background(), tampered); !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
}

func TestWrongSchemaVersionIsRejectedBeforeAnyClientOperation(t *testing.T) {
	client := newRecordingContainerdClient()
	tampered := containerdTestOciPlan(t)
	tampered.SchemaVersion = 1

	adapter := NewContainerdHostRuntimeAdapter(client)
	var operationError *InvalidOperationError
	err := adapter.Converge(context.Background(), tampered)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if len(client.operations) != 0 {
		t.Fatalf("no client operation may run: %v", client.operations)
	}
}
