// This file tests the rootless-podman host runtime adapter of the
// rootless-hosting and autoscaling lane: idempotent convergence, label
// fencing, and the stop/delete state matrix, all against a recording fake
// PodmanClient. No podman binary is ever executed here.
package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recordingPodmanClient struct {
	operations     []string
	observation    PodmanAllocationObservation
	inspectError   error
	preflightError error
	pullError      error
	createError    error
	startError     error
	stopError      error
	deleteError    error
	ensureError    error
	created        *PodmanRunRequest
	pulledImage    string
	pulledPlatform string
	ensuredVolumes []string
	startedIds     []string
	stoppedIds     []string
	deletedIds     []string
}

func (c *recordingPodmanClient) Preflight(ctx context.Context) error {
	c.operations = append(c.operations, "preflight")
	return c.preflightError
}

func (c *recordingPodmanClient) Pull(ctx context.Context, imageReference string, platform string) error {
	c.operations = append(c.operations, "pull")
	c.pulledImage = imageReference
	c.pulledPlatform = platform
	return c.pullError
}

func (c *recordingPodmanClient) Create(ctx context.Context, request PodmanRunRequest) error {
	c.operations = append(c.operations, "create")
	created := request
	c.created = &created
	return c.createError
}

func (c *recordingPodmanClient) Start(ctx context.Context, containerId string) error {
	c.operations = append(c.operations, "start")
	c.startedIds = append(c.startedIds, containerId)
	return c.startError
}

func (c *recordingPodmanClient) Stop(ctx context.Context, containerId string) error {
	c.operations = append(c.operations, "stop")
	c.stoppedIds = append(c.stoppedIds, containerId)
	return c.stopError
}

func (c *recordingPodmanClient) Delete(ctx context.Context, containerId string) error {
	c.operations = append(c.operations, "delete")
	c.deletedIds = append(c.deletedIds, containerId)
	return c.deleteError
}

func (c *recordingPodmanClient) Inspect(ctx context.Context, containerId string) (PodmanAllocationObservation, error) {
	c.operations = append(c.operations, "inspect")
	return c.observation, c.inspectError
}

func (c *recordingPodmanClient) EnsureVolume(ctx context.Context, name string) error {
	c.operations = append(c.operations, "ensure-volume")
	c.ensuredVolumes = append(c.ensuredVolumes, name)
	return c.ensureError
}

func podmanTestOciPlan(t *testing.T) HostRuntimePlan {
	t.Helper()
	plan, err := NewHostRuntimePlan(
		AdmittedRoleLoki,
		RuntimeDriverOciContainer,
		mustRuntimeAllocationId(t, "gru-loki-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureX64,
		nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan
}

func podmanTestVolumes() []PodmanVolumeMount {
	return []PodmanVolumeMount{
		{VolumeName: "loki-gru-1", Destination: "/var/lib/loki", ReadOnly: false},
		{VolumeName: "loki-gru-1-rules", Destination: "/etc/loki/rules", ReadOnly: true},
	}
}

func newPodmanTestAdapter(t *testing.T, client *recordingPodmanClient) *PodmanRootlessHostRuntimeAdapter {
	t.Helper()
	adapter, err := NewPodmanRootlessHostRuntimeAdapter(client, podmanTestVolumes())
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return adapter
}

func podmanFencedObservation(
	t *testing.T,
	plan HostRuntimePlan,
	state PodmanAllocationState,
	labels map[string]string,
) PodmanAllocationObservation {
	t.Helper()
	if state == PodmanAllocationStateAbsent {
		observation, err := NewPodmanAllocationObservation(state, "", nil, false)
		if err != nil {
			t.Fatalf("observation: %v", err)
		}
		return observation
	}
	observation, err := NewPodmanAllocationObservation(
		state, plan.Oci.ImageReference, labels, state == PodmanAllocationStateRunning, plan.Oci.Platform)
	if err != nil {
		t.Fatalf("observation: %v", err)
	}
	return observation
}

func podmanMatchingLabels(t *testing.T, plan HostRuntimePlan) map[string]string {
	t.Helper()
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return map[string]string{
		PodmanLabelAllocation:  plan.AllocationId.Value,
		PodmanLabelFingerprint: fingerprint,
	}
}

func TestPodmanConvergeAbsentRunsPreflightEnsuresVolumesPullsCreatesAndStarts(t *testing.T) {
	client := &recordingPodmanClient{
		observation: podmanFencedObservation(t, podmanTestOciPlan(t), PodmanAllocationStateAbsent, nil),
	}
	plan := podmanTestOciPlan(t)
	adapter := newPodmanTestAdapter(t, client)

	if err := adapter.Converge(context.Background(), plan); err != nil {
		t.Fatalf("converge: %v", err)
	}

	if !stringSlicesEqual(client.operations,
		[]string{"preflight", "inspect", "ensure-volume", "ensure-volume", "pull", "create", "start"}) {
		t.Fatalf("unexpected operations %v", client.operations)
	}
	if !stringSlicesEqual(client.ensuredVolumes, []string{"loki-gru-1", "loki-gru-1-rules"}) {
		t.Fatalf("unexpected ensured volumes %v", client.ensuredVolumes)
	}
	if client.pulledImage != plan.Oci.ImageReference || client.pulledPlatform != plan.Oci.Platform {
		t.Fatalf("pulled %q for %q", client.pulledImage, client.pulledPlatform)
	}
	if !stringSlicesEqual(client.startedIds, []string{plan.Oci.ContainerId}) {
		t.Fatalf("unexpected started ids %v", client.startedIds)
	}

	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	created := client.created
	if created == nil {
		t.Fatal("the run request must be created")
	}
	if created.ContainerId != plan.Oci.ContainerId {
		t.Fatalf("container id = %q", created.ContainerId)
	}
	if created.ImageReference != plan.Oci.ImageReference || !strings.Contains(created.ImageReference, "@sha256:") {
		t.Fatalf("image reference = %q", created.ImageReference)
	}
	if created.Platform != plan.Oci.Platform {
		t.Fatalf("platform = %q", created.Platform)
	}
	if created.RunAsUser != plan.Oci.Security.RunAsUser || created.RunAsGroup != plan.Oci.Security.RunAsGroup {
		t.Fatalf("run-as identity = %d:%d", created.RunAsUser, created.RunAsGroup)
	}
	if created.CgroupParent != plan.Oci.Security.CgroupParent {
		t.Fatalf("cgroup parent = %q", created.CgroupParent)
	}
	if !stringSlicesEqual(created.CapDrop, plan.Oci.Security.DroppedCapabilities) {
		t.Fatalf("capability drops = %v", created.CapDrop)
	}
	if !created.ReadOnlyRootfs || !created.NoNewPrivileges {
		t.Fatal("the created allocation must be hardened")
	}
	if created.MemoryMaxBytes != plan.Resources.MemoryMaxBytes {
		t.Fatalf("memory limit = %d", created.MemoryMaxBytes)
	}
	if created.PidsLimit != plan.Resources.TasksMax {
		t.Fatalf("pids limit = %d", created.PidsLimit)
	}
	if created.CpuQuotaPercent != plan.Resources.CpuQuotaPercent ||
		created.CpuWeight != plan.Resources.CpuWeight {
		t.Fatalf("cpu limits = %d/%d", created.CpuQuotaPercent, created.CpuWeight)
	}
	if len(created.Volumes) != len(podmanTestVolumes()) {
		t.Fatalf("volume mounts = %v", created.Volumes)
	}
	if created.Labels[PodmanLabelAllocation] != plan.AllocationId.Value {
		t.Fatalf("allocation label missing: %v", created.Labels)
	}
	if created.Labels[PodmanLabelFingerprint] != fingerprint {
		t.Fatalf("fingerprint label missing: %v", created.Labels)
	}
}

func TestPodmanConvergeIsIdempotentForRunningAndStartingAllocations(t *testing.T) {
	for _, state := range []PodmanAllocationState{
		PodmanAllocationStateRunning,
		PodmanAllocationStateStarting,
	} {
		t.Run(state.String(), func(t *testing.T) {
			plan := podmanTestOciPlan(t)
			client := &recordingPodmanClient{
				observation: podmanFencedObservation(t, plan, state, podmanMatchingLabels(t, plan)),
			}
			if err := newPodmanTestAdapter(t, client).Converge(context.Background(), plan); err != nil {
				t.Fatalf("converge: %v", err)
			}
			if !stringSlicesEqual(client.operations, []string{"preflight", "inspect"}) {
				t.Fatalf("a converged allocation must only be inspected: %v", client.operations)
			}
		})
	}
}

func TestPodmanConvergeStartsCreatingStoppedAndFailedAllocations(t *testing.T) {
	for _, state := range []PodmanAllocationState{
		PodmanAllocationStateCreating,
		PodmanAllocationStateStopped,
		PodmanAllocationStateFailed,
	} {
		t.Run(state.String(), func(t *testing.T) {
			plan := podmanTestOciPlan(t)
			client := &recordingPodmanClient{
				observation: podmanFencedObservation(t, plan, state, podmanMatchingLabels(t, plan)),
			}
			if err := newPodmanTestAdapter(t, client).Converge(context.Background(), plan); err != nil {
				t.Fatalf("converge: %v", err)
			}
			if !stringSlicesEqual(client.operations, []string{"preflight", "inspect", "start"}) {
				t.Fatalf("unexpected operations %v", client.operations)
			}
			if !stringSlicesEqual(client.startedIds, []string{plan.Oci.ContainerId}) {
				t.Fatalf("unexpected started ids %v", client.startedIds)
			}
		})
	}
}

func TestPodmanConvergeWaitsForAStoppingAllocation(t *testing.T) {
	plan := podmanTestOciPlan(t)
	client := &recordingPodmanClient{
		observation: podmanFencedObservation(t, plan, PodmanAllocationStateStopping, podmanMatchingLabels(t, plan)),
	}

	var operationError *InvalidOperationError
	err := newPodmanTestAdapter(t, client).Converge(context.Background(), plan)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if !stringSlicesEqual(client.operations, []string{"preflight", "inspect"}) {
		t.Fatalf("a stopping allocation must not be started again: %v", client.operations)
	}
}

func TestPodmanConvergeFencesAllocationsFromDifferentPlans(t *testing.T) {
	plan := podmanTestOciPlan(t)
	matching := podmanMatchingLabels(t, plan)
	foreignFingerprint := map[string]string{
		PodmanLabelAllocation:  plan.AllocationId.Value,
		PodmanLabelFingerprint: strings.Repeat("b", 64),
	}
	foreignAllocation := map[string]string{
		PodmanLabelAllocation:  "terrascale-gru-loki-2",
		PodmanLabelFingerprint: matching[PodmanLabelFingerprint],
	}
	missingAllocation := map[string]string{PodmanLabelFingerprint: matching[PodmanLabelFingerprint]}
	missingFingerprint := map[string]string{PodmanLabelAllocation: plan.AllocationId.Value}

	tests := []struct {
		name   string
		labels map[string]string
	}{
		{name: "foreign fingerprint", labels: foreignFingerprint},
		{name: "foreign allocation", labels: foreignAllocation},
		{name: "missing allocation label", labels: missingAllocation},
		{name: "missing fingerprint label", labels: missingFingerprint},
		{name: "no fencing labels at all", labels: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &recordingPodmanClient{
				observation: podmanFencedObservation(t, plan, PodmanAllocationStateRunning, test.labels),
			}

			var operationError *InvalidOperationError
			err := newPodmanTestAdapter(t, client).Converge(context.Background(), plan)
			if !errors.As(err, &operationError) {
				t.Fatalf("expected InvalidOperationError, got %v", err)
			}
			if !strings.Contains(err.Error(), "belongs to a different plan") {
				t.Fatalf("the operator message must say the container belongs to a different plan: %v", err)
			}
			if !stringSlicesEqual(client.operations, []string{"preflight", "inspect"}) {
				t.Fatalf("a foreign allocation must never be mutated: %v", client.operations)
			}
		})
	}
}

func TestPodmanObserveReturnsTheFencedObservation(t *testing.T) {
	plan := podmanTestOciPlan(t)
	client := &recordingPodmanClient{
		observation: podmanFencedObservation(t, plan, PodmanAllocationStateRunning, podmanMatchingLabels(t, plan)),
	}

	observation, err := newPodmanTestAdapter(t, client).Observe(context.Background(), plan)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if observation.State != PodmanAllocationStateRunning || !observation.Running {
		t.Fatalf("unexpected observation %+v", observation)
	}
	if !stringSlicesEqual(client.operations, []string{"inspect"}) {
		t.Fatalf("unexpected operations %v", client.operations)
	}
}

func TestPodmanObserveFencesForeignAllocations(t *testing.T) {
	plan := podmanTestOciPlan(t)
	client := &recordingPodmanClient{
		observation: podmanFencedObservation(t, plan, PodmanAllocationStateStopped,
			map[string]string{PodmanLabelAllocation: plan.AllocationId.Value}),
	}

	var operationError *InvalidOperationError
	_, err := newPodmanTestAdapter(t, client).Observe(context.Background(), plan)
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
}

func TestPodmanObserveFencesImageAndPlatformMismatches(t *testing.T) {
	plan := podmanTestOciPlan(t)
	labels := podmanMatchingLabels(t, plan)
	for _, test := range []struct {
		name  string
		image string
		plat  string
	}{
		{name: "image", image: "registry.terrascale.internal/terrascale/other@sha256:" + hostRuntimePlanDigest, plat: plan.Oci.Platform},
		{name: "platform", image: plan.Oci.ImageReference, plat: "linux/arm64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation, err := NewPodmanAllocationObservation(
				PodmanAllocationStateRunning, test.image, labels, true, test.plat)
			if err != nil {
				t.Fatalf("observation: %v", err)
			}
			client := &recordingPodmanClient{observation: observation}
			var operationError *InvalidOperationError
			if _, err := newPodmanTestAdapter(t, client).Observe(context.Background(), plan); !errors.As(err, &operationError) {
				t.Fatalf("expected ownership fence error, got %v", err)
			}
		})
	}
}

func TestPodmanStopMatrix(t *testing.T) {
	for _, state := range AllPodmanAllocationStates {
		t.Run(state.String(), func(t *testing.T) {
			plan := podmanTestOciPlan(t)
			client := &recordingPodmanClient{
				observation: podmanFencedObservation(t, plan, state, podmanMatchingLabels(t, plan)),
			}

			if err := newPodmanTestAdapter(t, client).Stop(context.Background(), plan); err != nil {
				t.Fatalf("stop: %v", err)
			}
			expectStop := state == PodmanAllocationStateRunning || state == PodmanAllocationStateStarting
			if expectStop && len(client.stoppedIds) != 1 {
				t.Fatalf("a %s allocation must be stopped", state)
			}
			if !expectStop && len(client.stoppedIds) != 0 {
				t.Fatalf("a %s allocation has nothing to stop: %v", state, client.stoppedIds)
			}
			if !stringSlicesEqual(client.operations, []string{"inspect", "stop"}) && expectStop {
				t.Fatalf("unexpected operations %v", client.operations)
			}
			if !expectStop && !stringSlicesEqual(client.operations, []string{"inspect"}) {
				t.Fatalf("unexpected operations %v", client.operations)
			}
		})
	}
}

func TestPodmanDeleteMatrix(t *testing.T) {
	for _, state := range AllPodmanAllocationStates {
		t.Run(state.String(), func(t *testing.T) {
			plan := podmanTestOciPlan(t)
			client := &recordingPodmanClient{
				observation: podmanFencedObservation(t, plan, state, podmanMatchingLabels(t, plan)),
			}

			if err := newPodmanTestAdapter(t, client).Delete(context.Background(), plan); err != nil {
				t.Fatalf("delete: %v", err)
			}
			switch {
			case state == PodmanAllocationStateAbsent:
				if !stringSlicesEqual(client.operations, []string{"inspect"}) {
					t.Fatalf("an absent allocation is success: %v", client.operations)
				}
			case state == PodmanAllocationStateRunning || state == PodmanAllocationStateStarting:
				if !stringSlicesEqual(client.operations, []string{"inspect", "stop", "delete"}) {
					t.Fatalf("a %s allocation must be stopped before deletion: %v", state, client.operations)
				}
			default:
				if !stringSlicesEqual(client.operations, []string{"inspect", "delete"}) {
					t.Fatalf("a %s allocation must be deleted without a stop: %v", state, client.operations)
				}
			}
		})
	}
}

func TestPodmanAdapterFailsClosedOnPreflightAndClientErrors(t *testing.T) {
	plan := podmanTestOciPlan(t)
	preflightFailed := &recordingPodmanClient{
		observation:    podmanFencedObservation(t, plan, PodmanAllocationStateAbsent, nil),
		preflightError: &InvalidOperationError{Message: "podman info failed with exit code 1."},
	}
	err := newPodmanTestAdapter(t, preflightFailed).Converge(context.Background(), plan)
	var operationError *InvalidOperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError, got %v", err)
	}
	if !stringSlicesEqual(preflightFailed.operations, []string{"preflight"}) {
		t.Fatalf("a failed preflight must stop convergence: %v", preflightFailed.operations)
	}

	inspectFailed := &recordingPodmanClient{inspectError: &InvalidDataError{Message: "boom"}}
	if _, err := newPodmanTestAdapter(t, inspectFailed).Observe(context.Background(), plan); err == nil {
		t.Fatal("an inspect failure must surface")
	}
}

func TestPodmanAdapterRejectsNonCanonicalPlansBeforeAnyClientOperation(t *testing.T) {
	nativePlan, err := NewHostRuntimePlan(
		AdmittedRoleOrchestrator,
		RuntimeDriverNativeSystemd,
		mustRuntimeAllocationId(t, "gru-orchestrator-1"),
		mustArtifactDigest(t, hostRuntimePlanDigest),
		HostArchitectureArm64,
		nil)
	if err != nil {
		t.Fatalf("native plan: %v", err)
	}
	client := &recordingPodmanClient{}
	adapter := newPodmanTestAdapter(t, client)

	var argumentError *ArgumentError
	if err := adapter.Converge(context.Background(), nativePlan); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError for the native plan, got %v", err)
	}

	tampered := podmanTestOciPlan(t)
	tamperedOci := *tampered.Oci
	tamperedOci.ImageReference = "evil.example/loki:latest"
	tampered.Oci = &tamperedOci
	var operationError *InvalidOperationError
	if err := adapter.Converge(context.Background(), tampered); !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError for the tampered plan, got %v", err)
	}

	if err := adapter.Stop(context.Background(), tampered); !errors.As(err, &operationError) {
		t.Fatalf("expected InvalidOperationError for the tampered plan stop, got %v", err)
	}
	if len(client.operations) != 0 {
		t.Fatalf("no client operation may run: %v", client.operations)
	}
}

func TestPodmanAdapterRejectsNilContext(t *testing.T) {
	adapter := newPodmanTestAdapter(t, &recordingPodmanClient{})
	var argumentError *ArgumentError
	if err := adapter.Converge(nil, podmanTestOciPlan(t)); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
	if _, err := adapter.Observe(nil, podmanTestOciPlan(t)); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
	if err := adapter.Stop(nil, podmanTestOciPlan(t)); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
	if err := adapter.Delete(nil, podmanTestOciPlan(t)); !errors.As(err, &argumentError) {
		t.Fatalf("expected ArgumentError, got %v", err)
	}
}

func TestNewPodmanRootlessHostRuntimeAdapterValidatesItsConfiguration(t *testing.T) {
	if _, err := NewPodmanRootlessHostRuntimeAdapter(nil, nil); !errorsAsParam(err, "client") {
		t.Fatalf("a nil client must be rejected, got %v", err)
	}

	volumes := podmanTestVolumes()
	duplicateName := append(append([]PodmanVolumeMount{}, volumes...),
		PodmanVolumeMount{VolumeName: "loki-gru-1", Destination: "/var/lib/loki-2"})
	if _, err := NewPodmanRootlessHostRuntimeAdapter(&recordingPodmanClient{}, duplicateName); !errorsAsParam(err, "statefulVolumes") {
		t.Fatalf("a duplicate volume name must be rejected, got %v", err)
	}

	duplicateDestination := append(append([]PodmanVolumeMount{}, volumes...),
		PodmanVolumeMount{VolumeName: "loki-gru-2", Destination: "/var/lib/loki"})
	if _, err := NewPodmanRootlessHostRuntimeAdapter(&recordingPodmanClient{}, duplicateDestination); !errorsAsParam(err, "statefulVolumes") {
		t.Fatalf("a duplicate destination must be rejected, got %v", err)
	}

	invalidMount := []PodmanVolumeMount{{VolumeName: "bad_volume", Destination: "/data"}}
	if _, err := NewPodmanRootlessHostRuntimeAdapter(&recordingPodmanClient{}, invalidMount); !errorsAsParam(err, "volumeName") {
		t.Fatalf("an invalid mount must be rejected, got %v", err)
	}

	adapter, err := NewPodmanRootlessHostRuntimeAdapter(&recordingPodmanClient{}, nil)
	if err != nil {
		t.Fatalf("a stateless adapter must be constructible: %v", err)
	}
	if len(adapter.statefulVolumes) != 0 {
		t.Fatalf("a stateless adapter must carry no volumes: %v", adapter.statefulVolumes)
	}
}
