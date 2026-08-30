// This file implements the rootless-podman host runtime adapter of the
// rootless-hosting and autoscaling lane. It mirrors the containerd adapter in
// shape and semantics: canonical-plan fencing via CanonicalPlanFingerprint,
// Inspect-first convergence, and a Converge/Observe/Stop/Delete surface driven
// by the PodmanClient seam, plus materialization of the stateful named
// volumes before creation.
package runtime

import (
	"context"
	"fmt"
)

// PodmanRootlessHostRuntimeAdapter converges canonical OCI plans through the
// rootless-podman client seam. Existing containers are fenced by the
// terrascale.allocation and terrascale.fingerprint labels: a container whose
// labels do not prove ownership by the exact canonical plan being converged
// belongs to a different plan and is never adopted or mutated.
type PodmanRootlessHostRuntimeAdapter struct {
	client          PodmanClient
	statefulVolumes []PodmanVolumeMount
}

// NewPodmanRootlessHostRuntimeAdapter composes the adapter with its client and
// the stateful volume mounts of the hosted allocation. Each mount is
// revalidated at this trust boundary and the list is snapshotted in the given
// order; pass an empty list for a stateless role.
func NewPodmanRootlessHostRuntimeAdapter(
	client PodmanClient,
	statefulVolumes []PodmanVolumeMount,
) (*PodmanRootlessHostRuntimeAdapter, error) {
	if client == nil {
		return nil, &ArgumentError{Param: "client", Message: "A podman client is required."}
	}
	if len(statefulVolumes) > podmanMaximumVolumeCount {
		return nil, &ArgumentError{
			Param:   "statefulVolumes",
			Message: fmt.Sprintf("Volume input exceeds the bound of %d entries.", podmanMaximumVolumeCount),
		}
	}
	snapshot := make([]PodmanVolumeMount, 0, len(statefulVolumes))
	seenVolumeNames := make(map[string]struct{}, len(statefulVolumes))
	seenDestinations := make(map[string]struct{}, len(statefulVolumes))
	for _, mount := range statefulVolumes {
		validated, err := NewPodmanVolumeMount(mount.VolumeName, mount.Destination, mount.ReadOnly)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenVolumeNames[validated.VolumeName]; duplicate {
			return nil, &ArgumentError{
				Param:   "statefulVolumes",
				Message: "A named volume may be mounted only once per allocation.",
			}
		}
		if _, duplicate := seenDestinations[validated.Destination]; duplicate {
			return nil, &ArgumentError{
				Param:   "statefulVolumes",
				Message: "Volume destinations must be unique.",
			}
		}
		seenVolumeNames[validated.VolumeName] = struct{}{}
		seenDestinations[validated.Destination] = struct{}{}
		snapshot = append(snapshot, validated)
	}
	return &PodmanRootlessHostRuntimeAdapter{client: client, statefulVolumes: snapshot}, nil
}

// Converge brings the allocation to the running state. The client preflight
// must prove the rootless environment before anything else runs. An absent
// allocation gets every stateful volume materialized, the digest-pinned image
// pulled, the container created with the fencing labels, and the container
// started; a fenced allocation in a creating, stopped, or failed state is
// started; a running or starting allocation is already converged.
func (a *PodmanRootlessHostRuntimeAdapter) Converge(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The podman context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The podman runtime client is unavailable."}
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	if err := a.client.Preflight(ctx); err != nil {
		return err
	}
	observation, err := a.client.Inspect(ctx, oci.ContainerId)
	if err != nil {
		return err
	}
	if observation.State != PodmanAllocationStateAbsent {
		fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
		if err != nil {
			return err
		}
		if err := requireMatchingPodmanAllocation(observation, plan.AllocationId.Value, oci, fingerprint); err != nil {
			return err
		}
		switch observation.State {
		case PodmanAllocationStateRunning, PodmanAllocationStateStarting:
			return nil
		case PodmanAllocationStateCreating, PodmanAllocationStateStopped, PodmanAllocationStateFailed:
			return a.client.Start(ctx, oci.ContainerId)
		case PodmanAllocationStateStopping:
			return &InvalidOperationError{
				Message: fmt.Sprintf(
					"podman allocation %s is stopping and must settle before convergence continues.",
					plan.AllocationId),
			}
		default:
			return &InvalidOperationError{
				Message: "The podman allocation state could not be reconciled.",
			}
		}
	}

	for _, volume := range a.statefulVolumes {
		if err := a.client.EnsureVolume(ctx, volume.VolumeName); err != nil {
			return err
		}
	}
	if err := a.client.Pull(ctx, oci.ImageReference, oci.Platform); err != nil {
		return err
	}
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		return err
	}
	request, err := a.runRequestForPlan(plan, oci, fingerprint)
	if err != nil {
		return err
	}
	if err := a.client.Create(ctx, request); err != nil {
		return err
	}
	return a.client.Start(ctx, oci.ContainerId)
}

// Observe returns one fenced observation of the allocation. An existing
// container is returned only when its fencing labels prove ownership by the
// exact canonical plan.
func (a *PodmanRootlessHostRuntimeAdapter) Observe(ctx context.Context, plan HostRuntimePlan) (PodmanAllocationObservation, error) {
	if ctx == nil {
		return PodmanAllocationObservation{}, &ArgumentError{Param: "ctx", Message: "The podman context must not be nil."}
	}
	if a == nil || a.client == nil {
		return PodmanAllocationObservation{}, &InvalidOperationError{Message: "The podman runtime client is unavailable."}
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	observation, err := a.client.Inspect(ctx, oci.ContainerId)
	if err != nil {
		return PodmanAllocationObservation{}, err
	}
	if observation.State != PodmanAllocationStateAbsent {
		fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
		if err != nil {
			return PodmanAllocationObservation{}, err
		}
		if err := requireMatchingPodmanAllocation(observation, plan.AllocationId.Value, oci, fingerprint); err != nil {
			return PodmanAllocationObservation{}, err
		}
	}
	return observation, nil
}

// Stop stops a running or starting allocation. Every other observed state has
// nothing running, so stopping it is already satisfied.
func (a *PodmanRootlessHostRuntimeAdapter) Stop(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The podman context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The podman runtime client is unavailable."}
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	if observation.State == PodmanAllocationStateRunning || observation.State == PodmanAllocationStateStarting {
		return a.client.Stop(ctx, oci.ContainerId)
	}
	return nil
}

// Delete removes the allocation, stopping it first when it is running or
// starting; an absent allocation is success.
func (a *PodmanRootlessHostRuntimeAdapter) Delete(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &ArgumentError{Param: "ctx", Message: "The podman context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The podman runtime client is unavailable."}
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	if observation.State == PodmanAllocationStateAbsent {
		return nil
	}
	if observation.State == PodmanAllocationStateRunning || observation.State == PodmanAllocationStateStarting {
		if err := a.client.Stop(ctx, oci.ContainerId); err != nil {
			return err
		}
	}
	return a.client.Delete(ctx, oci.ContainerId)
}

// runRequestForPlan derives the exact rootless podman run envelope of one
// canonical plan: identity and image from the OCI execution plan, security
// from the OCI security plan (the request constructor re-pins the read-only
// root filesystem, no-new-privileges, and the ALL capability drop so no plan
// can widen them), memory, PID, and CPU limits from the plan resources, the
// stateful volume mounts from the adapter construction, and the two fencing
// labels.
func (a *PodmanRootlessHostRuntimeAdapter) runRequestForPlan(
	plan HostRuntimePlan,
	oci *OciExecutionPlan,
	fingerprint string,
) (PodmanRunRequest, error) {
	return NewPodmanRunRequest(
		oci.ContainerId,
		oci.ImageReference,
		oci.Platform,
		oci.Security.RunAsUser,
		oci.Security.RunAsGroup,
		oci.Security.CgroupParent,
		oci.Security.DroppedCapabilities,
		plan.Resources.MemoryMaxBytes,
		plan.Resources.TasksMax,
		plan.Resources.CpuQuotaPercent,
		plan.Resources.CpuWeight,
		a.statefulVolumes,
		map[string]string{
			PodmanLabelAllocation:  plan.AllocationId.Value,
			PodmanLabelFingerprint: fingerprint,
		},
	)
}

// requireMatchingPodmanAllocation fences one observation against the plan
// being converged: both fencing labels must be present and equal to the
// allocation identifier and the canonical plan fingerprint. A container that
// fails the fence belongs to a different plan and must never be adopted or
// mutated.
func requireMatchingPodmanAllocation(
	observation PodmanAllocationObservation,
	allocationId string,
	expected *OciExecutionPlan,
	fingerprint string,
) error {
	allocationLabel, hasAllocation := observation.Labels[PodmanLabelAllocation]
	fingerprintLabel, hasFingerprint := observation.Labels[PodmanLabelFingerprint]
	if !hasAllocation || !hasFingerprint ||
		allocationLabel != allocationId ||
		fingerprintLabel != fingerprint ||
		observation.ImageReference != expected.ImageReference ||
		observation.Platform != expected.Platform {
		return &InvalidOperationError{
			Message: fmt.Sprintf(
				"Existing podman allocation '%s' belongs to a different plan and was not adopted or mutated.",
				expected.ContainerId),
		}
	}
	return nil
}
