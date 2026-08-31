package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ContainerdAllocationState is the observed containerd allocation state.
type ContainerdAllocationState int

const (
	ContainerdAllocationStateAbsent ContainerdAllocationState = iota
	ContainerdAllocationStateCreated
	ContainerdAllocationStateRunning
	ContainerdAllocationStateStopped
	ContainerdAllocationStateFailed
)

func (s ContainerdAllocationState) String() string {
	names := [...]string{"Absent", "Created", "Running", "Stopped", "Failed"}
	if s >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("ContainerdAllocationState(%d)", int(s))
}

// ContainerdAllocationObservation is one read-only containerd observation.
type ContainerdAllocationObservation struct {
	ContainerId     string
	State           ContainerdAllocationState
	ImageReference  *string
	Platform        *string
	PlanFingerprint *string
	ProcessId       *int
	Detail          string
}

// ContainerdCreateRequest is the exact create call of the adapter.
type ContainerdCreateRequest struct {
	Namespace       string
	ContainerId     string
	ImageReference  string
	Platform        string
	Security        OciSecurityPlan
	Resources       RuntimeResourceLimits
	PlanFingerprint string
}

// ContainerdClient ports the internal IContainerdClient seam.
type ContainerdClient interface {
	Observe(ctx context.Context, namespace string, containerId string) (ContainerdAllocationObservation, error)
	Pull(ctx context.Context, namespace string, imageReference string, platform string) (string, error)
	Create(ctx context.Context, request ContainerdCreateRequest) error
	Start(ctx context.Context, namespace string, containerId string) error
	Stop(ctx context.Context, namespace string, containerId string) error
	Delete(ctx context.Context, namespace string, containerId string) error
}

// ContainerdNamespace is the fixed containerd namespace of the adapter.
const ContainerdNamespace = "terrascale"

// ContainerdHostRuntimeAdapter converges canonical OCI plans via containerd.
type ContainerdHostRuntimeAdapter struct {
	client ContainerdClient
}

// NewContainerdHostRuntimeAdapter composes the adapter with its client.
func NewContainerdHostRuntimeAdapter(client ContainerdClient) *ContainerdHostRuntimeAdapter {
	return &ContainerdHostRuntimeAdapter{client: client}
}

// Converge brings the allocation to the running state, fenced by the canonical
// plan fingerprint and the immutable digest.
func (a *ContainerdHostRuntimeAdapter) Converge(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The containerd context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The containerd runtime client is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
	if err != nil {
		return err
	}
	observation, err := a.client.Observe(ctx, ContainerdNamespace, oci.ContainerId)
	if err != nil {
		return err
	}
	if observation.State != ContainerdAllocationStateAbsent {
		if err := requireMatchingAllocation(observation, oci, fingerprint); err != nil {
			return err
		}
		if observation.State == ContainerdAllocationStateRunning {
			return nil
		}
		if observation.State == ContainerdAllocationStateCreated || observation.State == ContainerdAllocationStateStopped {
			return a.client.Start(ctx, ContainerdNamespace, oci.ContainerId)
		}
		return &InvalidOperationError{
			Message: fmt.Sprintf(
				"containerd allocation %s is failed and requires an observed recovery decision.",
				plan.AllocationId),
		}
	}

	pulledDigest, err := a.client.Pull(ctx, ContainerdNamespace, oci.ImageReference, oci.Platform)
	if err != nil {
		return err
	}
	if pulledDigest != plan.ArtifactDigest.Value {
		return &InvalidOperationError{
			Message: fmt.Sprintf(
				"containerd returned an unexpected digest for allocation %s.",
				plan.AllocationId),
		}
	}
	if err := a.client.Create(ctx, ContainerdCreateRequest{
		Namespace:       ContainerdNamespace,
		ContainerId:     oci.ContainerId,
		ImageReference:  oci.ImageReference,
		Platform:        oci.Platform,
		Security:        oci.Security,
		Resources:       oci.Resources,
		PlanFingerprint: fingerprint,
	}); err != nil {
		return err
	}
	return a.client.Start(ctx, ContainerdNamespace, oci.ContainerId)
}

// Observe returns one fenced observation of the allocation.
func (a *ContainerdHostRuntimeAdapter) Observe(ctx context.Context, plan HostRuntimePlan) (ContainerdAllocationObservation, error) {
	if ctx == nil {
		return ContainerdAllocationObservation{}, &errs.Argument{Param: "ctx", Message: "The containerd context must not be nil."}
	}
	if a == nil || a.client == nil {
		return ContainerdAllocationObservation{}, &InvalidOperationError{Message: "The containerd runtime client is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return ContainerdAllocationObservation{}, err
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return ContainerdAllocationObservation{}, err
	}
	observation, err := a.client.Observe(ctx, ContainerdNamespace, oci.ContainerId)
	if err != nil {
		return ContainerdAllocationObservation{}, err
	}
	if observation.State != ContainerdAllocationStateAbsent {
		fingerprint, err := CanonicalPlanFingerprint.Compute(plan)
		if err != nil {
			return ContainerdAllocationObservation{}, err
		}
		if err := requireMatchingAllocation(observation, oci, fingerprint); err != nil {
			return ContainerdAllocationObservation{}, err
		}
	}
	return observation, nil
}

// Stop stops a running allocation.
func (a *ContainerdHostRuntimeAdapter) Stop(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The containerd context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The containerd runtime client is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	if observation.State == ContainerdAllocationStateRunning {
		return a.client.Stop(ctx, ContainerdNamespace, oci.ContainerId)
	}
	return nil
}

// Delete removes the allocation (stopping it first when needed).
func (a *ContainerdHostRuntimeAdapter) Delete(ctx context.Context, plan HostRuntimePlan) error {
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "The containerd context must not be nil."}
	}
	if a == nil || a.client == nil {
		return &InvalidOperationError{Message: "The containerd runtime client is unavailable."}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oci, err := requireCanonicalOciPlan(plan)
	if err != nil {
		return err
	}
	observation, err := a.Observe(ctx, plan)
	if err != nil {
		return err
	}
	if observation.State == ContainerdAllocationStateAbsent {
		return nil
	}
	if observation.State == ContainerdAllocationStateRunning {
		if err := a.client.Stop(ctx, ContainerdNamespace, oci.ContainerId); err != nil {
			return err
		}
	}
	return a.client.Delete(ctx, ContainerdNamespace, oci.ContainerId)
}

func requireMatchingAllocation(
	observation ContainerdAllocationObservation,
	expected *OciExecutionPlan,
	fingerprint string,
) error {
	containerIDMatches := observation.ContainerId == expected.ContainerId
	imageMatches := observation.ImageReference != nil && *observation.ImageReference == expected.ImageReference
	platformMatches := observation.Platform != nil && *observation.Platform == expected.Platform
	fingerprintMatches := observation.PlanFingerprint != nil && *observation.PlanFingerprint == fingerprint
	if !containerIDMatches || !imageMatches || !platformMatches || !fingerprintMatches {
		return &InvalidOperationError{
			Message: fmt.Sprintf(
				"Existing containerd allocation '%s' is not owned by the canonical plan.",
				expected.ContainerId),
		}
	}
	return nil
}

func requireCanonicalOciPlan(plan HostRuntimePlan) (*OciExecutionPlan, error) {
	if plan.Driver != RuntimeDriverOciContainer || plan.Oci == nil || plan.Systemd != nil {
		return nil, &errs.Argument{
			Param:   "plan",
			Message: "The containerd adapter requires an OCI plan.",
		}
	}
	expected, err := NewHostRuntimePlan(
		plan.Role,
		plan.Driver,
		plan.AllocationId,
		plan.ArtifactDigest,
		plan.Architecture,
		&plan.Resources)
	if err != nil {
		// The C# source lets HostRuntimePlan.Create surface its own exception
		// (admission or policy) here without wrapping it.
		return nil, err
	}
	expectedOci := expected.Oci
	if expectedOci == nil {
		return nil, &InvalidOperationError{
			Message: "The OCI execution plan could not be reconstructed from the admitted role.",
		}
	}
	actualOci := plan.Oci
	if !canonicalPlanFieldsMatch(plan, expected) ||
		plan.SchemaVersion != expected.SchemaVersion ||
		actualOci.ContainerId != expectedOci.ContainerId ||
		actualOci.ImageReference != expectedOci.ImageReference ||
		actualOci.Platform != expectedOci.Platform ||
		actualOci.Resources != expectedOci.Resources ||
		actualOci.Security.RunAsUser != expectedOci.Security.RunAsUser ||
		actualOci.Security.RunAsGroup != expectedOci.Security.RunAsGroup ||
		actualOci.Security.NoNewPrivileges != expectedOci.Security.NoNewPrivileges ||
		actualOci.Security.ReadOnlyRootFileSystem != expectedOci.Security.ReadOnlyRootFileSystem ||
		!stringSlicesEqual(actualOci.Security.DroppedCapabilities, expectedOci.Security.DroppedCapabilities) ||
		actualOci.Security.SeccompProfile != expectedOci.Security.SeccompProfile ||
		actualOci.Security.CgroupParent != expectedOci.Security.CgroupParent ||
		plan.Resources != expected.Resources {
		return nil, &InvalidOperationError{
			Message: "The OCI execution plan is not canonical for the admitted role.",
		}
	}
	return actualOci, nil
}

func canonicalPlanFieldsMatch(actual, expected HostRuntimePlan) bool {
	return actual.Role == expected.Role && actual.Driver == expected.Driver &&
		actual.AllocationId == expected.AllocationId &&
		actual.ArtifactDigest == expected.ArtifactDigest &&
		actual.Architecture == expected.Architecture
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// CanonicalPlanFingerprint ports the internal CanonicalPlanFingerprint static
// class; call it as runtime.CanonicalPlanFingerprint.Compute(plan).
var CanonicalPlanFingerprint canonicalPlanFingerprint

type canonicalPlanFingerprint struct{}

// Compute derives the canonical length-prefixed SHA-256 fingerprint of a plan.
func (canonicalPlanFingerprint) Compute(plan HostRuntimePlan) (string, error) {
	hash := sha256.New()
	addFingerprintField(hash, strconv.Itoa(plan.SchemaVersion))
	addFingerprintField(hash, plan.Role.String())
	addFingerprintField(hash, plan.Driver.String())
	addFingerprintField(hash, plan.AllocationId.Value)
	addFingerprintField(hash, plan.ArtifactDigest.Value)
	addFingerprintField(hash, plan.Architecture.String())
	addFingerprintField(hash, strconv.FormatInt(plan.Resources.MemoryMaxBytes, 10))
	addFingerprintField(hash, strconv.FormatInt(plan.Resources.MemoryHighBytes(), 10))
	addFingerprintField(hash, strconv.FormatInt(plan.Resources.MemorySwapMaxBytes(), 10))
	addFingerprintField(hash, strconv.Itoa(plan.Resources.TasksMax))
	addFingerprintField(hash, strconv.Itoa(plan.Resources.CpuQuotaPercent))
	addFingerprintField(hash, strconv.Itoa(plan.Resources.CpuWeight))
	addFingerprintField(hash, strconv.Itoa(plan.Resources.IoWeight))
	addFingerprintField(hash, strconv.Itoa(plan.Resources.Nice))
	if oci := plan.Oci; oci != nil {
		addFingerprintField(hash, oci.ContainerId)
		addFingerprintField(hash, oci.ImageReference)
		addFingerprintField(hash, oci.Platform)
		addFingerprintField(hash, strconv.FormatUint(uint64(oci.Security.RunAsUser), 10))
		addFingerprintField(hash, strconv.FormatUint(uint64(oci.Security.RunAsGroup), 10))
		addFingerprintField(hash, strconv.FormatBool(oci.Security.NoNewPrivileges))
		addFingerprintField(hash, strconv.FormatBool(oci.Security.ReadOnlyRootFileSystem))
		for _, capability := range oci.Security.DroppedCapabilities {
			addFingerprintField(hash, capability)
		}
		addFingerprintField(hash, oci.Security.SeccompProfile)
		addFingerprintField(hash, oci.Security.CgroupParent)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func addFingerprintField(hash hashWriter, value string) {
	bytes := []byte(value)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(bytes)))
	hash.Write(length[:])
	hash.Write(bytes)
}

type hashWriter interface {
	Write([]byte) (int, error)
}
