package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

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

// CanonicalPlanFingerprint is the canonical length-prefixed SHA-256 fingerprint of a plan.
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
