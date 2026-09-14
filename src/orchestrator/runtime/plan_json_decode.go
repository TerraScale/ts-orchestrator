// This file decodes the camelCase JSON produced by the HostRuntimePlan
// MarshalJSON in host_runtime_plan.go, so a node agent can rebuild a plan from
// the exact bytes the control plane serialized.
package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// hostRuntimePlanCurrentSchemaVersion is the only plan schema version this
// decoder accepts; NewHostRuntimePlan always produces it.
const hostRuntimePlanCurrentSchemaVersion = 2

// UnmarshalJSON decodes exactly the JSON produced by
// (HostRuntimePlan).MarshalJSON: camelCase fields, the schema version, role,
// driver, and architecture as camelCase enum strings, the allocation id and
// artifact digest as {value:...} objects, and the optional systemd and OCI
// plans as null or nested objects. Unknown fields, trailing data, unknown enum
// names, a driver that disagrees with the carried execution plan, and an
// execution plan that is not the canonical plan NewHostRuntimePlan would
// derive for the decoded role, resources, and identity are rejected as
// invalid data; the receiver is left untouched on any error.
func (p *HostRuntimePlan) UnmarshalJSON(data []byte) error {
	var wire hostRuntimePlanWire
	if err := decodeStrictPlanJSON(data, &wire); err != nil {
		return err
	}
	if wire.SchemaVersion == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry a schemaVersion."}
	}
	if *wire.SchemaVersion != hostRuntimePlanCurrentSchemaVersion {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The runtime plan schema version %d is not supported; only version %d is decoded.",
			*wire.SchemaVersion, hostRuntimePlanCurrentSchemaVersion)}
	}
	if wire.Role == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry a role."}
	}
	role, roleKnown := parseAdmittedRoleWire(*wire.Role)
	if !roleKnown {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The runtime plan role %q is not admitted.", *wire.Role)}
	}
	if wire.Driver == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry a driver."}
	}
	driver, driverKnown := parseRuntimeDriverWire(*wire.Driver)
	if !driverKnown {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The runtime plan driver %q is not a runtime driver.", *wire.Driver)}
	}
	if wire.AllocationId == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry an allocationId."}
	}
	allocationId, err := NewRuntimeAllocationId(wire.AllocationId.Value)
	if err != nil {
		return err
	}
	if wire.ArtifactDigest == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry an artifactDigest."}
	}
	digest, err := NewArtifactDigest(wire.ArtifactDigest.Value)
	if err != nil {
		return err
	}
	if wire.Architecture == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry an architecture."}
	}
	architecture, architectureKnown := parseHostArchitectureWire(*wire.Architecture)
	if !architectureKnown {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The runtime plan architecture %q is not a host architecture.", *wire.Architecture)}
	}
	if wire.Resources == nil {
		return &InvalidDataError{Message: "The runtime plan payload must carry resources."}
	}
	resources, err := wire.Resources.limits()
	if err != nil {
		return err
	}

	var systemd *SystemdExecutionPlan
	if wire.Systemd != nil && !wire.isNullPlan(*wire.Systemd) {
		var planWire systemdExecutionPlanWire
		if err := decodeStrictPlanJSON(*wire.Systemd, &planWire); err != nil {
			return err
		}
		var planErr error
		systemd, planErr = planWire.plan()
		if planErr != nil {
			return planErr
		}
	}
	var oci *OciExecutionPlan
	if wire.Oci != nil && !wire.isNullPlan(*wire.Oci) {
		var planWire ociExecutionPlanWire
		if err := decodeStrictPlanJSON(*wire.Oci, &planWire); err != nil {
			return err
		}
		var planErr error
		oci, planErr = planWire.plan()
		if planErr != nil {
			return planErr
		}
	}
	if err := requirePlanDriverShape(driver, systemd, oci); err != nil {
		return err
	}
	expected, err := NewHostRuntimePlan(role, driver, allocationId, digest, architecture, &resources)
	if err != nil {
		return err
	}
	if !decodedPlansAreCanonical(systemd, oci, expected) {
		return &InvalidDataError{
			Message: "The decoded execution plan is not the canonical plan of the admitted role.",
		}
	}

	*p = HostRuntimePlan{
		SchemaVersion:  *wire.SchemaVersion,
		Role:           role,
		Driver:         driver,
		AllocationId:   allocationId,
		ArtifactDigest: digest,
		Architecture:   architecture,
		Resources:      resources,
		Systemd:        systemd,
		Oci:            oci,
	}
	return nil
}

// hostRuntimePlanWire is the strict wire shape of one serialized plan. Every
// field is a pointer so an absent field is distinguishable from a zero value.
type hostRuntimePlanWire struct {
	SchemaVersion  *int                       `json:"schemaVersion"`
	Role           *string                    `json:"role"`
	Driver         *string                    `json:"driver"`
	AllocationId   *wireTokenValue            `json:"allocationId"`
	ArtifactDigest *wireTokenValue            `json:"artifactDigest"`
	Architecture   *string                    `json:"architecture"`
	Resources      *runtimeResourceLimitsWire `json:"resources"`
	Systemd        *json.RawMessage           `json:"systemd"`
	Oci            *json.RawMessage           `json:"oci"`
}

// wireTokenValue is the {value:...} spelling of the plan token objects.
type wireTokenValue struct {
	Value string `json:"value"`
}

// runtimeResourceLimitsWire mirrors the marshaled resource limits. The
// memoryHighBytes and memorySwapMaxBytes watermarks the serializer always
// emits must match the values derived from the limits themselves, so a
// tampered watermark cannot ride along in a decoded plan.
type runtimeResourceLimitsWire struct {
	MemoryMaxBytes     *int64 `json:"memoryMaxBytes"`
	TasksMax           *int   `json:"tasksMax"`
	CpuQuotaPercent    *int   `json:"cpuQuotaPercent"`
	CpuWeight          *int   `json:"cpuWeight"`
	IoWeight           *int   `json:"ioWeight"`
	Nice               *int   `json:"nice"`
	MemoryHighBytes    *int64 `json:"memoryHighBytes"`
	MemorySwapMaxBytes *int64 `json:"memorySwapMaxBytes"`
}

func (w *runtimeResourceLimitsWire) limits() (RuntimeResourceLimits, error) {
	if w == nil || w.MemoryMaxBytes == nil || w.TasksMax == nil || w.CpuQuotaPercent == nil ||
		w.CpuWeight == nil || w.IoWeight == nil || w.Nice == nil || w.MemoryHighBytes == nil ||
		w.MemorySwapMaxBytes == nil {
		return RuntimeResourceLimits{}, &InvalidDataError{Message: "The runtime resource limits payload is incomplete."}
	}
	limits := RuntimeResourceLimits{MemoryMaxBytes: *w.MemoryMaxBytes, TasksMax: *w.TasksMax,
		CpuQuotaPercent: *w.CpuQuotaPercent, CpuWeight: *w.CpuWeight, IoWeight: *w.IoWeight, Nice: *w.Nice}
	if *w.MemoryHighBytes != limits.MemoryHighBytes() || *w.MemorySwapMaxBytes != limits.MemorySwapMaxBytes() {
		return RuntimeResourceLimits{}, &InvalidDataError{Message: "The runtime resource watermark fields are inconsistent."}
	}
	return limits, nil
}

// systemdExecutionPlanWire mirrors the marshaled systemd execution plan.
type systemdExecutionPlanWire struct {
	UnitName   *string   `json:"unitName"`
	Executable *string   `json:"executable"`
	Arguments  *[]string `json:"arguments"`
	Properties *[]string `json:"properties"`
}

func (w *systemdExecutionPlanWire) plan() (*SystemdExecutionPlan, error) {
	if w == nil || w.UnitName == nil || w.Executable == nil || w.Arguments == nil || w.Properties == nil {
		return nil, &InvalidDataError{Message: "The systemd execution plan payload is incomplete."}
	}
	return &SystemdExecutionPlan{UnitName: *w.UnitName, Executable: *w.Executable, Arguments: *w.Arguments, Properties: *w.Properties}, nil
}

// ociExecutionPlanWire mirrors the marshaled OCI execution plan.
type ociExecutionPlanWire struct {
	ContainerId    *string                    `json:"containerId"`
	ImageReference *string                    `json:"imageReference"`
	Platform       *string                    `json:"platform"`
	Security       *ociSecurityPlanWire       `json:"security"`
	Resources      *runtimeResourceLimitsWire `json:"resources"`
}

func (w *ociExecutionPlanWire) plan() (*OciExecutionPlan, error) {
	if w == nil || w.ContainerId == nil || w.ImageReference == nil || w.Platform == nil || w.Security == nil || w.Resources == nil {
		return nil, &InvalidDataError{Message: "The OCI execution plan payload is incomplete."}
	}
	resources, err := w.Resources.limits()
	if err != nil {
		return nil, err
	}
	security, err := w.Security.plan()
	if err != nil {
		return nil, err
	}
	return &OciExecutionPlan{ContainerId: *w.ContainerId, ImageReference: *w.ImageReference, Platform: *w.Platform, Security: security, Resources: resources}, nil
}

// ociSecurityPlanWire mirrors the marshaled OCI security plan.
type ociSecurityPlanWire struct {
	RunAsUser              *uint32   `json:"runAsUser"`
	RunAsGroup             *uint32   `json:"runAsGroup"`
	NoNewPrivileges        *bool     `json:"noNewPrivileges"`
	ReadOnlyRootFileSystem *bool     `json:"readOnlyRootFileSystem"`
	DroppedCapabilities    *[]string `json:"droppedCapabilities"`
	SeccompProfile         *string   `json:"seccompProfile"`
	CgroupParent           *string   `json:"cgroupParent"`
}

func (w *ociSecurityPlanWire) plan() (OciSecurityPlan, error) {
	if w == nil || w.RunAsUser == nil || w.RunAsGroup == nil || w.NoNewPrivileges == nil ||
		w.ReadOnlyRootFileSystem == nil || w.DroppedCapabilities == nil || w.SeccompProfile == nil || w.CgroupParent == nil {
		return OciSecurityPlan{}, &InvalidDataError{Message: "The OCI security plan payload is incomplete."}
	}
	return OciSecurityPlan{RunAsUser: *w.RunAsUser, RunAsGroup: *w.RunAsGroup, NoNewPrivileges: *w.NoNewPrivileges,
		ReadOnlyRootFileSystem: *w.ReadOnlyRootFileSystem, DroppedCapabilities: *w.DroppedCapabilities,
		SeccompProfile: *w.SeccompProfile, CgroupParent: *w.CgroupParent}, nil
}

// isNullPlan reports whether the optional plan member is present as an
// explicit null, which decodes to a nil execution plan. An absent member is a
// distinct error the caller reports on its own.
func (wire *hostRuntimePlanWire) isNullPlan(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// decodeStrictPlanJSON decodes one canonical JSON document, rejecting unknown
// fields and trailing data so the closed wire vocabulary stays closed.
func decodeStrictPlanJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &InvalidDataError{Message: fmt.Sprintf(
			"The runtime plan payload is not the canonical JSON shape: %s.", err.Error())}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return &InvalidDataError{Message: "The runtime plan payload must be exactly one JSON document."}
	}
	return nil
}

// parseAdmittedRoleWire resolves one camelCase role name to its role value.
func parseAdmittedRoleWire(value string) (AdmittedRole, bool) {
	for _, role := range AllAdmittedRoles {
		if camelCaseEnum(role.String()) == value {
			return role, true
		}
	}
	return AdmittedRole(0), false
}

// parseRuntimeDriverWire resolves one camelCase driver name to its driver.
func parseRuntimeDriverWire(value string) (RuntimeDriver, bool) {
	switch value {
	case camelCaseEnum(RuntimeDriverNativeSystemd.String()):
		return RuntimeDriverNativeSystemd, true
	case camelCaseEnum(RuntimeDriverOciContainer.String()):
		return RuntimeDriverOciContainer, true
	default:
		return RuntimeDriver(0), false
	}
}

// parseHostArchitectureWire resolves one camelCase architecture name.
func parseHostArchitectureWire(value string) (HostArchitecture, bool) {
	switch value {
	case camelCaseEnum(HostArchitectureArm64.String()):
		return HostArchitectureArm64, true
	case camelCaseEnum(HostArchitectureX64.String()):
		return HostArchitectureX64, true
	default:
		return HostArchitecture(0), false
	}
}

// decodedPlansAreCanonical reports whether the decoded execution plans are
// exactly the plans NewHostRuntimePlan derives for the same admitted role, so
// the decoder itself enforces the canonical-plan trust boundary this file
// documents: a tampered unit name, executable, argument list, property list,
// container id, image reference, platform, security envelope, or nested
// resource copy is rejected at decode instead of waiting for an adapter's
// requireCanonical* fence.
func decodedPlansAreCanonical(systemd *SystemdExecutionPlan, oci *OciExecutionPlan, expected HostRuntimePlan) bool {
	if systemd != nil {
		expectedSystemd := expected.Systemd
		if expectedSystemd == nil ||
			systemd.UnitName != expectedSystemd.UnitName ||
			systemd.Executable != expectedSystemd.Executable ||
			!stringSlicesEqual(systemd.Arguments, expectedSystemd.Arguments) ||
			!stringSlicesEqual(systemd.Properties, expectedSystemd.Properties) {
			return false
		}
	}
	if oci != nil {
		expectedOci := expected.Oci
		if expectedOci == nil ||
			oci.ContainerId != expectedOci.ContainerId ||
			oci.ImageReference != expectedOci.ImageReference ||
			oci.Platform != expectedOci.Platform ||
			oci.Resources != expectedOci.Resources ||
			oci.Security.RunAsUser != expectedOci.Security.RunAsUser ||
			oci.Security.RunAsGroup != expectedOci.Security.RunAsGroup ||
			oci.Security.NoNewPrivileges != expectedOci.Security.NoNewPrivileges ||
			oci.Security.ReadOnlyRootFileSystem != expectedOci.Security.ReadOnlyRootFileSystem ||
			!stringSlicesEqual(oci.Security.DroppedCapabilities, expectedOci.Security.DroppedCapabilities) ||
			oci.Security.SeccompProfile != expectedOci.Security.SeccompProfile ||
			oci.Security.CgroupParent != expectedOci.Security.CgroupParent {
			return false
		}
	}
	return true
}

// requirePlanDriverShape enforces that the decoded driver agrees with which
// execution plan is present, mirroring the shape NewHostRuntimePlan produces.
func requirePlanDriverShape(driver RuntimeDriver, systemd *SystemdExecutionPlan, oci *OciExecutionPlan) error {
	switch driver {
	case RuntimeDriverNativeSystemd:
		if systemd == nil || oci != nil {
			return &InvalidDataError{
				Message: "A nativeSystemd plan must carry its systemd plan and no OCI plan.",
			}
		}
	case RuntimeDriverOciContainer:
		if oci == nil || systemd != nil {
			return &InvalidDataError{
				Message: "An ociContainer plan must carry its OCI plan and no systemd plan.",
			}
		}
	default:
		return &errs.ArgumentOutOfRangeError{Param: "driver"}
	}
	return nil
}
