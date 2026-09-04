package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// HostArchitecture is the closed host architecture vocabulary.
type HostArchitecture int

const (
	HostArchitectureArm64 HostArchitecture = iota
	HostArchitectureX64
)

func (a HostArchitecture) defined() bool {
	return a == HostArchitectureArm64 || a == HostArchitectureX64
}

func (a HostArchitecture) String() string {
	switch a {
	case HostArchitectureArm64:
		return "Arm64"
	case HostArchitectureX64:
		return "X64"
	default:
		return fmt.Sprintf("HostArchitecture(%d)", int(a))
	}
}

var runtimeAllocationTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// RuntimeAllocationId is a lowercase DNS-style allocation token.
type RuntimeAllocationId struct {
	Value string
}

// NewRuntimeAllocationId validates the DNS-style token.
func NewRuntimeAllocationId(value string) (RuntimeAllocationId, error) {
	if len(value) < 1 || len(value) > 63 || !runtimeAllocationTokenPattern.MatchString(value) {
		return RuntimeAllocationId{}, &errs.Argument{
			Param:   "value",
			Message: "Allocation ID must be a lowercase DNS-style token.",
		}
	}
	return RuntimeAllocationId{Value: value}, nil
}

func (id RuntimeAllocationId) String() string { return id.Value }

// ArtifactDigest is a lowercase SHA-256 hex digest.
type ArtifactDigest struct {
	Value string
}

// NewArtifactDigest validates the digest shape.
func NewArtifactDigest(value string) (ArtifactDigest, error) {
	if len(value) != 64 || !isLowercaseHexDigest(value) {
		return ArtifactDigest{}, &errs.Argument{
			Param:   "value",
			Message: "Artifact digest must be lowercase SHA-256 hex.",
		}
	}
	return ArtifactDigest{Value: value}, nil
}

func (d ArtifactDigest) String() string { return d.Value }

func isLowercaseHexDigest(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// RuntimeResourceLimits is the closed systemd cgroup-v2 envelope
// for REQ-O012 and INV-017.
type RuntimeResourceLimits struct {
	MemoryMaxBytes  int64
	TasksMax        int
	CpuQuotaPercent int
	CpuWeight       int
	IoWeight        int
	Nice            int
}

// MemoryHighBytes derives the high watermark (90% of max).
func (l RuntimeResourceLimits) MemoryHighBytes() int64 {
	return l.MemoryMaxBytes * 9 / 10
}

// MemorySwapMaxBytes is pinned to zero (no swap).
func (l RuntimeResourceLimits) MemorySwapMaxBytes() int64 { return 0 }

// SystemdExecutionPlan is the catalog-derived systemd unit plan.
type SystemdExecutionPlan struct {
	UnitName   string
	Executable string
	Arguments  []string
	Properties []string
}

// OciSecurityPlan is the retired OCI security envelope (D-69, no containers).
// The struct is retained for wire decode and control-plane fingerprint
// compatibility until I-1 replaces the declared-estate types.
type OciSecurityPlan struct {
	RunAsUser              uint32
	RunAsGroup             uint32
	NoNewPrivileges        bool
	ReadOnlyRootFileSystem bool
	DroppedCapabilities    []string
	SeccompProfile         string
	CgroupParent           string
}

// OciExecutionPlan is the retired OCI execution plan (D-69, no containers).
// Retained for wire decode and control-plane fingerprint compatibility until
// I-1 replaces the declared-estate types.
type OciExecutionPlan struct {
	ContainerId    string
	ImageReference string
	Platform       string
	Security       OciSecurityPlan
	Resources      RuntimeResourceLimits
}

// HostRuntimePlan is the canonical runtime plan of one allocation.
type HostRuntimePlan struct {
	SchemaVersion  int
	Role           AdmittedRole
	Driver         RuntimeDriver
	AllocationId   RuntimeAllocationId
	ArtifactDigest ArtifactDigest
	Architecture   HostArchitecture
	Resources      RuntimeResourceLimits
	Systemd        *SystemdExecutionPlan
	Oci            *OciExecutionPlan
}

// NewHostRuntimePlan admits the role/driver pair, applies the closed resource
// policy and derives the execution plan.
func NewHostRuntimePlan(
	role AdmittedRole,
	driver RuntimeDriver,
	allocationId RuntimeAllocationId,
	digest ArtifactDigest,
	architecture HostArchitecture,
	requestedResources *RuntimeResourceLimits,
) (HostRuntimePlan, error) {
	// RuntimeAllocationId and ArtifactDigest are value structs with exported
	// fields for protocol compatibility. Revalidate them at this trust boundary
	// before deriving any filesystem path, unit name, image reference, or cgroup
	// identity from their values.
	if _, err := NewRuntimeAllocationId(allocationId.Value); err != nil {
		return HostRuntimePlan{}, err
	}
	if _, err := NewArtifactDigest(digest.Value); err != nil {
		return HostRuntimePlan{}, err
	}
	if !architecture.defined() {
		return HostRuntimePlan{}, &errs.ArgumentOutOfRangeError{Param: "architecture"}
	}

	descriptor, err := AdmittedRoleCatalog.Admit(role, driver)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	resources, err := RuntimeResourceLimitPolicy.For(role, requestedResources)
	if err != nil {
		return HostRuntimePlan{}, err
	}
	switch driver {
	case RuntimeDriverNativeSystemd:
		return HostRuntimePlan{
			SchemaVersion:  2,
			Role:           role,
			Driver:         driver,
			AllocationId:   allocationId,
			ArtifactDigest: digest,
			Architecture:   architecture,
			Resources:      resources,
			Systemd:        createSystemdExecutionPlan(descriptor, allocationId, digest, resources),
			Oci:            nil,
		}, nil
	case RuntimeDriverOciContainer:
		// D-69: no containers in production or CI. The OCI driver is retired;
		// no catalog role admits it. I-3 (ts-node/systemd delivery) replaces it.
		return HostRuntimePlan{}, &errs.ArgumentOutOfRangeError{
			Param:   "driver",
			Message: "The OCI container driver is retired; use native systemd (I-3).",
		}
	default:
		return HostRuntimePlan{}, &errs.ArgumentOutOfRangeError{Param: "driver"}
	}
}

func createSystemdExecutionPlan(
	descriptor AdmittedRoleDescriptor,
	allocation RuntimeAllocationId,
	digest ArtifactDigest,
	resources RuntimeResourceLimits,
) *SystemdExecutionPlan {
	unit := fmt.Sprintf("terrascale-%s.service", allocation)
	stateDirectory := fmt.Sprintf("/var/lib/terrascale-%s", allocation)
	executable := fmt.Sprintf("/opt/terrascale/artifacts/%s/sha256-%s/%s",
		descriptor.ArtifactKey, digest, descriptor.ArtifactKey)
	var arguments []string
	switch descriptor.Role {
	case AdmittedRoleNats:
		arguments = []string{"--config", stateDirectory + "/config.json"}
	default:
		arguments = []string{}
	}
	var configurationProperty string
	if descriptor.Role == AdmittedRoleAutoscaler || descriptor.Role == AdmittedRoleJournalWriter {
		configurationProperty = "Environment=TS_ORCH_CONFIG=" + stateDirectory + "/config.json"
	} else {
		configurationProperty = "EnvironmentFile=-" + stateDirectory + "/environment"
	}
	return &SystemdExecutionPlan{
		UnitName:   unit,
		Executable: executable,
		Arguments:  arguments,
		Properties: []string{
			"Type=exec",
			"Restart=always",
			"RestartSec=5s",
			"NoNewPrivileges=yes",
			"PrivateTmp=yes",
			"ProtectSystem=strict",
			"ProtectHome=yes",
			"ProtectKernelTunables=yes",
			"ProtectKernelModules=yes",
			"ProtectControlGroups=yes",
			"RestrictSUIDSGID=yes",
			"LockPersonality=yes",
			"StateDirectory=terrascale-" + allocation.Value,
			"RuntimeDirectory=terrascale-" + allocation.Value,
			configurationProperty,
			"LoadCredentialEncrypted=workload:" + stateDirectory + "/credentials/workload.cred",
			"MemoryMax=" + strconv.FormatInt(resources.MemoryMaxBytes, 10),
			"MemoryHigh=" + strconv.FormatInt(resources.MemoryHighBytes(), 10),
			"MemorySwapMax=" + strconv.FormatInt(resources.MemorySwapMaxBytes(), 10),
			"TasksMax=" + strconv.Itoa(resources.TasksMax),
			"CPUQuota=" + strconv.Itoa(resources.CpuQuotaPercent) + "%",
			"CPUWeight=" + strconv.Itoa(resources.CpuWeight),
			"IOWeight=" + strconv.Itoa(resources.IoWeight),
			"Nice=" + strconv.Itoa(resources.Nice),
		},
	}
}

// RuntimeResourceLimitPolicy ports the internal RuntimeResourceLimitPolicy.
var RuntimeResourceLimitPolicy runtimeResourceLimitPolicy

type runtimeResourceLimitPolicy struct{}

const runtimeMinimumMemoryBytes = int64(64 * 1024 * 1024)

// For resolves the effective limits of one role against the closed ceiling.
func (runtimeResourceLimitPolicy) For(role AdmittedRole, requested *RuntimeResourceLimits) (RuntimeResourceLimits, error) {
	if _, err := AdmittedRoleCatalog.Get(role); err != nil {
		return RuntimeResourceLimits{}, err
	}
	var maximum RuntimeResourceLimits
	switch role {
	case AdmittedRoleTerraBaseMember:
		maximum = RuntimeResourceLimits{8 * 1024 * 1024 * 1024, 2048, 400, 1000, 1000, 0}
	case AdmittedRoleNats:
		maximum = RuntimeResourceLimits{2 * 1024 * 1024 * 1024, 512, 200, 800, 800, 0}
	default:
		maximum = RuntimeResourceLimits{1 * 1024 * 1024 * 1024, 512, 200, 500, 300, 0}
	}
	if requested == nil {
		return maximum, nil
	}
	if requested.MemoryMaxBytes < runtimeMinimumMemoryBytes || requested.MemoryMaxBytes > maximum.MemoryMaxBytes {
		return RuntimeResourceLimits{}, &errs.ArgumentOutOfRangeError{
			Param: "requested",
			Message: fmt.Sprintf("Memory limit must be between %d and %d bytes for %s.",
				runtimeMinimumMemoryBytes, maximum.MemoryMaxBytes, role),
		}
	}
	if requested.TasksMax < 16 || requested.TasksMax > maximum.TasksMax {
		return RuntimeResourceLimits{}, &errs.ArgumentOutOfRangeError{
			Param:   "requested",
			Message: fmt.Sprintf("Task limit must be between 16 and %d for %s.", maximum.TasksMax, role),
		}
	}
	if requested.CpuQuotaPercent < 10 || requested.CpuQuotaPercent > maximum.CpuQuotaPercent {
		return RuntimeResourceLimits{}, &errs.ArgumentOutOfRangeError{
			Param: "requested",
			Message: fmt.Sprintf("CPU quota must be between 10 and %d percent for %s.",
				maximum.CpuQuotaPercent, role),
		}
	}
	if requested.CpuWeight < 1 || requested.CpuWeight > maximum.CpuWeight ||
		requested.IoWeight < 1 || requested.IoWeight > maximum.IoWeight {
		return RuntimeResourceLimits{}, &errs.ArgumentOutOfRangeError{
			Param: "requested",
			Message: fmt.Sprintf("CPU and I/O weights must be positive and cannot exceed the %s catalog policy.",
				role),
		}
	}
	if requested.Nice < maximum.Nice || requested.Nice > 19 {
		return RuntimeResourceLimits{}, &errs.ArgumentOutOfRangeError{
			Param:   "requested",
			Message: fmt.Sprintf("Nice must be between %d and 19 for %s.", maximum.Nice, role),
		}
	}
	return *requested, nil
}

// MarshalJSON emits the canonical camelCase plan shape: enums render as
// camelCase strings and the optional execution plan preserves null.
func (p HostRuntimePlan) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(`{"schemaVersion":`)
	buffer.WriteString(strconv.Itoa(p.SchemaVersion))
	buffer.WriteString(`,"role":`)
	writeJSONString(&buffer, camelCaseEnum(p.Role.String()))
	buffer.WriteString(`,"driver":`)
	writeJSONString(&buffer, camelCaseEnum(p.Driver.String()))
	buffer.WriteString(`,"allocationId":{"value":`)
	writeJSONString(&buffer, p.AllocationId.Value)
	buffer.WriteString(`},"artifactDigest":{"value":`)
	writeJSONString(&buffer, p.ArtifactDigest.Value)
	buffer.WriteString(`},"architecture":`)
	writeJSONString(&buffer, camelCaseEnum(p.Architecture.String()))
	buffer.WriteString(`,"resources":`)
	encoded, err := json.Marshal(p.Resources)
	if err != nil {
		return nil, err
	}
	buffer.Write(encoded)
	buffer.WriteString(`,"systemd":`)
	if p.Systemd == nil {
		buffer.WriteString("null")
	} else {
		encoded, err = json.Marshal(p.Systemd)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}
	buffer.WriteString(`,"oci":`)
	if p.Oci == nil {
		buffer.WriteString("null")
	} else {
		encoded, err = json.Marshal(p.Oci)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}
	buffer.WriteString("}")
	return buffer.Bytes(), nil
}

// MarshalJSON mirrors the Web-defaults camelCase output of
// RuntimeResourceLimits, including the computed high/swap watermarks that
// The computed watermarks serialize as read-only properties.
func (l RuntimeResourceLimits) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(`{"memoryMaxBytes":`)
	buffer.WriteString(strconv.FormatInt(l.MemoryMaxBytes, 10))
	buffer.WriteString(`,"tasksMax":`)
	buffer.WriteString(strconv.Itoa(l.TasksMax))
	buffer.WriteString(`,"cpuQuotaPercent":`)
	buffer.WriteString(strconv.Itoa(l.CpuQuotaPercent))
	buffer.WriteString(`,"cpuWeight":`)
	buffer.WriteString(strconv.Itoa(l.CpuWeight))
	buffer.WriteString(`,"ioWeight":`)
	buffer.WriteString(strconv.Itoa(l.IoWeight))
	buffer.WriteString(`,"nice":`)
	buffer.WriteString(strconv.Itoa(l.Nice))
	buffer.WriteString(`,"memoryHighBytes":`)
	buffer.WriteString(strconv.FormatInt(l.MemoryHighBytes(), 10))
	buffer.WriteString(`,"memorySwapMaxBytes":`)
	buffer.WriteString(strconv.FormatInt(l.MemorySwapMaxBytes(), 10))
	buffer.WriteString("}")
	return buffer.Bytes(), nil
}

// MarshalJSON mirrors the Web-defaults camelCase output of a systemd plan.
func (p *SystemdExecutionPlan) MarshalJSON() ([]byte, error) {
	encoded, err := json.Marshal(struct {
		UnitName   string   `json:"unitName"`
		Executable string   `json:"executable"`
		Arguments  []string `json:"arguments"`
		Properties []string `json:"properties"`
	}{p.UnitName, p.Executable, p.Arguments, p.Properties})
	return encoded, err
}

// MarshalJSON mirrors the Web-defaults camelCase output of an OCI plan.
func (p *OciExecutionPlan) MarshalJSON() ([]byte, error) {
	security, err := json.Marshal(p.Security)
	if err != nil {
		return nil, err
	}
	resources, err := json.Marshal(p.Resources)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(`{"containerId":`)
	writeJSONString(&buffer, p.ContainerId)
	buffer.WriteString(`,"imageReference":`)
	writeJSONString(&buffer, p.ImageReference)
	buffer.WriteString(`,"platform":`)
	writeJSONString(&buffer, p.Platform)
	buffer.WriteString(`,"security":`)
	buffer.Write(security)
	buffer.WriteString(`,"resources":`)
	buffer.Write(resources)
	buffer.WriteString("}")
	return buffer.Bytes(), nil
}

// MarshalJSON mirrors the Web-defaults camelCase output of an OCI security plan.
func (p OciSecurityPlan) MarshalJSON() ([]byte, error) {
	dropped, err := json.Marshal(p.DroppedCapabilities)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(`{"runAsUser":`)
	buffer.WriteString(strconv.FormatUint(uint64(p.RunAsUser), 10))
	buffer.WriteString(`,"runAsGroup":`)
	buffer.WriteString(strconv.FormatUint(uint64(p.RunAsGroup), 10))
	buffer.WriteString(`,"noNewPrivileges":`)
	buffer.WriteString(strconv.FormatBool(p.NoNewPrivileges))
	buffer.WriteString(`,"readOnlyRootFileSystem":`)
	buffer.WriteString(strconv.FormatBool(p.ReadOnlyRootFileSystem))
	buffer.WriteString(`,"droppedCapabilities":`)
	buffer.Write(dropped)
	buffer.WriteString(`,"seccompProfile":`)
	writeJSONString(&buffer, p.SeccompProfile)
	buffer.WriteString(`,"cgroupParent":`)
	writeJSONString(&buffer, p.CgroupParent)
	buffer.WriteString("}")
	return buffer.Bytes(), nil
}

func writeJSONString(buffer *bytes.Buffer, value string) {
	encoded, err := json.Marshal(value)
	if err != nil {
		// String marshaling cannot fail for valid Go strings.
		buffer.WriteString(`""`)
		return
	}
	buffer.Write(encoded)
}

func camelCaseEnum(name string) string {
	if name == "" {
		return name
	}
	return string(lowerFirstRune(name[0])) + name[1:]
}

func lowerFirstRune(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
