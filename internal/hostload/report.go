// Package hostload carries host and TerraBase load telemetry from host
// agents to the regional controller's autoscaler. A host agent samples its
// cgroup v2 role groups, /proc and statfs (Sampler), publishes one bounded
// Report over its authenticated host session, and the authority leader's
// Aggregator turns accepted reports into per-replica autoscale samples.
//
// Reports are operational telemetry, never evidence: nothing that admits,
// fences, retires or signs anything reads them, and the controller only
// accepts them when the signed controller config opts into host telemetry.
package hostload

import (
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

// SchemaVersion is the only Report version this build accepts.
const SchemaVersion = 1

// Bounds on what one report may carry.
const (
	MaxRoles = 32
	// MaxCPUCores bounds a role's measured CPU use; no OCI shape exceeds it.
	MaxCPUCores = 1024
	// MaxMemoryBytes bounds a role's measured memory use.
	MaxMemoryBytes = 1 << 44
	// MaxFilesystems allows the host roots and one volume per managed role.
	MaxFilesystems     = MaxRoles + 5
	MaxFilesystemBytes = 1 << 50
	// MaxNetworkBps bounds a host's receive or transmit rate: 1 TiB/s.
	MaxNetworkBps = 1 << 40
	// MaxLoad1 bounds the one-minute load average; the kernel's PID limit
	// keeps real values far below it.
	MaxLoad1 = 1e6
)

var ErrInvalidReport = errors.New("invalid host load report")

var roleRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Report is one host's load at the moment it was sampled.
type Report struct {
	SchemaVersion uint64      `json:"schema_version"`
	Host          HostUsage   `json:"host"`
	Roles         []RoleUsage `json:"roles,omitempty"`
}

// HostUsage carries capacity, filesystems and utilization fractions in [0,1].
// A nil field was not measured this interval (for example the first CPU sample,
// which has no earlier counter to diff against).
type HostUsage struct {
	FilesystemsIncomplete bool                           `json:"filesystems_incomplete,omitzero"`
	CPUCores              int                            `json:"cpu_capacity_cores,omitzero"`
	MemoryBytes           uint64                         `json:"memory_capacity_bytes,omitzero"`
	CPU                   *float64                       `json:"cpu_util,omitempty"`
	Memory                *float64                       `json:"mem_util,omitempty"`
	Disk                  *float64                       `json:"disk_util,omitempty"`
	Filesystems           []observability.FilesystemView `json:"filesystems,omitempty"`
	// NetworkRxBps and NetworkTxBps are bytes per second over every
	// non-loopback interface since the previous sample; Load1 is the
	// one-minute load average.
	NetworkRxBps *float64 `json:"net_rx_bps,omitempty"`
	NetworkTxBps *float64 `json:"net_tx_bps,omitempty"`
	Load1        *float64 `json:"load1,omitempty"`
}

// RoleUsage is one native role's cgroup v2 usage in absolute units, so the
// controller can relate it to the role's signed resource request, plus the
// TerraBase load block when the role is a TerraBase member that reports one.
type RoleUsage struct {
	Role        string                    `json:"role"`
	CPUCores    *float64                  `json:"cpu_cores,omitempty"`
	MemoryBytes *uint64                   `json:"memory_bytes,omitempty"`
	CPULimit    *float64                  `json:"cpu_limit_cores,omitempty"`
	MemoryLimit *uint64                   `json:"memory_limit_bytes,omitempty"`
	LimitsRead  bool                      `json:"limits_read,omitzero"`
	TerraBase   *memberstatus.Load        `json:"terrabase,omitempty"`
	WAN         *terrabase.WANObservation `json:"wan,omitempty"`
}

// Validate checks the schema version, role tokens and every value bound.
func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d", ErrInvalidReport, r.SchemaVersion)
	}
	if r.Host.CPUCores < 0 || r.Host.CPUCores > MaxCPUCores || r.Host.MemoryBytes > MaxMemoryBytes {
		return fmt.Errorf("%w: host capacity out of range", ErrInvalidReport)
	}
	for _, value := range []*float64{r.Host.CPU, r.Host.Memory, r.Host.Disk} {
		if value != nil && !fraction(*value) {
			return fmt.Errorf("%w: host utilization out of range", ErrInvalidReport)
		}
	}
	for _, value := range []*float64{r.Host.NetworkRxBps, r.Host.NetworkTxBps} {
		if value != nil && !finiteWithin(*value, MaxNetworkBps) {
			return fmt.Errorf("%w: host network rate out of range", ErrInvalidReport)
		}
	}
	if r.Host.Load1 != nil && !finiteWithin(*r.Host.Load1, MaxLoad1) {
		return fmt.Errorf("%w: host load out of range", ErrInvalidReport)
	}
	if len(r.Host.Filesystems) > MaxFilesystems {
		return fmt.Errorf("%w: more than %d filesystems", ErrInvalidReport, MaxFilesystems)
	}
	filesystems := make(map[string]bool, len(r.Host.Filesystems))
	for _, filesystem := range r.Host.Filesystems {
		if !validFilesystem(filesystem) || filesystems[filesystem.Role] {
			return fmt.Errorf("%w: invalid or repeated filesystem role %q", ErrInvalidReport, filesystem.Role)
		}
		filesystems[filesystem.Role] = true
	}
	if len(r.Roles) > MaxRoles {
		return fmt.Errorf("%w: more than %d roles", ErrInvalidReport, MaxRoles)
	}
	seen := make(map[string]struct{}, len(r.Roles))
	for _, role := range r.Roles {
		if !roleRE.MatchString(role.Role) {
			return fmt.Errorf("%w: role token", ErrInvalidReport)
		}
		if _, repeated := seen[role.Role]; repeated {
			return fmt.Errorf("%w: repeated role %q", ErrInvalidReport, role.Role)
		}
		seen[role.Role] = struct{}{}
		if role.CPUCores != nil && !finiteWithin(*role.CPUCores, MaxCPUCores) {
			return fmt.Errorf("%w: role %q CPU out of range", ErrInvalidReport, role.Role)
		}
		if role.MemoryBytes != nil && *role.MemoryBytes > MaxMemoryBytes {
			return fmt.Errorf("%w: role %q memory out of range", ErrInvalidReport, role.Role)
		}
		if role.CPULimit != nil && (!finiteWithin(*role.CPULimit, MaxCPUCores) || *role.CPULimit == 0) ||
			role.MemoryLimit != nil && *role.MemoryLimit > MaxMemoryBytes {
			return fmt.Errorf("%w: role limit out of range", ErrInvalidReport)
		}
		if role.TerraBase != nil {
			if err := role.TerraBase.Validate(); err != nil {
				return fmt.Errorf("%w: role %q: %v", ErrInvalidReport, role.Role, err)
			}
		}
		if role.WAN != nil {
			if role.Role != terrabase.Role {
				return fmt.Errorf("%w: WAN observations require the terrabase role", ErrInvalidReport)
			}
			if err := role.WAN.Validate(); err != nil {
				return fmt.Errorf("%w: role %q WAN: %v", ErrInvalidReport, role.Role, err)
			}
		}
	}
	return nil
}

func validFilesystem(filesystem observability.FilesystemView) bool {
	return protocol.ValidateSubjectToken(filesystem.Role) == nil &&
		len(filesystem.Path) <= 4096 && utf8.ValidString(filesystem.Path) &&
		filepath.IsAbs(filesystem.Path) && filepath.Clean(filesystem.Path) == filesystem.Path &&
		!strings.ContainsFunc(filesystem.Path, unicode.IsControl) &&
		filesystem.SizeBytes > 0 && filesystem.SizeBytes <= MaxFilesystemBytes &&
		filesystem.AvailBytes <= filesystem.FreeBytes && filesystem.FreeBytes <= filesystem.SizeBytes &&
		filesystem.Files <= MaxFilesystemBytes && filesystem.FilesFree <= filesystem.Files
}

func fraction(value float64) bool { return finiteWithin(value, 1) }

func finiteWithin(value, limit float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= limit
}
