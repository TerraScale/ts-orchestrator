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
	"regexp"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
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
)

var ErrInvalidReport = errors.New("invalid host load report")

var roleRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Report is one host's load at the moment it was sampled.
type Report struct {
	SchemaVersion uint64      `json:"schema_version"`
	Host          HostUsage   `json:"host"`
	Roles         []RoleUsage `json:"roles,omitempty"`
}

// HostUsage is whole-host utilization as fractions in [0,1]. A nil field was
// not measured this interval (for example the first CPU sample, which has no
// earlier counter to diff against).
type HostUsage struct {
	CPU    *float64 `json:"cpu_util,omitempty"`
	Memory *float64 `json:"mem_util,omitempty"`
	Disk   *float64 `json:"disk_util,omitempty"`
}

// RoleUsage is one native role's cgroup v2 usage in absolute units, so the
// controller can relate it to the role's signed resource request, plus the
// TerraBase load block when the role is a TerraBase member that reports one.
type RoleUsage struct {
	Role        string             `json:"role"`
	CPUCores    *float64           `json:"cpu_cores,omitempty"`
	MemoryBytes *uint64            `json:"memory_bytes,omitempty"`
	TerraBase   *memberstatus.Load `json:"terrabase,omitempty"`
}

// Validate checks the schema version, role tokens and every value bound.
func (r Report) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d", ErrInvalidReport, r.SchemaVersion)
	}
	for _, value := range []*float64{r.Host.CPU, r.Host.Memory, r.Host.Disk} {
		if value != nil && !fraction(*value) {
			return fmt.Errorf("%w: host utilization out of range", ErrInvalidReport)
		}
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
		if role.TerraBase != nil {
			if err := role.TerraBase.Validate(); err != nil {
				return fmt.Errorf("%w: role %q: %v", ErrInvalidReport, role.Role, err)
			}
		}
	}
	return nil
}

func fraction(value float64) bool { return finiteWithin(value, 1) }

func finiteWithin(value, limit float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= limit
}
