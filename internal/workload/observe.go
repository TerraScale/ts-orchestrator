package workload

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// Snapshot is one consistent read of the regional host view.
type Snapshot struct {
	Cell        string
	Environment string
	Role        string
	Hosts       []host.HostStatus
	// Desired holds committed allocations of every role, including withdrawn
	// targets, so that other roles are charged against host capacity.
	Desired []host.Desired
	// Profiles are per-replica resources by role for every role that may hold
	// an allocation on a generic host.
	Profiles map[string]placement.Resources
	Now      time.Time
}

// Observation is the placement view of one role in one environment.
type Observation struct {
	// Candidates are the generic hosts in the environment. Hosts dedicated to
	// a TerraBase member are never candidates.
	Candidates []placement.WorkloadHost
	// Assignments are the role's active allocations with readiness hints.
	Assignments []placement.Assignment
	// Active maps node to the role's active committed allocation.
	Active map[string]host.Desired
	// Statuses maps node to every verified host status in the cell.
	Statuses map[string]host.HostStatus
	// HighWater is the largest generation committed for the role in this
	// environment, including withdrawn targets. Release supersession is
	// judged against it, so another environment's newer release of the same
	// role never stalls this one.
	HighWater uint64
	// NodeHighWater is the largest generation committed for the role on each
	// node in any environment. Host generations are fenced per node and role,
	// so a write to a node must exceed that node's entry.
	NodeHighWater map[string]uint64
}

// Shaped reports whether the role has ever been committed with a
// release-scoped generation (see ReleaseShift) on any node. Such a role must
// stay in that generation space even after the reconciler stops owning it:
// a plain intent generation would move every host backwards.
func (o Observation) Shaped() bool {
	for _, generation := range o.NodeHighWater {
		if ReleaseOf(generation) > 0 {
			return true
		}
	}
	return false
}

// Dedicated reports whether a host registration belongs to one TerraBase
// member. Dedicated hosts never run generic workloads.
func Dedicated(registration host.Registration) bool {
	return registration.ManagedPlacement != nil || registration.ManagedMember != nil
}

// Schedulable converts a verified registration into a placement host. The
// host's system reserve is removed from its memory capacity.
func Schedulable(status host.HostStatus, now time.Time) placement.WorkloadHost {
	r := status.Registration
	live := now.Before(status.SessionExpiresAt)
	memory := r.Capacity.MemoryBytes
	if r.SystemReserveBytes > 0 {
		memory = max(memory-r.SystemReserveBytes, 0)
	}
	return placement.WorkloadHost{
		Cell: r.Cell, Node: r.Node, FailureDomain: strings.ToLower(r.FailureDomain), Roles: slices.Clone(r.Roles),
		Capacity:       placement.Resources{CPU: r.Capacity.CPU, MemoryBytes: memory, DiskBytes: r.Capacity.DiskBytes},
		CurrentSession: live, Admitted: true, Healthy: live,
	}
}

// Observe builds the deterministic placement inputs for one role. It fails
// closed on unverified host status, cross-cell allocations and roles whose
// resources are unknown on a candidate host.
func Observe(snapshot Snapshot) (Observation, error) {
	observation := Observation{
		Active:        make(map[string]host.Desired),
		Statuses:      make(map[string]host.HostStatus, len(snapshot.Hosts)),
		NodeHighWater: make(map[string]uint64),
	}
	candidateIndex := make(map[string]int, len(snapshot.Hosts))
	for _, status := range snapshot.Hosts {
		if !status.Verified {
			return Observation{}, errors.New("unverified host status cannot drive placement")
		}
		r := status.Registration
		observation.Statuses[r.Node] = status
		if r.Environment != snapshot.Environment || Dedicated(r) {
			continue
		}
		candidateIndex[r.Node] = len(observation.Candidates)
		observation.Candidates = append(observation.Candidates, Schedulable(status, snapshot.Now))
	}
	for _, desired := range snapshot.Desired {
		if desired.Cell != snapshot.Cell {
			return Observation{}, errors.New("allocation belongs to another cell")
		}
		if desired.Role == snapshot.Role {
			observation.NodeHighWater[desired.Node] = max(observation.NodeHighWater[desired.Node], desired.Generation)
			if desired.Environment == snapshot.Environment {
				observation.HighWater = max(observation.HighWater, desired.Generation)
			}
		}
		if desired.Withdrawn {
			continue
		}
		if desired.Role == snapshot.Role && desired.Environment == snapshot.Environment {
			observation.Active[desired.Node] = desired
			continue
		}
		index, exists := candidateIndex[desired.Node]
		if !exists {
			continue
		}
		other, exists := snapshot.Profiles[desired.Role]
		if !exists {
			return Observation{}, fmt.Errorf("active role %q lacks a resource profile", desired.Role)
		}
		candidate := &observation.Candidates[index]
		candidate.Allocated.CPU += other.CPU
		candidate.Allocated.MemoryBytes += other.MemoryBytes
		candidate.Allocated.DiskBytes += other.DiskBytes
	}
	nodes := make([]string, 0, len(observation.Active))
	for node := range observation.Active {
		nodes = append(nodes, node)
	}
	slices.Sort(nodes)
	for _, node := range nodes {
		observation.Assignments = append(observation.Assignments,
			assignmentFor(observation.Active[node], observation.Statuses, len(observation.Assignments)))
	}
	return observation, nil
}

// assignmentFor marks an allocation ready when the current host reports it
// running and pending unless that exact target failed.
func assignmentFor(desired host.Desired, statuses map[string]host.HostStatus, ordinal int) placement.Assignment {
	assignment := placement.Assignment{Node: desired.Node, Role: desired.Role, Ordinal: ordinal, Pending: true}
	if status, exists := statuses[desired.Node]; exists {
		for _, report := range status.Reports {
			if report.Role == desired.Role && report.Generation == desired.Generation && report.Digest == desired.Digest {
				assignment.Ready = report.State == "running"
				assignment.Pending = report.State != "failed"
			}
		}
	}
	return assignment
}
