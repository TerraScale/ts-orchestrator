package placement

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
)

var (
	ErrInvalidWorkload      = errors.New("invalid workload placement request")
	ErrInsufficientCapacity = errors.New("insufficient workload placement capacity")
)

// Resources are integer CPU cores and bytes. Zero-valued host capacity is
// unknown capacity and therefore cannot satisfy a positive request.
type Resources struct {
	CPU         int   `json:"cpu"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

// WorkloadHost is one registered host candidate. Allocated must include all
// other workloads and reservations, while excluding the previous assignments
// for the workload being planned. CurrentSession and Admitted must describe the
// same host registration generation. Healthy is host health; an individual
// workload's readiness is carried by Assignment.
type WorkloadHost struct {
	Cell           string
	Node           string
	FailureDomain  string
	Roles          []string
	Capacity       Resources
	Allocated      Resources
	CurrentSession bool
	Admitted       bool
	Healthy        bool
	Cordoned       bool
}

// Assignment is a desired node/role pair. Ready and Pending are observation
// hints used only when a later plan considers Previous. New assignments are
// pending until a current-session host report confirms readiness.
type Assignment struct {
	Node      string `json:"node"`
	Role      string `json:"role"`
	Ordinal   int    `json:"ordinal"`
	Withdrawn bool   `json:"withdrawn"`
	Ready     bool   `json:"ready,omitempty"`
	Pending   bool   `json:"pending,omitempty"`
}

type WorkloadRequest struct {
	Cell     string
	Role     string
	Replicas int
	Request  Resources
	Hosts    []WorkloadHost
	Previous []Assignment
	// MaxPerFailureDomain caps the replicas placed in one failure domain,
	// retained assignments included; zero means unlimited. Retained
	// assignments past the cap are withdrawn so the plan can migrate.
	MaxPerFailureDomain int
}

// PlanWorkload makes a deterministic, capacity-aware desired node set for one
// workload. Healthy previous assignments are retained first, pending previous
// assignments remain in place to avoid duplicate in-flight launches, and
// failed/stale assignments are replaced on different nodes. Removed assignments
// are returned as Withdrawn so the caller can persist the entire plan atomically.
// An insufficient-capacity result has no partial assignments and causes no
// desired-state changes.
func PlanWorkload(request WorkloadRequest) ([]Assignment, error) {
	if !validToken(request.Cell) || !validToken(request.Role) || request.Replicas < 0 || request.Replicas > 1024 ||
		request.MaxPerFailureDomain < 0 || !positive(request.Request) {
		return nil, fmt.Errorf("%w: cell, role, replica count or resource request", ErrInvalidWorkload)
	}

	hosts := make(map[string]WorkloadHost, len(request.Hosts))
	for _, candidate := range request.Hosts {
		if !validToken(candidate.Cell) || !validToken(candidate.Node) || candidate.Cell != request.Cell ||
			candidate.FailureDomain != "" && !validToken(candidate.FailureDomain) ||
			!nonNegative(candidate.Capacity) || !nonNegative(candidate.Allocated) {
			return nil, fmt.Errorf("%w: malformed host %q", ErrInvalidWorkload, candidate.Node)
		}
		if _, exists := hosts[candidate.Node]; exists {
			return nil, fmt.Errorf("%w: duplicate host %q", ErrInvalidWorkload, candidate.Node)
		}
		hosts[candidate.Node] = candidate
	}

	previousNodes := make(map[string]Assignment, len(request.Previous))
	previous := make([]Assignment, 0, len(request.Previous))
	for _, assignment := range request.Previous {
		if assignment.Withdrawn {
			continue
		}
		if !validToken(assignment.Node) || assignment.Role != request.Role || assignment.Ordinal < 0 {
			return nil, fmt.Errorf("%w: malformed previous assignment", ErrInvalidWorkload)
		}
		if _, exists := previousNodes[assignment.Node]; exists {
			return nil, fmt.Errorf("%w: duplicate previous node %q", ErrInvalidWorkload, assignment.Node)
		}
		previousNodes[assignment.Node] = assignment
		previous = append(previous, assignment)
	}
	slices.SortFunc(previous, func(a, b Assignment) int {
		if ordinal := cmp.Compare(a.Ordinal, b.Ordinal); ordinal != 0 {
			return ordinal
		}
		return cmp.Compare(a.Node, b.Node)
	})

	active := make([]Assignment, 0, request.Replicas)
	usedNodes := make(map[string]struct{}, request.Replicas)
	quarantined := make(map[string]struct{})
	domainCounts := make(map[string]int)
	for _, old := range previous {
		candidate, exists := hosts[old.Node]
		if exists && schedulable(candidate, request.Role) && fits(candidate, request.Request) && (old.Ready || old.Pending) {
			if len(active) < request.Replicas && !domainFull(request, domainCounts, candidate) {
				old.Ordinal = len(active)
				active = append(active, old)
				usedNodes[old.Node] = struct{}{}
				domainCounts[candidate.FailureDomain]++
				continue
			}
		} else if exists {
			// A host with a failed workload is not immediately selected as its own
			// replacement during the same reconciliation.
			quarantined[old.Node] = struct{}{}
		}
	}

	for len(active) < request.Replicas {
		best, ok := chooseHost(request, hosts, usedNodes, quarantined, active, domainCounts)
		if !ok {
			return nil, fmt.Errorf("%w: placed %d of %d replicas", ErrInsufficientCapacity, len(active), request.Replicas)
		}
		active = append(active, Assignment{
			Node:    best.Node,
			Role:    request.Role,
			Ordinal: len(active),
			Pending: true,
		})
		usedNodes[best.Node] = struct{}{}
		domainCounts[best.FailureDomain]++
	}

	result := slices.Clone(active)
	kept := make(map[string]struct{}, len(active))
	for _, assignment := range active {
		kept[assignment.Node] = struct{}{}
	}
	withdrawn := make([]Assignment, 0, len(previous))
	for _, old := range previous {
		if _, exists := kept[old.Node]; exists {
			continue
		}
		old.Withdrawn = true
		withdrawn = append(withdrawn, old)
	}
	slices.SortFunc(withdrawn, func(a, b Assignment) int {
		return cmp.Compare(a.Node, b.Node)
	})
	return append(result, withdrawn...), nil
}

// PlanReplicas is the positional form used by delivery callbacks.
func PlanReplicas(cell, role string, replicas int, request Resources, hosts []WorkloadHost, previous []Assignment) ([]Assignment, error) {
	return PlanWorkload(WorkloadRequest{
		Cell:     cell,
		Role:     role,
		Replicas: replicas,
		Request:  request,
		Hosts:    hosts,
		Previous: previous,
	})
}

// domainFull reports whether the candidate's failure domain already holds the
// request's per-domain cap. A host without a domain counts as the "" domain,
// as the workload reconciler's own cap check does.
func domainFull(request WorkloadRequest, counts map[string]int, candidate WorkloadHost) bool {
	return request.MaxPerFailureDomain > 0 && counts[candidate.FailureDomain] >= request.MaxPerFailureDomain
}

func chooseHost(request WorkloadRequest, hosts map[string]WorkloadHost, used, quarantined map[string]struct{},
	active []Assignment, domainCounts map[string]int,
) (WorkloadHost, bool) {
	activeDomains := make(map[string]int, len(active))
	for _, assignment := range active {
		if candidate, ok := hosts[assignment.Node]; ok && candidate.FailureDomain != "" {
			activeDomains[candidate.FailureDomain]++
		}
	}

	var best WorkloadHost
	bestDomainCount := math.MaxInt
	bestLoad := math.Inf(1)
	found := false
	for _, candidate := range hosts {
		if !schedulable(candidate, request.Role) || !fits(candidate, request.Request) {
			continue
		}
		if _, exists := used[candidate.Node]; exists {
			continue
		}
		if _, exists := quarantined[candidate.Node]; exists {
			continue
		}
		if domainFull(request, domainCounts, candidate) {
			continue
		}

		domainCount := 0
		if candidate.FailureDomain != "" {
			domainCount = activeDomains[candidate.FailureDomain]
		}
		load := projectedLoad(candidate, request.Request)
		if !found || domainCount < bestDomainCount || domainCount == bestDomainCount &&
			(load < bestLoad || load == bestLoad && candidate.Node < best.Node) {
			best = candidate
			bestDomainCount = domainCount
			bestLoad = load
			found = true
		}
	}
	return best, found
}

func schedulable(candidate WorkloadHost, role string) bool {
	return candidate.CurrentSession && candidate.Admitted && candidate.Healthy && !candidate.Cordoned &&
		slices.Contains(candidate.Roles, role)
}

func fits(candidate WorkloadHost, request Resources) bool {
	return availableCPU(candidate.Capacity.CPU, candidate.Allocated.CPU) >= request.CPU &&
		availableBytes(candidate.Capacity.MemoryBytes, candidate.Allocated.MemoryBytes) >= request.MemoryBytes &&
		availableBytes(candidate.Capacity.DiskBytes, candidate.Allocated.DiskBytes) >= request.DiskBytes
}

func projectedLoad(candidate WorkloadHost, request Resources) float64 {
	loads := []float64{
		float64(candidate.Allocated.CPU+request.CPU) / float64(candidate.Capacity.CPU),
		float64(candidate.Allocated.MemoryBytes+request.MemoryBytes) / float64(candidate.Capacity.MemoryBytes),
		float64(candidate.Allocated.DiskBytes+request.DiskBytes) / float64(candidate.Capacity.DiskBytes),
	}
	return slices.Max(loads)
}

func availableCPU(capacity, allocated int) int {
	if allocated >= capacity {
		return 0
	}
	return capacity - allocated
}

func availableBytes(capacity, allocated int64) int64 {
	if allocated >= capacity {
		return 0
	}
	return capacity - allocated
}

func positive(value Resources) bool {
	return value.CPU > 0 && value.MemoryBytes > 0 && value.DiskBytes > 0
}

func nonNegative(value Resources) bool {
	return value.CPU >= 0 && value.MemoryBytes >= 0 && value.DiskBytes >= 0
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > 63 || !isLowerAlphaNumeric(value[0]) || !isLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		if !isLowerAlphaNumeric(value[i]) && value[i] != '-' {
			return false
		}
	}
	return true
}

func isLowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
