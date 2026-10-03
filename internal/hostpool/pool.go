// Package hostpool scales generic host pools. A pure planner decides how many
// pool hosts to launch for workloads that placement could not fit and which
// idle pool hosts to reclaim after a cooldown; a Scaler applies those plans
// through a Provisioner on the regional authority leader. Hosts dedicated to a
// TerraBase member are never pool members and never receive generic work.
package hostpool

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

var (
	ErrInvalidPool = errors.New("invalid host pool")
	nameRE         = regexp.MustCompile(`^[a-z][a-z0-9-]{0,40}$`)
	domainRE       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

const maxPoolHosts = 256

// NodePool is an operator-signed generic host pool. Pool hosts are named
// "<name>-<ordinal>" so membership and launch identity are deterministic.
// Shape is the host's total capacity; SystemReserveBytes is withheld from
// memory for the host agent and operating system, matching registration.
type NodePool struct {
	Name                string              `json:"name"`
	Environment         string              `json:"environment"`
	Roles               []string            `json:"roles"`
	Shape               placement.Resources `json:"shape"`
	SystemReserveBytes  int64               `json:"system_reserve_bytes,omitzero"`
	FailureDomains      []string            `json:"failure_domains"`
	Min                 int                 `json:"min"`
	Max                 int                 `json:"max"`
	IdleCooldownSeconds int                 `json:"idle_cooldown_seconds"`
}

// Validate checks the pool in isolation.
func (p NodePool) Validate() error {
	if !nameRE.MatchString(p.Name) || !nameRE.MatchString(p.Environment) || len(p.Roles) == 0 || len(p.Roles) > 32 {
		return fmt.Errorf("%w: name, environment or roles", ErrInvalidPool)
	}
	for _, role := range p.Roles {
		if !nameRE.MatchString(role) {
			return fmt.Errorf("%w: role %q", ErrInvalidPool, role)
		}
	}
	if p.Shape.CPU <= 0 || p.Shape.MemoryBytes <= 0 || p.Shape.DiskBytes <= 0 || p.SystemReserveBytes < 0 ||
		p.SystemReserveBytes >= p.Shape.MemoryBytes {
		return fmt.Errorf("%w: shape must be positive and exceed its system reserve", ErrInvalidPool)
	}
	if len(p.FailureDomains) == 0 || len(p.FailureDomains) > 3 {
		return fmt.Errorf("%w: one to three failure domains", ErrInvalidPool)
	}
	for index, domain := range p.FailureDomains {
		if !domainRE.MatchString(domain) || slices.Contains(p.FailureDomains[:index], domain) {
			return fmt.Errorf("%w: failure domain %q", ErrInvalidPool, domain)
		}
	}
	if p.Min < 0 || p.Max < p.Min || p.Max > maxPoolHosts {
		return fmt.Errorf("%w: host bounds %d..%d", ErrInvalidPool, p.Min, p.Max)
	}
	if p.IdleCooldownSeconds < 60 || p.IdleCooldownSeconds > 7*24*60*60 {
		return fmt.Errorf("%w: idle cooldown must be within 60s..7d", ErrInvalidPool)
	}
	return nil
}

// ValidatePools checks a pool set and rejects repeated names.
func ValidatePools(pools []NodePool) error {
	seen := make(map[string]struct{}, len(pools))
	for _, pool := range pools {
		if err := pool.Validate(); err != nil {
			return err
		}
		if _, exists := seen[pool.Name]; exists {
			return fmt.Errorf("%w: repeated pool %q", ErrInvalidPool, pool.Name)
		}
		seen[pool.Name] = struct{}{}
	}
	return nil
}

// NodeName is the deterministic node name and launch identity of an ordinal.
func (p NodePool) NodeName(ordinal int) string { return p.Name + "-" + strconv.Itoa(ordinal) }

// Ordinal returns the pool ordinal of a member node name.
func (p NodePool) Ordinal(node string) (int, bool) {
	suffix, ok := strings.CutPrefix(node, p.Name+"-")
	if !ok || suffix == "" || len(suffix) > 3 || suffix[0] == '0' && suffix != "0" {
		return 0, false
	}
	ordinal, err := strconv.Atoi(suffix)
	return ordinal, err == nil && ordinal >= 0 && ordinal < maxPoolHosts
}

func (p NodePool) servesRole(role string) bool { return slices.Contains(p.Roles, role) }

// virtualHost is a not-yet-registered pool host as placement would see it.
func (p NodePool) virtualHost(cell, node, domain string) placement.WorkloadHost {
	shape := p.Shape
	shape.MemoryBytes -= p.SystemReserveBytes
	return placement.WorkloadHost{Cell: cell, Node: node, FailureDomain: domain, Roles: slices.Clone(p.Roles),
		Capacity: shape, CurrentSession: true, Admitted: true, Healthy: true}
}

// Member is one registered or launching pool host.
type Member struct {
	Node          string
	FailureDomain string
	// Allocations counts the active workload allocations of every role.
	Allocations int
	Launching   bool
}

// Launch is one host the pool should create.
type Launch struct {
	Node          string
	FailureDomain string
}

// Plan is one pool decision. At most one host is reclaimed per plan.
type Plan struct {
	Launch  []Launch
	Reclaim []string
	Reason  string
}

// PlanInput is the observed state of one pool.
type PlanInput struct {
	Cell    string
	Pool    NodePool
	Members []Member
	// Demands are placement requests that failed on the current hosts. Their
	// Hosts include every generic candidate, pool members among them.
	Demands []placement.WorkloadRequest
	// IdleSince is when each member was first observed without allocations.
	IdleSince map[string]time.Time
	// ReservedOrdinals are pool ordinals whose node names belong to hosts
	// that cannot be members (dedicated or in another environment). They
	// are never launched, and they do not count as members.
	ReservedOrdinals []int
	Now              time.Time
}

// PlanPool launches the fewest hosts that let every demand served by the pool
// fit, spreading launches over the least-used failure domains, and otherwise
// reclaims one idle host whose cooldown elapsed while the pool exceeds Min.
func PlanPool(in PlanInput) (Plan, error) {
	if err := in.Pool.Validate(); err != nil {
		return Plan{}, err
	}
	members := slices.Clone(in.Members)
	slices.SortFunc(members, func(a, b Member) int { return cmp.Compare(a.Node, b.Node) })
	used := make(map[int]bool, len(members))
	for _, member := range members {
		ordinal, ok := in.Pool.Ordinal(member.Node)
		if !ok {
			return Plan{}, fmt.Errorf("%w: %q is not a member name", ErrInvalidPool, member.Node)
		}
		used[ordinal] = true
	}
	for _, ordinal := range in.ReservedOrdinals {
		used[ordinal] = true
	}
	headroom := in.Pool.Max - len(members)
	floor := max(in.Pool.Min-len(members), 0)

	demands := slices.DeleteFunc(slices.Clone(in.Demands), func(d placement.WorkloadRequest) bool {
		return !in.Pool.servesRole(d.Role)
	})
	need := floor
	reason := "below-min"
	if len(demands) > 0 {
		fitted := false
		for extra := floor; extra <= max(headroom, 0); extra++ {
			if fits(in, demands, launches(in.Pool, members, used, extra)) {
				need, fitted, reason = extra, true, "insufficient-capacity"
				break
			}
		}
		if !fitted {
			need, reason = max(headroom, floor), "pool-max-insufficient"
		}
	}
	if need > 0 {
		return Plan{Launch: launches(in.Pool, members, used, need), Reason: reason}, nil
	}
	if len(demands) > 0 {
		return Plan{Reason: reason}, nil
	}
	if len(members) <= in.Pool.Min {
		return Plan{Reason: "at-min"}, nil
	}
	cooldown := time.Duration(in.Pool.IdleCooldownSeconds) * time.Second
	var candidates []Member
	for _, member := range members {
		since, idle := in.IdleSince[member.Node]
		if !member.Launching && member.Allocations == 0 && idle && in.Now.Sub(since) >= cooldown {
			candidates = append(candidates, member)
		}
	}
	if len(candidates) == 0 {
		return Plan{Reason: "no-idle-host"}, nil
	}
	// Reclaim the highest ordinal so launches reuse low ordinals.
	victim := slices.MaxFunc(candidates, func(a, b Member) int {
		left, _ := in.Pool.Ordinal(a.Node)
		right, _ := in.Pool.Ordinal(b.Node)
		return cmp.Compare(left, right)
	})
	return Plan{Reclaim: []string{victim.Node}, Reason: "idle-cooldown-elapsed"}, nil
}

// launches chooses count new ordinals and failure domains deterministically.
func launches(pool NodePool, members []Member, used map[int]bool, count int) []Launch {
	domains := make(map[string]int, len(pool.FailureDomains))
	for _, member := range members {
		domains[member.FailureDomain]++
	}
	result := make([]Launch, 0, count)
	for ordinal := 0; len(result) < count && ordinal < maxPoolHosts; ordinal++ {
		if used[ordinal] {
			continue
		}
		domain := slices.MinFunc(pool.FailureDomains, func(a, b string) int {
			if c := cmp.Compare(domains[a], domains[b]); c != 0 {
				return c
			}
			return cmp.Compare(slices.Index(pool.FailureDomains, a), slices.Index(pool.FailureDomains, b))
		})
		domains[domain]++
		result = append(result, Launch{Node: pool.NodeName(ordinal), FailureDomain: domain})
	}
	return result
}

// fits simulates placement of every demand in order on the current hosts plus
// the launched and launching pool hosts, charging each plan to its hosts.
//
// Each demand's host snapshot excludes that demand's own allocations (the
// placement.WorkloadHost contract), so the snapshots disagree. The shared
// baseline is the real usage: a snapshot plus its own demand's retained
// replicas. Each demand is then planned with only its own previous replicas
// excluded again, and its new replicas are charged for the demands after it.
func fits(in PlanInput, demands []placement.WorkloadRequest, extra []Launch) bool {
	hosts := make(map[string]placement.WorkloadHost)
	order := []string{}
	add := func(candidate placement.WorkloadHost) {
		if _, exists := hosts[candidate.Node]; !exists {
			order = append(order, candidate.Node)
		}
		hosts[candidate.Node] = candidate
	}
	for _, demand := range demands {
		own := previousNodes(demand)
		for _, candidate := range demand.Hosts {
			if _, exists := hosts[candidate.Node]; !exists {
				if _, held := own[candidate.Node]; held {
					candidate.Allocated = plus(candidate.Allocated, demand.Request)
				}
				add(candidate)
			}
		}
	}
	for _, member := range in.Members {
		if _, exists := hosts[member.Node]; exists {
			continue
		}
		// A launching host, or a registered member the demand snapshots
		// predate, is modelled as an empty pool host. A registered member
		// that already holds allocations is left out: its usage is unknown.
		if member.Launching || member.Allocations == 0 {
			add(in.Pool.virtualHost(in.Cell, member.Node, member.FailureDomain))
		}
	}
	for _, launch := range extra {
		add(in.Pool.virtualHost(in.Cell, launch.Node, launch.FailureDomain))
	}
	for _, demand := range demands {
		own := previousNodes(demand)
		request := demand
		request.Hosts = make([]placement.WorkloadHost, 0, len(order))
		for _, node := range order {
			candidate := hosts[node]
			if _, held := own[node]; held {
				candidate.Allocated = minus(candidate.Allocated, demand.Request)
			}
			request.Hosts = append(request.Hosts, candidate)
		}
		assignments, err := placement.PlanWorkload(request)
		if err != nil {
			return false
		}
		for _, assignment := range assignments {
			if _, kept := own[assignment.Node]; assignment.Withdrawn || kept {
				// Retained replicas are already in the baseline; withdrawn
				// ones stay charged until they actually stop.
				continue
			}
			candidate := hosts[assignment.Node]
			candidate.Allocated = plus(candidate.Allocated, demand.Request)
			hosts[assignment.Node] = candidate
		}
	}
	return true
}

func previousNodes(demand placement.WorkloadRequest) map[string]struct{} {
	nodes := make(map[string]struct{}, len(demand.Previous))
	for _, assignment := range demand.Previous {
		if !assignment.Withdrawn {
			nodes[assignment.Node] = struct{}{}
		}
	}
	return nodes
}

func plus(left, right placement.Resources) placement.Resources {
	return placement.Resources{CPU: left.CPU + right.CPU, MemoryBytes: left.MemoryBytes + right.MemoryBytes,
		DiskBytes: left.DiskBytes + right.DiskBytes}
}

func minus(left, right placement.Resources) placement.Resources {
	return placement.Resources{CPU: max(left.CPU-right.CPU, 0), MemoryBytes: max(left.MemoryBytes-right.MemoryBytes, 0),
		DiskBytes: max(left.DiskBytes-right.DiskBytes, 0)}
}
