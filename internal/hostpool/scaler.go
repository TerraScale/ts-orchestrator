package hostpool

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

const (
	DefaultInterval    = 30 * time.Second
	DefaultLaunchGrace = 15 * time.Minute
	DefaultDemandTTL   = 2 * time.Minute
)

// Provisioner creates and removes pool hosts. Launch must be idempotent for
// one node name, for example by using it as the journaled OCI create key, and
// Reclaim must refuse a host that still holds allocations or a TerraBase seat.
type Provisioner interface {
	Launch(ctx context.Context, epoch uint64, pool NodePool, launch Launch) error
	Reclaim(ctx context.Context, epoch uint64, pool NodePool, node string) error
}

type Config struct {
	Cell   string
	Pools  []NodePool
	Hosts  workload.HostView
	Fencer authority.Fencer
	// Provisioner nil keeps the scaler in recommend-only mode: plans are
	// computed and logged but no host is launched or reclaimed.
	Provisioner Provisioner
	Interval    time.Duration
	LaunchGrace time.Duration
	DemandTTL   time.Duration
	Now         func() time.Time
	Logf        func(string, ...any)
}

type demand struct {
	pool    string
	request placement.WorkloadRequest
	at      time.Time
}

// Scaler keeps generic host pools sized to placement demand. It implements
// workload.CapacityRequester and acts only on the regional authority leader.
type Scaler struct {
	config Config

	mu        sync.Mutex
	demands   map[string]demand
	launching map[string]time.Time
	idleSince map[string]time.Time
	last      map[string]Plan
	// recommended is the last recommend-only plan journaled per pool.
	recommended map[string]Plan
}

func NewScaler(config Config) (*Scaler, error) {
	if config.Hosts == nil || config.Fencer == nil || config.Cell == "" {
		return nil, errors.New("host pool scaler requires cell, host view and fencer")
	}
	if err := ValidatePools(config.Pools); err != nil {
		return nil, err
	}
	if config.Interval <= 0 {
		config.Interval = DefaultInterval
	}
	if config.LaunchGrace <= 0 {
		config.LaunchGrace = DefaultLaunchGrace
	}
	if config.DemandTTL <= 0 {
		config.DemandTTL = DefaultDemandTTL
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logf == nil {
		config.Logf = func(string, ...any) {}
	}
	config.Pools = slices.Clone(config.Pools)
	return &Scaler{config: config, demands: make(map[string]demand), launching: make(map[string]time.Time),
		idleSince: make(map[string]time.Time), last: make(map[string]Plan), recommended: make(map[string]Plan)}, nil
}

// RequestCapacity records unplaceable demand for the spec's pool, or for the
// first pool serving its role when the spec names none.
func (s *Scaler) RequestCapacity(spec workload.ServiceSpec, request placement.WorkloadRequest) {
	pool := ""
	for _, candidate := range s.config.Pools {
		if candidate.Environment != spec.Environment || !candidate.servesRole(spec.Role) {
			continue
		}
		if spec.Placement.NodePool == "" || spec.Placement.NodePool == candidate.Name {
			pool = candidate.Name
			break
		}
	}
	if pool == "" {
		s.config.Logf("hostpool: no host pool serves role %q in %q", spec.Role, spec.Environment)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.demands[spec.Role] = demand{pool: pool, request: request, at: s.config.Now()}
}

// Last returns the latest plan per pool for diagnostics.
func (s *Scaler) Last() map[string]Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.last)
}

func (s *Scaler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.config.Logf("hostpool reconciliation: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Tick plans and, with a provisioner, applies one step for every pool.
func (s *Scaler) Tick(ctx context.Context) error {
	snapshot := s.config.Fencer.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	now := s.config.Now()
	hosts, err := s.config.Hosts.ListHosts(ctx)
	if err != nil {
		return err
	}
	desired, err := s.config.Hosts.ListDesired(ctx, "")
	if err != nil {
		return err
	}
	allocations := make(map[string]int)
	for _, d := range desired {
		if !d.Withdrawn {
			allocations[d.Node]++
		}
	}
	var errs []error
	for _, pool := range s.config.Pools {
		in := PlanInput{Cell: s.config.Cell, Pool: pool, Now: now, IdleSince: make(map[string]time.Time)}
		registered := make(map[string]bool)
		for _, status := range hosts {
			r := status.Registration
			if _, member := pool.Ordinal(r.Node); !member {
				continue
			}
			if workload.Dedicated(r) || r.Environment != pool.Environment {
				errs = append(errs, fmt.Errorf("pool %q: host %q is dedicated or in another environment", pool.Name, r.Node))
				continue
			}
			registered[r.Node] = true
			in.Members = append(in.Members, Member{Node: r.Node, FailureDomain: r.FailureDomain,
				Allocations: allocations[r.Node]})
		}
		s.mu.Lock()
		for node, since := range s.launching {
			if _, member := pool.Ordinal(node); !member {
				continue
			}
			if registered[node] || now.Sub(since) > s.config.LaunchGrace {
				delete(s.launching, node)
				continue
			}
			in.Members = append(in.Members, Member{Node: node, Launching: true})
		}
		for _, member := range in.Members {
			if member.Launching || member.Allocations > 0 {
				delete(s.idleSince, member.Node)
				continue
			}
			if _, seen := s.idleSince[member.Node]; !seen {
				s.idleSince[member.Node] = now
			}
			in.IdleSince[member.Node] = s.idleSince[member.Node]
		}
		for role, entry := range s.demands {
			if now.Sub(entry.at) > s.config.DemandTTL {
				delete(s.demands, role)
				continue
			}
			if entry.pool == pool.Name {
				in.Demands = append(in.Demands, entry.request)
			}
		}
		s.mu.Unlock()
		slices.SortFunc(in.Demands, func(a, b placement.WorkloadRequest) int {
			if a.Role < b.Role {
				return -1
			}
			if a.Role > b.Role {
				return 1
			}
			return 0
		})
		plan, err := PlanPool(in)
		if err != nil {
			errs = append(errs, fmt.Errorf("pool %q: %w", pool.Name, err))
			continue
		}
		s.mu.Lock()
		s.last[pool.Name] = plan
		s.mu.Unlock()
		if err := s.apply(ctx, snapshot.Epoch, pool, plan, allocations, now); err != nil {
			errs = append(errs, fmt.Errorf("pool %q: %w", pool.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Scaler) apply(ctx context.Context, epoch uint64, pool NodePool, plan Plan, allocations map[string]int, now time.Time) error {
	if len(plan.Launch) == 0 && len(plan.Reclaim) == 0 {
		return nil
	}
	if s.config.Provisioner == nil {
		s.config.Logf("hostpool: pool %s recommends launching %d and reclaiming %v (%s); no provisioner configured",
			pool.Name, len(plan.Launch), plan.Reclaim, plan.Reason)
		s.mu.Lock()
		previous, seen := s.recommended[pool.Name]
		changed := !seen || !samePlan(previous, plan)
		s.recommended[pool.Name] = plan
		s.mu.Unlock()
		if changed {
			recordRecommendation(ctx, s.config.Cell, epoch, pool, plan)
		}
		return nil
	}
	for _, launch := range plan.Launch {
		if err := s.config.Fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		if err := s.config.Provisioner.Launch(ctx, epoch, pool, launch); err != nil {
			return fmt.Errorf("launch %s: %w", launch.Node, err)
		}
		s.mu.Lock()
		s.launching[launch.Node] = now
		s.mu.Unlock()
		s.config.Logf("hostpool: pool %s launching %s in %s (%s)", pool.Name, launch.Node, launch.FailureDomain, plan.Reason)
		recordLaunch(ctx, s.config.Cell, epoch, pool, plan, launch)
	}
	for _, node := range plan.Reclaim {
		if allocations[node] != 0 {
			continue
		}
		if err := s.config.Fencer.Guard(ctx, epoch); err != nil {
			return err
		}
		if err := s.config.Provisioner.Reclaim(ctx, epoch, pool, node); err != nil {
			return fmt.Errorf("reclaim %s: %w", node, err)
		}
		s.mu.Lock()
		delete(s.idleSince, node)
		s.mu.Unlock()
		s.config.Logf("hostpool: pool %s reclaimed idle host %s", pool.Name, node)
		recordReclaim(ctx, s.config.Cell, epoch, pool, plan, node)
	}
	return nil
}
