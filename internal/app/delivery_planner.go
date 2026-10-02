package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

type regionalDeliveryPlanner struct {
	hosts     *host.Controller
	profiles  map[string]WorkloadProfile
	workloads *workload.Reconciler
}

func (p *regionalDeliveryPlanner) ApplyDesired(ctx context.Context, desired host.Desired) (host.Receipt, error) {
	return p.hosts.ApplyDesired(ctx, desired)
}

func (p *regionalDeliveryPlanner) resourceProfiles() map[string]placement.Resources {
	resources := make(map[string]placement.Resources, len(p.profiles))
	for role, profile := range p.profiles {
		resources[role] = profile.Resources
	}
	return resources
}

func validateWorkloadProfiles(profiles map[string]WorkloadProfile) error {
	for role, profile := range profiles {
		if !grantToken.MatchString(role) || profile.Resources.CPU <= 0 || profile.Resources.CPU > 4096 ||
			profile.Resources.MemoryBytes <= 0 || profile.Resources.MemoryBytes > 1<<50 ||
			profile.Resources.DiskBytes <= 0 || profile.Resources.DiskBytes > 1<<50 {
			return fmt.Errorf("invalid workload resource profile for role %q", role)
		}
		if len(profile.Args) > 64 || len(profile.Env) > 64 {
			return fmt.Errorf("workload profile for %q exceeds argument or environment limit", role)
		}
		for _, arg := range profile.Args {
			if len(arg) > 4096 {
				return fmt.Errorf("workload argument for %q is too long", role)
			}
		}
		for key, value := range profile.Env {
			if key == "" || len(value) > 4096 {
				return fmt.Errorf("workload environment for %q is invalid", role)
			}
		}
	}
	return nil
}

// Plan plans a release with the intent's own generation and replica count.
func (p *regionalDeliveryPlanner) Plan(ctx context.Context, intent delivery.Intent) ([]host.Desired, error) {
	var shape delivery.PlanShape
	return p.plan(ctx, intent, func(workload.Observation) (delivery.PlanShape, error) {
		return delivery.PlanShape{Generation: intent.Generation, Replicas: intent.DesiredReplicas}, nil
	}, &shape)
}

func (p *regionalDeliveryPlanner) plan(ctx context.Context, intent delivery.Intent,
	shapeOf func(workload.Observation) (delivery.PlanShape, error), shape *delivery.PlanShape,
) ([]host.Desired, error) {
	profile, ok := p.profiles[intent.Role]
	if !ok {
		return nil, fmt.Errorf("no workload profile for role %q", intent.Role)
	}
	if delivery.ConfigDigestOf(profile.Args, profile.Env) != intent.ConfigDigest {
		return nil, errors.New("intent configuration digest differs from controller workload profile")
	}
	statuses, err := p.hosts.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	allocations, err := p.hosts.ListDesired(ctx, "")
	if err != nil {
		return nil, err
	}
	observation, err := workload.Observe(workload.Snapshot{
		Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role,
		Hosts: statuses, Desired: allocations, Profiles: p.resourceProfiles(), Now: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	if *shape, err = shapeOf(observation); err != nil {
		return nil, err
	}
	assignments, err := placement.PlanWorkload(placement.WorkloadRequest{
		Cell: intent.Cell, Role: intent.Role, Replicas: shape.Replicas,
		Request: profile.Resources, Hosts: observation.Candidates, Previous: observation.Assignments,
	})
	if err != nil {
		return nil, err
	}
	result := make([]host.Desired, 0, len(assignments))
	for _, assignment := range assignments {
		status, exists := observation.Statuses[assignment.Node]
		if !exists {
			return nil, errors.New("placement selected an unknown host")
		}
		desired := host.Desired{
			Cell: intent.Cell, Node: assignment.Node, Environment: status.Registration.Environment,
			Role: intent.Role, Generation: shape.Generation, AuthorityEpoch: intent.AuthorityEpoch,
			Withdrawn: assignment.Withdrawn,
		}
		if !assignment.Withdrawn {
			desired.Digest = intent.ArtifactDigest
			desired.Args = slices.Clone(profile.Args)
			desired.Env = maps.Clone(profile.Env)
		}
		result = append(result, desired)
	}
	slices.SortFunc(result, func(a, b host.Desired) int { return strings.Compare(a.Node, b.Node) })
	return result, nil
}
