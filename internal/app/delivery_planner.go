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
)

type regionalDeliveryPlanner struct {
	hosts    *host.Controller
	profiles map[string]WorkloadProfile
}

func (p *regionalDeliveryPlanner) ApplyDesired(ctx context.Context, desired host.Desired) (host.Receipt, error) {
	return p.hosts.ApplyDesired(ctx, desired)
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

func (p *regionalDeliveryPlanner) Plan(ctx context.Context, intent delivery.Intent) ([]host.Desired, error) {
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
	statusByNode := make(map[string]host.HostStatus, len(statuses))
	candidates := make([]placement.WorkloadHost, 0, len(statuses))
	now := time.Now()
	for _, status := range statuses {
		if !status.Verified {
			return nil, errors.New("unverified host status cannot drive placement")
		}
		r := status.Registration
		statusByNode[r.Node] = status
		if r.Environment != intent.Environment {
			continue
		}
		live := now.Before(status.SessionExpiresAt)
		candidates = append(candidates, placement.WorkloadHost{
			Cell: r.Cell, Node: r.Node, FailureDomain: strings.ToLower(r.FailureDomain), Roles: slices.Clone(r.Roles),
			Capacity:       placement.Resources{CPU: r.Capacity.CPU, MemoryBytes: r.Capacity.MemoryBytes, DiskBytes: r.Capacity.DiskBytes},
			CurrentSession: live, Admitted: true, Healthy: live,
		})
	}
	candidateByNode := make(map[string]*placement.WorkloadHost, len(candidates))
	for index := range candidates {
		candidateByNode[candidates[index].Node] = &candidates[index]
	}
	var previous []placement.Assignment
	for _, desired := range allocations {
		if desired.Withdrawn {
			continue
		}
		if desired.Cell != intent.Cell {
			return nil, errors.New("allocation belongs to another cell")
		}
		if desired.Role == intent.Role && desired.Environment == intent.Environment {
			assignment := placement.Assignment{Node: desired.Node, Role: desired.Role, Ordinal: len(previous), Pending: true}
			if status, exists := statusByNode[desired.Node]; exists {
				for _, report := range status.Reports {
					if report.Role == desired.Role && report.Generation == desired.Generation && report.Digest == desired.Digest {
						assignment.Ready = report.State == "running"
						assignment.Pending = report.State != "failed"
					}
				}
			}
			previous = append(previous, assignment)
			continue
		}
		candidate := candidateByNode[desired.Node]
		if candidate == nil {
			continue
		}
		other, exists := p.profiles[desired.Role]
		if !exists {
			return nil, fmt.Errorf("active role %q lacks a resource profile", desired.Role)
		}
		candidate.Allocated.CPU += other.Resources.CPU
		candidate.Allocated.MemoryBytes += other.Resources.MemoryBytes
		candidate.Allocated.DiskBytes += other.Resources.DiskBytes
	}
	assignments, err := placement.PlanWorkload(placement.WorkloadRequest{
		Cell: intent.Cell, Role: intent.Role, Replicas: intent.DesiredReplicas,
		Request: profile.Resources, Hosts: candidates, Previous: previous,
	})
	if err != nil {
		return nil, err
	}
	result := make([]host.Desired, 0, len(assignments))
	for _, assignment := range assignments {
		status, exists := statusByNode[assignment.Node]
		if !exists {
			return nil, errors.New("placement selected an unknown host")
		}
		desired := host.Desired{
			Cell: intent.Cell, Node: assignment.Node, Environment: status.Registration.Environment,
			Role: intent.Role, Generation: intent.Generation, AuthorityEpoch: intent.AuthorityEpoch,
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
