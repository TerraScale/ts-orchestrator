package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/roleidentity"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

type regionalDeliveryPlanner struct {
	nativeHistory *nativeHistory
	hosts         *host.Controller
	services      *specRegistry
	// profiles returns the current cell spec's delivery profiles.
	profiles func() map[string]WorkloadProfile
	// address returns the private address the cell spec grants a node.
	address  func(node string) string
	migrated func(string) bool
}

func (p *regionalDeliveryPlanner) ApplyDesired(ctx context.Context, desired host.Desired) (host.Receipt, error) {
	if p.migrated != nil && p.migrated(desired.Role) {
		return host.Receipt{}, errors.New("stateless desired writes are owned by the signed manager runtime")
	}
	if slices.Contains(serviceReleaseRoles, desired.Role) {
		if p.nativeHistory == nil {
			return host.Receipt{}, errors.New("native signed profile history is unavailable")
		}
		return p.nativeHistory.ApplyDesired(ctx, desired)
	}
	return p.hosts.ApplyDesired(ctx, desired)
}

func profileResources(profiles map[string]WorkloadProfile) map[string]placement.Resources {
	resources := make(map[string]placement.Resources, len(profiles))
	for role, profile := range profiles {
		resources[role] = profile.Resources
	}
	return resources
}

func validateWorkloadProfiles(cell string, profiles map[string]WorkloadProfile) error {
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
		for key := range profile.Secrets {
			if role == terrabase.Role && !vaultsecret.FileKey(key) {
				return fmt.Errorf("workload profile for %q takes only Vault secret files (keys ending in _FILE)", role)
			}
			if roleidentity.Reserved(role, key) {
				return fmt.Errorf("workload profile for %q: the host sets %s for its NATS identity", role, key)
			}
		}
		for key := range profile.Env {
			if roleidentity.Reserved(role, key) {
				return fmt.Errorf("workload profile for %q: the host sets %s for its NATS identity", role, key)
			}
		}
		if err := vaultsecret.ValidateRefs(cell, role, profile.Secrets, profile.Env); err != nil {
			return fmt.Errorf("workload profile for %q: %w", role, err)
		}
		// Secret names start with the role, so a longer role would share them.
		for other := range profiles {
			if len(profile.Secrets) != 0 && strings.HasPrefix(other, role+"-") {
				return fmt.Errorf("workload profile for %q names Vault secrets, so no role may extend its name (%q)", role, other)
			}
		}
		// A terrabase profile with settings configures the C# TerraBase
		// binary. Arguments would override the host-owned settings.
		if role == terrabase.Role && len(profile.Env) != 0 {
			if _, err := terrabase.ParseProfile(profile.Env); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
			if len(profile.Args) != 0 {
				return fmt.Errorf("workload profile for %q sets TerraBase settings only through env", role)
			}
		}
		// The ts-auth profile is signed and readable: it must hold every
		// setting and name its secrets, which hosts read from the Vault.
		if role == tsauth.Role {
			if err := tsauth.ValidateProfile(cell, profile.Args, profile.Env, profile.Secrets); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
			if err := tsauth.ValidateMembers(profile.Env, profiles[terrabase.Role].Env); err != nil {
				return fmt.Errorf("workload profile for %q: %w", role, err)
			}
		}
	}
	return nil
}

// terraBasePlacement places one C# member on each host the signed peer list
// names, by its node or its granted address (address may be nil), so a
// member never moves: while a listed host is unavailable the release cannot
// be placed. A member's data lives on its host, so a failed member, for
// example a release that never started, is replaced in place.
func terraBasePlacement(profile WorkloadProfile, replicas int, candidates []placement.WorkloadHost, previous []placement.Assignment,
	address func(string) string,
) ([]placement.WorkloadHost, []placement.Assignment, error) {
	if members, err := terrabase.ParseProfile(profile.Env); err == nil {
		if replicas != len(members.Peers) {
			return nil, nil, fmt.Errorf("terrabase release asks for %d members, %s lists %d", replicas, terrabase.EnvPeers, len(members.Peers))
		}
		candidates = slices.DeleteFunc(slices.Clone(candidates), func(candidate placement.WorkloadHost) bool {
			var granted string
			if address != nil {
				granted = address(candidate.Node)
			}
			_, listed := members.Member(candidate.Node, granted)
			return !listed
		})
	}
	previous = slices.Clone(previous)
	for i := range previous {
		previous[i].Pending = true
	}
	return candidates, previous, nil
}

// releaseFailures is the observed assignments for planning a release of
// digest. A failed replica of another digest failed with its own release,
// not with its host, so the release replaces it in place instead of
// quarantining the host: the rollback of a release that crashed on every
// replica must not need as many spare hosts as there are replicas.
func releaseFailures(observation workload.Observation, digest, configDigest string) []placement.Assignment {
	previous := slices.Clone(observation.Assignments)
	for i, assignment := range previous {
		if active, ok := observation.Active[assignment.Node]; ok && (active.Digest != digest || delivery.ConfigDigestOf(active.Args, active.Env, active.Secrets) != configDigest) {
			previous[i].Pending = true
		}
	}
	return previous
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
	profiles := p.profiles()
	profile, ok := profiles[intent.Role]
	if !ok {
		return nil, fmt.Errorf("no workload profile for role %q", intent.Role)
	}
	if slices.Contains(serviceReleaseRoles, intent.Role) {
		if p.nativeHistory == nil {
			return nil, errors.New("native signed profile history is unavailable")
		}
		var err error
		profile, err = p.nativeHistory.profile(ctx, intent)
		if err != nil {
			return nil, err
		}
		profiles[intent.Role] = profile
	}
	if delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets) != intent.ConfigDigest {
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
	if p.nativeHistory == nil {
		return nil, errors.New("native signed profile history is unavailable")
	}
	// The target uses its prepared profile; colocated roles use their committed reservations.
	otherAllocations := slices.DeleteFunc(slices.Clone(allocations), func(d host.Desired) bool { return d.Role == intent.Role })
	resources, err := p.nativeHistory.resources(ctx, otherAllocations, profileResources(profiles))
	if err != nil {
		return nil, err
	}
	observation, err := workload.Observe(workload.Snapshot{
		Cell: intent.Cell, Environment: intent.Environment, Role: intent.Role,
		Hosts: statuses, Desired: allocations, Profiles: resources, Now: time.Now(),
	})
	if err != nil {
		return nil, err
	}
	if *shape, err = shapeOf(observation); err != nil {
		return nil, err
	}
	candidates, previous := observation.Candidates, releaseFailures(observation, intent.ArtifactDigest, intent.ConfigDigest)
	if intent.Role == terrabase.Role {
		if candidates, previous, err = terraBasePlacement(profile, shape.Replicas, candidates, previous, p.address); err != nil {
			return nil, err
		}
	}
	maxPerFailureDomain := releasePlacementDomainCap(intent.Role)
	assignments, err := placement.PlanWorkload(placement.WorkloadRequest{
		Cell: intent.Cell, Role: intent.Role, Replicas: shape.Replicas,
		Request: profile.Resources, Hosts: candidates, Previous: previous, MaxPerFailureDomain: maxPerFailureDomain,
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
			desired.Secrets = maps.Clone(profile.Secrets)
		}
		result = append(result, desired)
	}
	slices.SortFunc(result, func(a, b host.Desired) int { return strings.Compare(a.Node, b.Node) })
	return result, nil
}

func releasePlacementDomainCap(role string) int {
	if role == tsauth.Role {
		return 1
	}
	return 0
}
