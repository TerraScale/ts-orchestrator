package workload

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// ReleaseShift splits a reconciled role's host desired generation into a
// release (the signed delivery intent generation) and a reconciliation step.
// Host desired generations are monotonic per node and role, so every write of
// a reconciled role needs a fresh generation; keeping the release in the high
// bits lets the next signed release supersede every reconciled step.
const ReleaseShift = 24

const maxRelease = uint64(1)<<(64-ReleaseShift) - 1

var (
	ErrNoRelease         = errors.New("workload has no active release to reconcile")
	ErrGenerationSpace   = errors.New("workload release generation space is exhausted")
	ErrReleaseSuperseded = errors.New("workload release has no active replicas")
)

// ReleaseGeneration is the first desired generation of a reconciled release.
func ReleaseGeneration(release uint64) (uint64, error) {
	if release == 0 || release > maxRelease {
		return 0, fmt.Errorf("%w: release generation %d", ErrGenerationSpace, release)
	}
	return release << ReleaseShift, nil
}

// ReleaseOf returns the release part of a desired generation.
func ReleaseOf(generation uint64) uint64 { return generation >> ReleaseShift }

// Release is the role's newest active release and its replicas.
type Release struct {
	Release  uint64
	Template host.Desired
	// Current are the release's assignments; Stale are active allocations of
	// an older release, which are retired once the release is ready.
	Current []placement.Assignment
	Stale   []placement.Assignment
}

// Converged reports whether every replica of the release is ready and no
// older release remains.
func (r Release) Converged() bool {
	if len(r.Stale) != 0 {
		return false
	}
	for _, assignment := range r.Current {
		if !assignment.Ready {
			return false
		}
	}
	return true
}

// CurrentRelease selects the newest release among active allocations. Its
// highest-generation allocation is the template for new replicas.
func CurrentRelease(observation Observation) (Release, error) {
	var release Release
	found := false
	for _, node := range slices.Sorted(maps.Keys(observation.Active)) {
		desired := observation.Active[node]
		if !found || ReleaseOf(desired.Generation) > release.Release ||
			ReleaseOf(desired.Generation) == release.Release && desired.Generation > release.Template.Generation {
			release.Release, release.Template, found = ReleaseOf(desired.Generation), desired, true
		}
	}
	if !found {
		return Release{}, ErrNoRelease
	}
	if ReleaseOf(observation.HighWater) != release.Release {
		return Release{}, fmt.Errorf("%w: newest committed release %d", ErrReleaseSuperseded, ReleaseOf(observation.HighWater))
	}
	for _, assignment := range observation.Assignments {
		if ReleaseOf(observation.Active[assignment.Node].Generation) == release.Release {
			assignment.Ordinal = len(release.Current)
			release.Current = append(release.Current, assignment)
		} else {
			release.Stale = append(release.Stale, assignment)
		}
	}
	return release, nil
}

// StepInput is one bounded reconciliation request for a stateless service.
type StepInput struct {
	Cell        string
	Spec        ServiceSpec
	Resources   placement.Resources
	Observation Observation
	Release     Release
	Replicas    int
	Epoch       uint64
}

// Step is the set of host desired writes for one reconciliation, sorted by
// node and sharing one fresh generation. An empty step means converged or
// waiting for in-flight replicas.
type Step struct {
	Generation uint64
	Writes     []host.Desired
	Added      int
	Withdrawn  int
	Waiting    bool
}

// PlanStep plans toward Replicas with placement.PlanWorkload and then limits
// the change: at most MaxSurge new replicas, failed replicas are replaced
// immediately, and ready replicas (current or stale) are withdrawn only when
// no replica is starting, at most MaxUnavailable per step.
func PlanStep(in StepInput) (Step, error) {
	assignments, err := placement.PlanWorkload(placement.WorkloadRequest{
		Cell: in.Cell, Role: in.Spec.Role, Replicas: in.Replicas, Request: in.Resources,
		Hosts: in.Observation.Candidates, Previous: in.Release.Current,
	})
	if err != nil {
		return Step{}, err
	}
	if err := checkDomainCap(in.Spec.Placement, in.Observation.Candidates, assignments); err != nil {
		return Step{}, err
	}
	current := make(map[string]placement.Assignment, len(in.Release.Current))
	for _, assignment := range in.Release.Current {
		current[assignment.Node] = assignment
	}
	var additions, withdrawals []string
	starting := false
	for _, assignment := range assignments {
		previous, existed := current[assignment.Node]
		switch {
		case assignment.Withdrawn && !previous.Ready:
			// Failed, starting or unreachable replicas serve nothing.
			withdrawals = append(withdrawals, assignment.Node)
		case assignment.Withdrawn:
			// Ready surplus waits for the unavailability budget below.
		case !existed:
			if len(additions) < in.Spec.Rollout.surge() {
				additions = append(additions, assignment.Node)
			}
			starting = true
		case !previous.Ready:
			starting = true
		}
	}
	if !starting {
		budget := in.Spec.Rollout.unavailable()
		for _, assignment := range assignments {
			if budget > 0 && assignment.Withdrawn && current[assignment.Node].Ready {
				withdrawals = append(withdrawals, assignment.Node)
				budget--
			}
		}
		for _, stale := range in.Release.Stale {
			if budget > 0 {
				withdrawals = append(withdrawals, stale.Node)
				budget--
			}
		}
	}
	if len(additions) == 0 && len(withdrawals) == 0 {
		return Step{Waiting: starting}, nil
	}
	generation := in.Observation.HighWater + 1
	if generation == 0 || ReleaseOf(generation) != in.Release.Release {
		return Step{}, ErrGenerationSpace
	}
	step := Step{Generation: generation, Added: len(additions), Withdrawn: len(withdrawals), Waiting: starting}
	template := in.Release.Template
	for _, node := range additions {
		step.Writes = append(step.Writes, host.Desired{
			Cell: in.Cell, Node: node, Environment: in.Spec.Environment, Role: in.Spec.Role,
			Digest: template.Digest, Generation: generation, AuthorityEpoch: in.Epoch,
			Args: slices.Clone(template.Args), Env: maps.Clone(template.Env),
		})
	}
	for _, node := range withdrawals {
		step.Writes = append(step.Writes, host.Desired{
			Cell: in.Cell, Node: node, Environment: in.Spec.Environment, Role: in.Spec.Role,
			Generation: generation, AuthorityEpoch: in.Epoch, Withdrawn: true,
		})
	}
	slices.SortFunc(step.Writes, func(a, b host.Desired) int { return cmp.Compare(a.Node, b.Node) })
	return step, nil
}

func checkDomainCap(constraints Constraints, hosts []placement.WorkloadHost, assignments []placement.Assignment) error {
	if constraints.MaxPerFailureDomain == 0 {
		return nil
	}
	domains := make(map[string]string, len(hosts))
	for _, candidate := range hosts {
		domains[candidate.Node] = candidate.FailureDomain
	}
	counts := make(map[string]int)
	for _, assignment := range assignments {
		if assignment.Withdrawn {
			continue
		}
		domain := domains[assignment.Node]
		counts[domain]++
		if counts[domain] > constraints.MaxPerFailureDomain {
			return fmt.Errorf("%w: failure domain %q exceeds %d replicas", placement.ErrInsufficientCapacity,
				domain, constraints.MaxPerFailureDomain)
		}
	}
	return nil
}
