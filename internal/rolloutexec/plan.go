package rolloutexec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// ControllerGroup is the quorum group of the regional controllers.
const ControllerGroup = "controllers"

// ControllerUnits returns the controller units of a cell. seed names the
// founding controller, which rollout.PlanWaves always replaces last and
// alone; every controller shares one group, so a wave never restarts two.
func ControllerUnits(controllers []string, seed string) ([]rollout.Unit, error) {
	if seed != "" && !slices.Contains(controllers, seed) {
		return nil, fmt.Errorf("%w: seed controller %q is not a controller", ErrInvalid, seed)
	}
	units := make([]rollout.Unit, 0, len(controllers))
	for _, id := range controllers {
		units = append(units, rollout.Unit{ID: id, Group: ControllerGroup, Seed: id == seed})
	}
	return units, nil
}

// HostUnits returns the host units of a cell from the TerraBase partitions
// each host serves a seat of. Hosts that share a partition, directly or
// through other hosts, share a group, so a wave never takes two seats of
// one partition. A host without seats is its own group.
func HostUnits(partitions map[string][]string) []rollout.Unit {
	hosts := slices.Sorted(maps.Keys(partitions))
	parent := make(map[string]string, len(hosts))
	var find func(string) string
	find = func(host string) string {
		if parent[host] == host {
			return host
		}
		root := find(parent[host])
		parent[host] = root
		return root
	}
	for _, host := range hosts {
		parent[host] = host
	}
	owner := map[string]string{}
	for _, host := range hosts {
		for _, partition := range partitions[host] {
			first, seen := owner[partition]
			if !seen {
				owner[partition] = host
				continue
			}
			a, b := find(first), find(host)
			if a != b {
				// Keep the smallest host as the root so the group name
				// depends only on the input set.
				parent[max(a, b)] = min(a, b)
			}
		}
	}
	units := make([]rollout.Unit, 0, len(hosts))
	for _, host := range hosts {
		sum := sha256.Sum256([]byte(find(host)))
		units = append(units, rollout.Unit{ID: host, Group: "hosts-" + hex.EncodeToString(sum[:8])})
	}
	return units
}

// Program is an ordered list of rollouts. The executor starts each one only
// after the previous one completed, so the controllers finish before any
// host moves, and stops the program at the first rollout that did not
// complete (rolled back, aborted).
type Program []rollout.Spec

// SelfUpdateProgram returns the controller rollout followed by the host
// rollout of one orchestrator release. Rollout IDs are derived from id.
func SelfUpdateProgram(id, cell, from, to string, controllers []rollout.Unit, hosts []rollout.Unit,
	policy rollout.Policy,
) Program {
	var program Program
	if len(controllers) > 0 {
		program = append(program, rollout.Spec{RolloutID: id + "-controllers", Kind: rollout.KindController, Cell: cell,
			FromDigest: from, ToDigest: to, Units: controllers, Policy: policy})
	}
	if len(hosts) > 0 {
		program = append(program, rollout.Spec{RolloutID: id + "-hosts", Kind: rollout.KindHost, Cell: cell,
			FromDigest: from, ToDigest: to, Units: hosts, Policy: policy})
	}
	return program
}
