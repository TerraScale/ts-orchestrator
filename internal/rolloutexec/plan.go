package rolloutexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"

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

// ReleaseRolloutID is the rollout ID prefix of a desired release generation.
func ReleaseRolloutID(generation uint64) string { return fmt.Sprintf("release-g%d", generation) }

// ReleaseProgram derives the executor's program from the cell's desired
// release (rollout.Store.Desired): the controllers that do not run it yet
// move to it from the release they all prove now, one per wave and the seed
// last. A started rollout keeps the units and predecessor it began with.
// Nothing starts while the cell is paused, has no desired release, already
// runs it everywhere, or knows it as bad.
//
// ponytail: controllers only; hosts join once their steps and proofs travel
// over the host session (the second program rollout of SelfUpdateProgram).
// A controller that falls behind after its generation completed waits for
// the next generation.
type ReleaseProgram struct {
	Store       *rollout.Store
	Proofs      ProofSource
	Controllers []rollout.Unit
	Policy      rollout.Policy
	Freshness   time.Duration
	Now         func() time.Time
}

// Program implements Executor.Program.
func (p ReleaseProgram) Program(ctx context.Context) (Program, error) {
	desired, _, err := p.Store.Desired(ctx)
	if err != nil {
		return nil, err
	}
	release := desired.Release
	if release.Generation == 0 || desired.Paused || len(p.Controllers) == 0 {
		return nil, nil
	}
	id := ReleaseRolloutID(release.Generation)
	existing, _, err := p.Store.Load(ctx, id+"-controllers")
	if err == nil {
		// The stored plan is this generation's step, whatever it ended as.
		return Program{existingSpec(existing)}, nil
	}
	if !errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, err
	}
	units, from, err := p.behind(p.Controllers, release.Digest)
	if err != nil || len(units) == 0 {
		return nil, err
	}
	if bad, err := p.Store.IsKnownBad(ctx, release.Digest); err != nil || bad {
		return nil, err
	}
	return SelfUpdateProgram(id, desired.Cell, from, release.Digest, units, nil, p.Policy), nil
}

func existingSpec(record rollout.Record) rollout.Spec {
	units := make([]rollout.Unit, 0, len(record.Units))
	for id, progress := range record.Units {
		units = append(units, rollout.Unit{ID: id, Group: progress.Group, Seed: progress.Seed})
	}
	return rollout.Spec{RolloutID: record.RolloutID, Kind: record.Kind, Cell: record.Cell, FromDigest: record.FromDigest,
		ToDigest: record.ToDigest, Units: units, Policy: record.Policy}
}

// behind returns the units that do not run target and the one release they
// all run. Every unit must have a fresh proof, so a step never starts while
// a peer is silent, and the units behind must agree on their release.
func (p ReleaseProgram) behind(units []rollout.Unit, target string) ([]rollout.Unit, string, error) {
	now, freshness := time.Now().UTC(), p.Freshness
	if p.Now != nil {
		now = p.Now().UTC()
	}
	if freshness <= 0 {
		freshness = DefaultProofFreshness
	}
	var behind []rollout.Unit
	digest := ""
	for _, unit := range units {
		proof, ok := p.Proofs.Latest(unit.ID)
		if !ok || !isFresh(proof, now, freshness) {
			return nil, "", fmt.Errorf("unit %s has no fresh health proof", unit.ID)
		}
		if proof.BinarySHA256 == target {
			continue
		}
		if digest != "" && proof.BinarySHA256 != digest {
			return nil, "", fmt.Errorf("units run different releases (%s, %s)", short(digest), short(proof.BinarySHA256))
		}
		digest = proof.BinarySHA256
		behind = append(behind, unit)
	}
	return behind, digest, nil
}
