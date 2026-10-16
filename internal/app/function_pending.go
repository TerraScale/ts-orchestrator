package app

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// A failed authority or manager observation holds the entire scaling decision.
func functionDemandSource(config functionControllerConfig) func(context.Context) ([]nodescale.CapacityDemand, error) {
	return func(ctx context.Context) ([]nodescale.CapacityDemand, error) {
		if config.Authority == nil || config.Client == nil || config.Roots == nil || config.Factory == nil || config.Worker == nil || config.Evidence == nil || config.Material.Reader.Roots == nil ||
			!release.ValidRegion(strings.ToUpper(config.Cell)) || !release.ValidEnvironment(config.Environment) {
			return nil, errors.New("function capacity requires current authority, manager and qualified worker source")
		}
		epoch := config.Authority.Current().Epoch
		if err := config.Authority.Guard(ctx, epoch); err != nil {
			return nil, err
		}
		entries, err := config.Authority.ListFunctionIntents(ctx)
		if err != nil {
			return nil, err
		}
		reader := config.Material.Reader
		reader.Authority = config.Authority
		current := functionIntentSource{reader: reader, authority: config.Authority, epoch: epoch, roots: config.Roots, rootHead: config.Roots.reply("").Head}
		slots := map[string]uint64{}
		for _, entry := range entries {
			stored, err := authority.DecodeFunctionIntent(entry)
			if err != nil {
				return nil, err
			}
			proof, err := current.CurrentFunction(ctx, stored.Claim.TenantID, stored.Claim.FunctionID)
			if err != nil {
				return nil, err
			}
			claim := proof.Claim()
			if claim.Cell != strings.ToUpper(config.Cell) || claim.Environment != config.Environment {
				return nil, release.ErrExpectationMismatch
			}
			worker, err := config.Worker(ctx, proof)
			if err != nil {
				return nil, err
			}
			target := release.ContainerTarget{
				Cell: claim.Cell, Environment: claim.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: worker.Architecture,
			}
			allocations, err := currentContainerAllocations(ctx, config.Factory, worker.Bundle, reader.Roots(), target)
			if err != nil {
				return nil, err
			}
			verified, err := release.VerifyContainerCurrent(ctx, worker.Bundle, reader.Roots(), target, time.Now(), proof.ExpiresAt(), config.Evidence, allocations)
			if err != nil {
				return nil, err
			}
			demand, err := functionServiceTarget(proof, worker.Architecture).PendingCapacity(ctx, config.Client, current, verified)
			if err != nil {
				return nil, err
			}
			if demand.Architecture != worker.Architecture || math.MaxUint64-slots[demand.Architecture] < demand.Slots {
				return nil, errors.New("function capacity architecture or slot count differs from qualified worker")
			}
			slots[demand.Architecture] += demand.Slots
		}
		architectures := slices.Sorted(maps.Keys(slots))
		demands := make([]nodescale.CapacityDemand, 0, len(architectures))
		for _, architecture := range architectures {
			demands = append(demands, nodescale.CapacityDemand{Architecture: architecture, Slots: slots[architecture]})
		}
		if err := config.Authority.Guard(ctx, epoch); err != nil {
			return nil, err
		}
		if config.Roots.reply("").Head != current.rootHead {
			return nil, errors.New("function roots changed during capacity observation")
		}
		return demands, ctx.Err()
	}
}
