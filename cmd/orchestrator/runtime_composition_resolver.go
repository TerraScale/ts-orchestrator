package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/globalclient"
)

// admittedProductionAutoscaleWiring builds the default GRU observation seam
// from the same authenticated roster used by the production estate and KV
// publishers. The reconcile command may supply a richer wiring through the
// context; the normal run command must nevertheless be complete on its own.
// Autoscale decisions are durable in the lease-owned NATS target journal, so
// this callback validates the target handoff while the next compute reconcile
// consumes that journal-backed target.
func admittedProductionAutoscaleWiring(spec estate.Spec, healthFile string) (productionAutoscaleWiring, error) {
	health, err := newObservedKVHealthSource(spec, nil, func(key string) (string, bool) {
		return healthFile, key == reconcileHealthConfigEnvironment && healthFile != ""
	})
	if err != nil {
		return productionAutoscaleWiring{}, err
	}
	regions := make([]string, 0, len(spec.Regions))
	known := make(map[string]struct{}, len(spec.Regions))
	for _, region := range spec.Regions {
		regions = append(regions, region.Code)
		known[region.Code] = struct{}{}
	}
	return productionAutoscaleWiring{
		Source:  health,
		Regions: regions,
		Apply: func(region string, desired int) error {
			if _, ok := known[region]; !ok || desired < 2 || desired > 1024 {
				return errors.New("reconcile: autoscale target is outside the admitted estate")
			}
			return nil
		},
	}, nil
}

// resolveProductionRuntime performs the file-only half of composition. Live
// NATS and provider clients are opened by the returned constructor, after the
// selected broker is ready. The regional connection used to read the leaders
// bucket is a delivery transport; it does not authorize global effects.
func resolveProductionRuntime(ctx context.Context, options *control.OrchestratorOptions) (*admittedProductionRuntime, error) {
	if ctx == nil || options == nil {
		return nil, errors.New("production runtime admission requires context and options")
	}
	deployment, err := loadProductionDeployment(options)
	if err != nil {
		return nil, err
	}
	spec := estate.Default()
	deliveryPlan, err := deployment.Delivery.Admit(spec, strings.ToLower(options.Cell))
	if err != nil {
		return nil, fmt.Errorf("production delivery admission: %w", err)
	}
	g := deployment.Global
	var workerPlan *globalclient.Plan
	var auth productionAuthBootstrapConfig
	var transition productionPlacementTransitionConfig
	var autoscaleWiring productionAutoscaleWiring
	if g != nil {
		if err := g.Estate.validate(); err != nil {
			return nil, err
		}
		if err := g.KV.validate(); err != nil {
			return nil, err
		}
		if err := g.Rotation.Admit(); err != nil {
			return nil, err
		}
		if err := g.Recovery.Admit(); err != nil {
			return nil, err
		}
		transition, err = g.PlacementTransition.load()
		if err != nil {
			return nil, err
		}
		auth, err = LoadProductionAuthBootstrap(g.AuthBootstrapFile)
		if err != nil {
			return nil, err
		}
		if _, err := resolveProductionDatabase(g.Database, productionPlacementConfig{Targets: auth.Targets}, auth); err != nil {
			return nil, fmt.Errorf("production database admission: %w", err)
		}
		autoscaleWiring, err = admittedProductionAutoscaleWiring(spec, g.HealthFile)
		if err != nil {
			return nil, fmt.Errorf("production autoscale admission: %w", err)
		}
		_ = transition
	}
	if options.GlobalNats != nil {
		workerPlan, err = globalclient.Admit(options.GlobalNats)
		if err != nil {
			return nil, fmt.Errorf("global worker connection admission: %w", err)
		}
	}
	if (g != nil) != (workerPlan != nil) {
		return nil, errors.New("production deployment and global NATS role must agree")
	}
	return &admittedProductionRuntime{construct: func(constructCtx context.Context) (*productionRuntime, error) {
		if constructCtx == nil {
			return nil, errors.New("production runtime construction requires context")
		}
		var err error
		var conn *nats.Conn
		if workerPlan != nil {
			conn, err = workerPlan.Connect(constructCtx)
		} else {
			membership, e := deliveryPlan.membership.source.configuration()
			if e != nil {
				return nil, e
			}
			for _, region := range membership.Regions {
				if region.Code != strings.ToLower(options.Cell) {
					continue
				}
				credentials, e := bootstrapcredentials.Load(region.Connection)
				if e != nil {
					return nil, e
				}
				conn, e = dialBootstrapStore(constructCtx, bootstrap.ControlNATSStore{URL: credentials.URL, Options: credentials.Options})
				_ = credentials.Close()
				err = e
				break
			}
			if err != nil {
				return nil, fmt.Errorf("production regional NATS connection: %w", err)
			}
			if conn == nil {
				return nil, errors.New("production delivery requires an admitted regional NATS connection")
			}
		}
		if err != nil {
			return nil, err
		}
		closeConn := func() error { conn.Close(); return nil }
		js, err := jetstream.New(conn)
		if err != nil {
			_ = closeConn()
			return nil, err
		}
		leaders, err := js.KeyValue(constructCtx, "ORCH_LEADERS")
		if err != nil {
			_ = closeConn()
			return nil, err
		}
		constructed, err := deliveryPlan.Construct(constructCtx, conn, leaders)
		if err != nil {
			_ = constructed.Close()
			_ = closeConn()
			return nil, err
		}
		var globalPlan *productionGlobalWorkerPlan
		var runtime *productionRuntime
		if g != nil {
			wiring := autoscaleWiring
			if contextWiring, ok := productionAutoscaleFromContext(constructCtx); ok {
				wiring = contextWiring
			}
			globalPlan = &productionGlobalWorkerPlan{CandidateID: "global-controller-" + strings.ToLower(options.Cell) + "-" + options.Instance}
			globalPlan.Construct = func(workerCtx context.Context, session globalWorkerSession) (productionGlobalWorkerConfig, error) {
				return buildProductionGlobalConfig(workerCtx, session, productionGlobalBuildInput{
					BindProjection: wiring.BindProjection, BindTargetProjection: wiring.BindTargetProjection,
					Global: g, Auth: auth, Spec: spec, Mirror: runtime.mirror,
					Shared: constructed.Store, Ownership: constructed.Ownership, Transition: transition,
					GlobalEdge: constructed.GlobalEdge,
				})
			}
		}
		runtime, err = newProductionRuntime(productionRuntimeConfig{Global: globalPlan, EstateSpec: spec, DeliveryStore: constructed.Store, BindDelivery: constructed.BindMirror, Close: func() error {
			return errors.Join(constructed.Close(), closeConn())
		}})
		if err != nil {
			_ = constructed.Close()
			_ = closeConn()
			return nil, err
		}
		if wiring, ok := productionAutoscaleFromContext(constructCtx); ok {
			runtime.autoscale = &wiring
		} else if g != nil {
			runtime.autoscale = &autoscaleWiring
		}
		runtime.autoscaleRequired = true
		return runtime, nil
	}}, nil
}
