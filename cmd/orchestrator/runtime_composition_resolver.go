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
		transition, err := g.PlacementTransition.load()
		if err != nil {
			return nil, err
		}
		auth, err := LoadProductionAuthBootstrap(g.AuthBootstrapFile)
		if err != nil {
			return nil, err
		}
		if _, err := resolveProductionDatabase(g.Database, productionPlacementConfig{Targets: auth.Targets}, auth); err != nil {
			return nil, fmt.Errorf("production database admission: %w", err)
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
	if g != nil {
		return nil, errors.New("production global admission requires TerraBase reaper and restore lifecycle providers")
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
		runtime, err := newProductionRuntime(productionRuntimeConfig{EstateSpec: spec, DeliveryStore: constructed.Store, BindDelivery: constructed.BindMirror, Close: func() error {
			return errors.Join(constructed.Close(), closeConn())
		}})
		if err != nil {
			_ = constructed.Close()
			_ = closeConn()
			return nil, err
		}
		if wiring, ok := productionAutoscaleFromContext(constructCtx); ok {
			runtime.autoscale = &wiring
		}
		return runtime, nil
	}}, nil
}
