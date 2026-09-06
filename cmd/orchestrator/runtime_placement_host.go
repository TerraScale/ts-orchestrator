package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/authbootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
)

const placementHostFileEnvironment = "TS_ORCH_PLACEMENT_HOST_FILE"

type productionPlacementHost struct {
	bridge          *placementpublisher.HostBridge
	acceptBridge    *placementpublisher.AcceptanceHostBridge
	drainBridge     *placementpublisher.AcceptanceHostBridge
	readinessBridge *placementpublisher.AcceptanceHostBridge
	authBridge      *authbootstrap.HostBridge
	authEngine      *tbep.AuthBootstrapClient
	completion      chan struct{}
	engine          *tbep.PlacementClient
	connection      *nats.Conn
	once            sync.Once
	err             error
}

func (host *productionPlacementHost) Completion() <-chan struct{} { return host.completion }
func (host *productionPlacementHost) Close() error {
	if host == nil {
		return nil
	}
	host.once.Do(func() {
		host.err = errors.Join(host.bridge.Close(), host.acceptBridge.Close(), host.drainBridge.Close(), host.readinessBridge.Close())
		host.err = errors.Join(host.err, host.authBridge.Close(), host.authEngine.Close())
		host.err = errors.Join(host.err, host.engine.Close())
		host.connection.Close()
	})
	return host.err
}

// startProductionPlacementHost is required by run. Host control uses its own
// NKey and mTLS identities; no GRU authority credentials belong on a member host.
func startProductionPlacementHost(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (*productionPlacementHost, error) {
	if options == nil || lookup == nil {
		return nil, errors.New("placement host: options and configuration required")
	}
	path, ok := lookup(placementHostFileEnvironment)
	if !ok || path == "" {
		return nil, errors.New("placement host: TS_ORCH_PLACEMENT_HOST_FILE is required")
	}
	data, err := bootstrapcredentials.ReadFile(path, false, 32<<10)
	if err != nil {
		return nil, err
	}
	config, err := placementpublisher.ParseHostFile(data, options.Cell, options.Instance)
	if err != nil {
		return nil, err
	}
	engineTLS, err := config.EngineTLS.LoadTLS()
	if err != nil {
		return nil, err
	}
	engine, err := tbep.NewPlacement(tbep.Config{Endpoint: config.EngineEndpoint, ServerIdentity: config.EngineIdentity, Certificate: engineTLS.Certificates[0], Roots: engineTLS.RootCAs, Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	authEngine, err := tbep.NewAuthBootstrap(tbep.Config{Endpoint: config.EngineEndpoint, ServerIdentity: config.EngineIdentity, Certificate: engineTLS.Certificates[0], Roots: engineTLS.RootCAs, Timeout: 5 * time.Second})
	if err != nil {
		_ = engine.Close()
		return nil, err
	}
	host := &productionPlacementHost{engine: engine, authEngine: authEngine, completion: make(chan struct{})}
	completed := false
	defer func() {
		if !completed {
			_ = engine.Close()
			_ = authEngine.Close()
			if host.drainBridge != nil {
				_ = host.drainBridge.Close()
			}
			if host.readinessBridge != nil {
				_ = host.readinessBridge.Close()
			}
			if host.authBridge != nil {
				_ = host.authBridge.Close()
			}
			if host.acceptBridge != nil {
				_ = host.acceptBridge.Close()
			}
			if host.bridge != nil {
				_ = host.bridge.Close()
			}
			if host.connection != nil {
				host.connection.Close()
			}
		}
	}()
	natsTLS, err := config.NATSIdentity.LoadTLS()
	if err != nil {
		return nil, err
	}
	seed, err := bootstrapcredentials.ReadFile(config.NKeyFile, true, 1024)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, errors.New("placement host: invalid dedicated NKey")
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, errors.New("placement host: user NKey required")
	}
	connection, err := natsconnect.Connect(ctx, natsconnect.Config{URL: config.NATSURL, TLS: natsTLS, PublicNKey: public, Sign: pair.Sign, Timeout: 5 * time.Second}, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	host.connection = connection
	bridge, err := placementpublisher.StartHostBridge(ctx, connection, engine)
	if err != nil {
		return nil, err
	}
	host.bridge = bridge
	authBridge, err := authbootstrap.StartHostBridge(ctx, connection, authEngine)
	if err != nil {
		return nil, err
	}
	host.authBridge = authBridge
	acceptBridge, err := placementpublisher.StartAcceptanceHostBridge(ctx, connection, engine)
	if err != nil {
		_ = authBridge.Close()
		return nil, err
	}
	host.acceptBridge = acceptBridge
	drainBridge, err := placementpublisher.StartDrainHostBridge(ctx, connection, engine)
	if err != nil {
		return nil, err
	}
	host.drainBridge = drainBridge
	readinessBridge, err := placementpublisher.StartReadinessHostBridge(ctx, connection, engine)
	if err != nil {
		return nil, err
	}
	host.readinessBridge = readinessBridge
	go func() {
		select {
		case <-bridge.Completion():
		case <-authBridge.Completion():
		case <-acceptBridge.Completion():
		case <-drainBridge.Completion():
		case <-readinessBridge.Completion():
		}
		close(host.completion)
	}()
	completed = true
	return host, nil
}
