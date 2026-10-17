package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// The sole embedded broker and its rekey/close lifecycle remain in root.
type rootBrokerRuntime struct {
	runtime   *natscell.Runtime
	cfg       Config
	authority *rootOCIAuthority
	ctx       context.Context
	cancel    context.CancelFunc
	sockets   []*rootBrokerSocket
	workers   sync.WaitGroup
	once      sync.Once
	origin    bootstrapstart.RuntimeAuthority
}

func startRootBrokerRuntime(ctx context.Context, cfg Config, authority *rootOCIAuthority) (*rootBrokerRuntime, error) {
	if ctx == nil || ctx.Err() != nil || authority == nil || cfg.NATS.Embedded == nil {
		return nil, rootoci.ErrUnauthorized
	}
	probe, stopProbe := context.WithTimeout(ctx, 30*time.Second)
	origin, err := authority.readBrokerOrigin(probe)
	stopProbe()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, origin.ExpiresAt())
	cfg.NATS.ClientRole = "controller"
	broker := &rootBrokerRuntime{cfg: cfg, authority: authority, ctx: ctx, cancel: cancel, origin: origin}
	runtime, err := broker.openControllerRuntime(ctx, cfg, controllerClockCheck(hostClockProbe()))
	if err != nil {
		cancel()
		return nil, err
	}
	broker.runtime = runtime
	if err := broker.guard(ctx); err != nil {
		_ = broker.Close()
		return nil, err
	}
	for _, path := range []string{rootBrokerStartupSocket, rootBrokerObservationSocket, rootBrokerReconnectSocket} {
		socket, err := listenRootBrokerSocket(path, authority.gid)
		if err != nil {
			_ = broker.Close()
			return nil, err
		}
		broker.sockets = append(broker.sockets, socket)
		handler := broker.serveObservations
		if path == rootBrokerStartupSocket {
			handler = broker.serveStartup
		} else if path == rootBrokerReconnectSocket {
			handler = broker.serveReconnect
		}
		broker.workers.Go(func() { serveRootBrokerSocket(ctx, socket, handler) })
	}
	if err := startRootBrokerGate(broker); err != nil {
		_ = broker.Close()
		return nil, err
	}
	broker.workers.Go(func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				view, observed := runtime.ObserveCluster()
				if observed != nil || !view.Running {
					cancel()
					return
				}
				probe, stop := context.WithTimeout(ctx, 5*time.Second)
				err := broker.guard(probe)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	})
	return broker, nil
}

func (broker *rootBrokerRuntime) Close() error {
	broker.once.Do(func() {
		broker.cancel()
		for _, socket := range broker.sockets {
			_ = socket.Close()
		}
		broker.workers.Wait()
		stepDownMetaLeaderOnShutdown(broker.runtime, broker.cfg.NATS.Embedded.MembershipCredentialsFile)
		_ = broker.runtime.Close()
	})
	return nil
}

func (broker *rootBrokerRuntime) serveStartup(parent context.Context, conn *net.UnixConn) {
	probe, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil {
		return
	}
	startup, err := broker.authority.admitBrokerStartup(probe, peer)
	if err != nil {
		return
	}
	defer startup.cancel()
	ctx, stop := context.WithDeadline(parent, startup.deadline)
	stopProcess := context.AfterFunc(startup.ctx, stop)
	defer func() { stopProcess(); stop() }()
	if err := broker.authority.verifyBrokerStartup(ctx, startup); err != nil {
		return
	}
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		for ctx.Err() == nil {
			if startup.process.witness.Verify() != nil {
				stop()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	defer func() { stop(); <-monitorDone }()
	sourceDone := make(chan struct{})
	go func() {
		defer close(sourceDone)
		for ctx.Err() == nil {
			if broker.authority.verifyBrokerStartup(ctx, startup) != nil {
				stop()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	defer func() { stop(); <-sourceDone }()
	_ = broker.runtime.ServeStartupController(ctx, conn, startup.deadline)
}

func (broker *rootBrokerRuntime) serveObservations(parent context.Context, conn *net.UnixConn) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	peer, err := nativerootoci.PeerCredential(conn)
	if err != nil {
		return
	}
	lease, err := broker.authority.brokerObservationLease(ctx, peer)
	if err != nil {
		return
	}
	ctx, stopLease := context.WithDeadline(ctx, lease.Deadline)
	defer stopLease()
	revoke := context.AfterFunc(lease.Context, stopLease)
	defer revoke()
	deadline, _ = ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	stopBound := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopBound()
	wire, err := nativerootoci.ReadBoundedFrame(conn, nativerootoci.MaxFrameBytes)
	if err != nil {
		return
	}
	var request rootBrokerRequest
	if json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)) != nil {
		return
	}
	stopPeer := watchRootBrokerPeer(conn, cancel)
	defer stopPeer()
	guard := func() error {
		if ctx.Err() != nil || lease.Context.Err() != nil {
			return rootoci.ErrUnauthorized
		}
		current, err := broker.authority.brokerObservationLease(ctx, peer)
		if err != nil || current.Context != lease.Context || current.Deadline != lease.Deadline || current.Binding != lease.Binding {
			return rootoci.ErrUnauthorized
		}
		return nil
	}
	if guard() != nil {
		return
	}
	response, err := broker.observe(ctx, request.Operation)
	if err != nil && !(request.Operation == rootBrokerCluster && response.Cluster != nil && errors.Is(err, natscell.ErrEmbeddedServerStopped)) {
		response = rootBrokerResponse{Error: rootBrokerErrorCode(err)}
	}
	if guard() != nil {
		response = rootBrokerResponse{Error: "unauthorized"}
	}
	wire, err = json.Marshal(response)
	if err != nil || len(wire) > nativerootoci.MaxFrameBytes {
		return
	}
	if guard() != nil || ctx.Err() != nil {
		return
	}
	_ = nativerootoci.WriteBoundedFrame(conn, wire, nativerootoci.MaxFrameBytes)
}

func (broker *rootBrokerRuntime) observe(ctx context.Context, operation rootBrokerOperation) (rootBrokerResponse, error) {
	var response rootBrokerResponse
	switch operation {
	case rootBrokerCluster:
		view, err := broker.runtime.ObserveCluster()
		response.Cluster = &rootBrokerClusterView{Observation: view,
			QuorumReady: broker.runtime.FullClusterReady(broker.cfg.NATS.Replicas/2 + 1),
			FullReady:   broker.runtime.FullClusterReady(broker.cfg.NATS.Replicas)}
		if err != nil {
			return response, err
		}
	case rootBrokerMeta:
		view, err := broker.runtime.Meta()
		if err != nil {
			return response, err
		}
		response.Meta = &view
	case rootBrokerMetrics:
		view, err := broker.runtime.Observe(ctx)
		if err != nil {
			return response, err
		}
		response.Metrics = &view
	case rootBrokerStore:
		view, err := broker.runtime.LocalStoreUsedBytes(ctx)
		if err != nil {
			return response, err
		}
		response.Store = &view
	case rootBrokerStreams:
		view, err := broker.runtime.StreamHealth(ctx)
		if err != nil {
			return response, err
		}
		response.Streams = &view
	case rootBrokerAccount:
		view, err := broker.runtime.ReadControllerAccount(ctx)
		if err != nil {
			return response, err
		}
		response.Account = &view
	case rootBrokerCredentials:
		inputs, err := bootstrapstart.LoadTrustInputs(broker.authority.accepted)
		if err != nil {
			return response, err
		}
		material, err := bootstrapstart.NewMaterialStore(nil, broker.authority.uid, broker.authority.gid)
		if err != nil {
			return response, err
		}
		view, err := material.BrokerCredentialExpiries(ctx, broker.authority.accepted, inputs.Roots.Historical)
		if err != nil {
			return response, err
		}
		response.Credentials = &view
	default:
		return response, rootoci.ErrInvalid
	}
	return response, ctx.Err()
}

func rootBrokerErrorCode(err error) string {
	switch {
	case errors.Is(err, rootoci.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, natscell.ErrEmbeddedServerStopped):
		return "stopped"
	case errors.Is(err, natscell.ErrJetStreamDisabled):
		return "disabled"
	default:
		return "unavailable"
	}
}
