package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/moby/swarmkit/v2/api"
)

// Providers are bound before node startup and stay closed until its one real
// ownhost session has independently completed enrollment.
type managedRuntimeHost struct {
	mu         sync.RWMutex
	reader     *bootstrapstart.CurrentFounderAuthorityReader
	accepted   bootstrapstart.AcceptedIdentity
	agent      *host.Agent
	transport  hostenroll.WorkerTransport
	registry   swarmruntime.RegistryResolver
	nodeID     string
	session    context.Context
	generation uint64
}

func (source *managedRuntimeHost) bind(ctx context.Context, agent *host.Agent, transport hostenroll.WorkerTransport, registry swarmruntime.RegistryResolver, nodeID string) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.session != ctx {
		source.generation++
	}
	source.agent, source.transport, source.registry = agent, transport, registry
	source.nodeID = nodeID
	source.session = ctx
}

func (source *managedRuntimeHost) clear() {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.agent, source.registry = nil, nil
	source.transport = hostenroll.WorkerTransport{}
	source.nodeID = ""
	source.session = nil
}

func (source *managedRuntimeHost) CurrentContainerMaterial(ctx context.Context, binding swarmruntime.ContainerTaskBinding) (result swarmruntime.ContainerMaterial, resultErr error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.agent == nil || source.session == nil || source.session.Err() != nil {
		return result, errors.New("controller container material awaits its current ownhost session")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(source.session, cancel)
	defer func() { stop(); cancel() }()
	current, err := swarmruntime.ReadControllerHostBinding(ctx, source.reader, source.accepted, source.agent, source.transport.Request, source.transport.Response)
	if err != nil {
		return result, err
	}
	identity := current.Identity()
	if binding.NodeID != source.nodeID || binding.HostID != current.ControllerSlot() || binding.InstanceID != identity.InstanceID || binding.Region != identity.OCIRegion {
		return result, errors.New("controller material differs from its accepted manager slot")
	}
	transportBinding := binding
	transportBinding.HostID = current.HostID()
	result, err = (containerMaterialSource{agent: source.agent}).CurrentContainerMaterial(ctx, transportBinding)
	if err != nil {
		return result, err
	}
	defer func() {
		if resultErr != nil {
			for _, value := range result.Files {
				clear(value)
			}
			result = swarmruntime.ContainerMaterial{}
		}
	}()
	if ctx.Err() != nil || source.session.Err() != nil || !time.Now().Before(result.ExpiresAt) {
		return result, errors.New("controller ownhost changed during material delivery")
	}
	result.Binding = binding
	return result, nil
}

func (source *managedRuntimeHost) registryResolver(ctx context.Context, task *api.Task, node *api.Node) (remotes.Resolver, error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.agent == nil || source.registry == nil || source.session == nil || source.session.Err() != nil {
		return nil, errors.New("controller registry awaits its current ownhost session")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(source.session, cancel)
	defer func() { stop(); cancel() }()
	resolver, err := source.registry(ctx, task, node)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || source.session.Err() != nil {
		return nil, errors.New("controller ownhost session ended during registry admission")
	}
	return resolver, nil
}

func setManagedRuntimeAvailability(ctx context.Context, node *swarmruntime.Node, admitted swarmruntime.Admission, availability api.NodeSpec_Availability) error {
	client, err := node.ControlClient(ctx)
	if err != nil {
		return err
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
	if err != nil {
		return err
	}
	if current == nil || current.Node == nil || current.Node.Role != api.NodeRoleManager || current.Node.Spec.DesiredRole != api.NodeRoleManager ||
		current.Node.Spec.Membership != api.NodeMembershipAccepted || current.Node.Spec.Annotations.Name != admitted.HostID ||
		current.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] != admitted.InstanceID ||
		current.Node.Spec.Annotations.Labels[swarmruntime.LabelRegion] != admitted.Region || current.Node.Spec.Annotations.Labels[swarmruntime.LabelHostRole] != "manager" {
		return errors.New("controller availability requires the exact current admitted manager")
	}
	if current.Node.Spec.Availability == availability {
		return nil
	}
	spec := current.Node.Spec.Copy()
	spec.Availability = availability
	_, err = client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: current.Node.ID, NodeVersion: &current.Node.Meta.Version, Spec: spec})
	return err
}

// Session failure pauses new placement while the manager and its tasks remain.
// Each retry joins the old session before constructing a fresh Agent.
func runManagedRuntimeOwnHost(ctx context.Context, cfg Config, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity,
	node *swarmruntime.Node, admitted swarmruntime.Admission, source *managedRuntimeHost,
) {
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := setManagedRuntimeAvailability(attempt, node, admitted, api.NodeAvailabilityPause)
		cancel()
		if err == nil {
			err = runManagedRuntimeHostSession(ctx, cfg, reader, accepted, node, admitted, source)
		}
		source.clear()
		if ctx.Err() != nil {
			return
		}
		attempt, cancel = context.WithTimeout(ctx, 30*time.Second)
		pauseErr := setManagedRuntimeAvailability(attempt, node, admitted, api.NodeAvailabilityPause)
		cancel()
		slog.WarnContext(ctx, "controller ownhost admission pending", "error", err, "pause_error", pauseErr)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func runManagedRuntimeHostSession(ctx context.Context, controller Config, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity,
	node *swarmruntime.Node, admitted swarmruntime.Admission, source *managedRuntimeHost,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := setupRuntimeWorker(ctx, io.Discard); err != nil {
		return err
	}
	cfg, err := LoadConfig(runtimeWorkerConfigPath)
	if err != nil {
		return err
	}
	if cfg.NATS.Embedded != nil || cfg.NATS.Cell != strings.ToLower(accepted.Cell) || cfg.Host.Environment != accepted.Environment {
		return errors.New("controller ownhost configuration differs from its accepted region")
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(accepted)
	if err != nil {
		return err
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return err
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return err
	}
	key, err := readPrivateKey(cfg.Host.IdentityKeyFile)
	if err != nil {
		return err
	}
	defer clear(key)
	natsUser, err := hostNATSUserPublicKey(cfg.NATS)
	if err != nil {
		return err
	}
	cfg.NATS.ClientRole = "host"
	cfg.NATS.ReloadClientMaterial = hostCredentialReloader(runtimeWorkerConfigPath, cfg, key)
	broker, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer broker.Close()
	ready := make(chan struct{})
	agent, err := host.NewAgent(host.AgentConfig{Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Environment: cfg.Host.Environment,
		Roles: cfg.Host.Roles, Conn: broker.Conn(), Identity: key, NATSUserPublicKey: natsUser, ControllerPublicKey: public,
		InstallRoot: cfg.Host.InstallRoot, StateRoot: cfg.Host.StateRoot,
		WorkloadIdentity: host.WorkloadIdentity{UID: cfg.Host.WorkloadUID, GID: cfg.Host.WorkloadGID},
		ClockCheck:       controllerClockCheck(hostClockProbe()),
		FollowRollouts:   hostRollouts(cfg, key, public), FollowNetBird: hostNetBird(cfg, public), Initialized: func() { close(ready) },
	})
	if err != nil {
		return err
	}
	done := make(chan struct{})
	var sessionErr error
	go func() { sessionErr = agent.RunSession(ctx); cancel(); close(done) }()
	defer func() {
		cancel()
		<-done
		attempt, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		if err := setManagedRuntimeAvailability(attempt, node, admitted, api.NodeAvailabilityPause); err != nil {
			slog.WarnContext(ctx, "pause controller ownhost placement", "error", err)
		}
		source.clear()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return sessionErr
	case <-ready:
	}
	refresh := func() error {
		installed, err := LoadConfig(runtimeWorkerConfigPath)
		if err != nil {
			return err
		}
		if err := sameHostIdentityConfig(cfg, installed); err != nil {
			return err
		}
		wire, err := readRuntimeWorkerTransport()
		if err != nil {
			return err
		}
		var transport hostenroll.WorkerTransport
		if err := protocol.DecodeStrict(wire, &transport, 128<<10); err != nil {
			return err
		}
		binding, err := swarmruntime.ReadControllerHostBinding(ctx, reader, accepted, agent, transport.Request, transport.Response)
		if err != nil || binding.ControllerSlot() != admitted.HostID || binding.Identity().InstanceID != admitted.InstanceID || binding.Identity().OCIRegion != admitted.Region {
			return errors.New("controller ownhost has no current completed accepted binding")
		}
		registry, err := managedRuntimeRegistryResolver(ctx, controller, reader, accepted, node, agent, transport)
		if err != nil {
			return err
		}
		source.bind(ctx, agent, transport, registry, node.ID())
		attempt, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		return setManagedRuntimeAvailability(attempt, node, admitted, api.NodeAvailabilityActive)
	}
	if err := refresh(); err != nil {
		return err
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return sessionErr
		case <-ticker.C:
			if err := setupRuntimeWorker(ctx, io.Discard); err != nil {
				return err
			}
			if err := refresh(); err != nil {
				return err
			}
		}
	}
}
