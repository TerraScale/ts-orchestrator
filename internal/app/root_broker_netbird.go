package app

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	netbirdagent "github.com/TerraScale/ts-orchestrator/internal/netbird/agent"
	netbirdmanager "github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/networkplan"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// The first complete proof retains its actual manager/session lifetime. A
// renewed daemon observation cannot extend that source or reopen it after loss.
type rootBrokerNetBirdProof struct {
	broker    *rootBrokerRuntime
	sources   *rootBoundRuntimeSources
	process   *rootOCIProcess
	binding   *rootManagerRuntimeBinding
	session   context.Context
	ctx       context.Context
	cancel    context.CancelFunc
	target    network.Target
	completed netbirdagent.CompletedTargetView
	address   netip.Addr
	node      string
}

func (broker *rootBrokerRuntime) readNetBirdProof() (_ *rootBrokerNetBirdProof, resultErr error) {
	authority := broker.authority
	authority.mu.Lock()
	defer authority.mu.Unlock()
	source := authority.ownhost
	source.mu.RLock()
	defer source.mu.RUnlock()
	sources, process := authority.sources, authority.main
	if sources == nil || sources.spec == nil || process == nil || process.managerBinding == nil || source.session == nil || source.session.Err() != nil ||
		process.managerBinding.session != source.session || source.agent == nil || source.node == nil {
		return nil, rootoci.ErrUnavailable
	}
	deadline := earlier(broker.origin.ExpiresAt(), earlier(sources.deadline, process.managerBinding.signed.Binding.ExpiresAt))
	// Parse the already retained wire before any source/native wait so its
	// signed expiry also bounds those waits, then independently verify it below.
	var signed cellspec.Signed
	if protocol.DecodeStrict(sources.spec.Value(), &signed, cellspec.MaxSignedBytes) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return nil, err
	}
	deadline = earlier(deadline, envelope.ExpiresAt)
	ctx, cancel := context.WithDeadline(broker.ctx, deadline)
	stopSession := context.AfterFunc(source.session, cancel)
	stopSources := context.AfterFunc(sources.lease, cancel)
	proof := &rootBrokerNetBirdProof{broker: broker, sources: sources, process: process, binding: process.managerBinding,
		session: source.session, ctx: ctx, node: process.managerBinding.signed.Binding.HostNode,
		cancel: func() { stopSession(); stopSources(); cancel() }}
	defer func() {
		if resultErr != nil {
			proof.cancel()
		}
	}()
	probe, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	if err := sources.guard(probe); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	verified, err := sources.specs.verify(sources.spec.Value(), &now)
	if err != nil || !verified.RootSigned || verified.NetBird == nil || verified.NetBird.Validate(broker.cfg.NATS.Cell) != nil {
		return nil, rootoci.ErrUnauthorized
	}
	proof.target = network.Target{Pin: verified.NetBird.Pin, Enrollment: verified.NetBird.Enrollment}
	if err := proof.guardOwnHost(probe, source); err != nil {
		return nil, err
	}
	proof.completed, err = netbirdagent.ReadCompletedTarget(broker.cfg.NATS.Cell, proof.node)
	if err != nil || proof.completed.TargetHash != network.Hash(proof.target) {
		return nil, rootoci.ErrUnauthorized
	}
	status, err := netbird.Status(probe)
	if err != nil {
		return nil, err
	}
	proof.address, err = proof.daemonAddress(status)
	if err != nil || sources.guard(probe) != nil || probe.Err() != nil {
		return nil, rootoci.ErrUnauthorized
	}
	return proof, nil
}

func (proof *rootBrokerNetBirdProof) guardOwnHost(ctx context.Context, source *managedRuntimeHost) error {
	if source.session != proof.session || source.session.Err() != nil || source.agent == nil || source.node == nil ||
		proof.process.managerBinding != proof.binding || proof.binding.session != proof.session {
		return rootoci.ErrUnauthorized
	}
	authority := proof.broker.authority
	current, err := source.reader.ReadRuntimeAuthority(ctx, authority.accepted, time.Now().UTC())
	if err != nil || !reflect.DeepEqual(current, proof.broker.origin) {
		return rootoci.ErrUnauthorized
	}
	binding, err := swarmruntime.ReadControllerHostBinding(ctx, source.reader, authority.accepted, source.agent, source.transport.Request, source.transport.Response)
	if err != nil || binding.ControllerSlot() != authority.accepted.Slot || binding.Identity() != current.Identity() {
		return rootoci.ErrUnauthorized
	}
	identity, err := source.agent.RuntimeWorkerIdentity(binding.Identity().InstanceID, source.nodeID)
	if err != nil || identity.Identity().HostNode != proof.node || identity.Identity().HostSessionID != proof.binding.signed.Binding.HostSessionID ||
		identity.SessionEpoch() != proof.binding.signed.Binding.HostSessionEpoch {
		return rootoci.ErrUnauthorized
	}
	return authority.verifyManagerRuntimeBinding(ctx, proof.process, binding, identity, current)
}

func (proof *rootBrokerNetBirdProof) daemonAddress(status netbird.LocalStatus) (netip.Addr, error) {
	if status.State != "Connected" || !status.Management.Connected || !status.Signal.Connected || status.Management.URL != netbird.DefaultManagementURL ||
		status.Version != proof.target.Pin.Version || status.FQDN != proof.node+"."+netbirdmanager.GRU().PeerDNSDomain {
		return netip.Addr{}, rootoci.ErrUnauthorized
	}
	if mapped := proof.target.Enrollment.PeerNames[proof.broker.origin.Identity().PrivateIP]; mapped != "" && mapped != proof.node {
		return netip.Addr{}, rootoci.ErrUnauthorized
	}
	address, err := netip.ParseAddr(status.IP)
	if err != nil {
		prefix, prefixErr := netip.ParsePrefix(status.IP)
		if prefixErr != nil {
			return netip.Addr{}, rootoci.ErrUnauthorized
		}
		address = prefix.Addr()
	}
	if !address.Is4() || address.Zone() != "" || !netip.MustParsePrefix(networkplan.Mesh).Contains(address) {
		return netip.Addr{}, rootoci.ErrUnauthorized
	}
	return address, nil
}

func (proof *rootBrokerNetBirdProof) guard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || proof.ctx.Err() != nil {
		return rootoci.ErrUnauthorized
	}
	deadline, _ := proof.ctx.Deadline()
	ctx, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(proof.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := proof.broker.guard(ctx); err != nil {
		return err
	}
	authority := proof.broker.authority
	err := func() error {
		authority.mu.Lock()
		defer authority.mu.Unlock()
		source := authority.ownhost
		source.mu.RLock()
		defer source.mu.RUnlock()
		if authority.sources != proof.sources || authority.main != proof.process || proof.guardOwnHost(ctx, source) != nil {
			return rootoci.ErrUnauthorized
		}
		if err := proof.sources.guard(ctx); err != nil {
			return err
		}
		completed, err := netbirdagent.ReadCompletedTarget(proof.broker.cfg.NATS.Cell, proof.node)
		if err != nil || completed != proof.completed {
			return rootoci.ErrUnauthorized
		}
		status, err := netbird.Status(ctx)
		if err != nil {
			return err
		}
		address, err := proof.daemonAddress(status)
		if err != nil || address != proof.address || ctx.Err() != nil {
			return rootoci.ErrUnauthorized
		}
		return proof.sources.guard(ctx)
	}()
	if err != nil {
		return err
	}
	return proof.broker.guard(ctx)
}

func (broker *rootBrokerRuntime) runNetBirdListener() {
	var proof *rootBrokerNetBirdProof
	var listener net.Listener
	var stopListener func() bool
	closeListener := func() {
		if stopListener != nil {
			stopListener()
			stopListener = nil
		}
		if listener != nil {
			_ = listener.Close()
			listener = nil
		}
	}
	defer func() {
		closeListener()
		if proof != nil {
			proof.cancel()
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for broker.ctx.Err() == nil {
		if proof == nil {
			proof, _ = broker.readNetBirdProof()
		}
		if proof != nil && proof.ctx.Err() == nil {
			probe, stop := context.WithTimeout(proof.ctx, 5*time.Second)
			err := proof.guard(probe)
			if err == nil && listener == nil {
				listener, err = broker.runtime.ListenNetBird(proof.address)
				if err == nil {
					opened := listener
					stopListener = context.AfterFunc(proof.ctx, func() { _ = opened.Close() })
					err = proof.guard(probe)
				}
			}
			stop()
			if err != nil {
				proof.cancel()
			}
		}
		if proof != nil && proof.ctx.Err() != nil {
			closeListener()
			// The original manager publication cannot grant another admission.
			// Only an independently replaced ownhost session may start a proof.
			broker.authority.ownhost.mu.RLock()
			current := broker.authority.ownhost.session
			broker.authority.ownhost.mu.RUnlock()
			if proof.session.Err() != nil && current != nil && current != proof.session {
				proof.cancel()
				proof = nil
			}
		}
		select {
		case <-broker.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
