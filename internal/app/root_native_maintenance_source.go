//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// This original phase source ends with the old target process. It grants no
// dispatch, protected journal write, or authority to admit a successor phase.
type rootNativeMaintenanceSource struct {
	ctx                        context.Context
	close                      context.CancelFunc
	call                       rootoci.Call
	observation                *rootReleaseObservation
	config                     containerMaterialConfig
	ownhost                    *managedRuntimeHost
	generation                 uint64
	session                    context.Context
	agent                      *host.Agent
	request, response          []byte
	local                      *swarmruntime.ControllerHostBinding
	origin                     *swarmruntime.ManagerRuntimeCandidate
	identity                   *swarmruntime.NativeMaintenanceIdentity
	recipient                  *bootstrapstart.ControllerHostRecipient
	target                     *swarmruntime.ManagerHostRecipient
	binary                     release.VerifiedBinary
	channel                    releasechannel.Channel
	channelWire                []byte
	accepted                   []byte
	unit                       string
	architecture               string
	deadline, workflowDeadline time.Time
}

func (b *rootReleaseChannels) captureNativeMaintenance(ctx context.Context, call rootoci.Call, unit string,
	producer *rootMaterialAdmission,
) (_ *rootNativeMaintenanceSource, resultErr error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || b == nil || producer == nil || producer.ownhost == nil ||
		b.ctx == nil || b.factory == nil || b.factory != producer.factory || call.Operation() != rootoci.OperationReconcileOrchestratorMaintenance ||
		call.RuntimeID() == "" {
		return nil, rootoci.ErrUnauthorized
	}
	b.mu.Lock()
	bound, controllers := b.bound, slices.Clone(b.controllers)
	b.mu.Unlock()
	if !bound || !slices.ContainsFunc(controllers, func(candidateUnit rollout.Unit) bool { return candidateUnit.ID == unit }) {
		return nil, rootoci.ErrUnauthorized
	}
	ownhost := producer.ownhost
	ownhost.mu.RLock()
	node, reader, agent, session := ownhost.node, ownhost.reader, ownhost.agent, ownhost.session
	generation, nodeID := ownhost.generation, ownhost.nodeID
	accepted := ownhost.accepted.Clone()
	request, response := bytes.Clone(ownhost.transport.Request), bytes.Clone(ownhost.transport.Response)
	ownhost.mu.RUnlock()
	if node == nil || node != b.sources.Node || reader == nil || reader != b.sources.Authority || agent == nil ||
		session == nil || session.Err() != nil || generation == 0 || nodeID != node.ID() {
		return nil, rootoci.ErrUnauthorized
	}
	acceptedWire, err := bootstrapstart.EncodeAcceptedIdentity(accepted)
	if err != nil {
		return nil, err
	}
	channelAccepted, err := bootstrapstart.EncodeAcceptedIdentity(b.sources.Accepted)
	if err != nil || !bytes.Equal(acceptedWire, channelAccepted) {
		return nil, rootoci.ErrUnauthorized
	}
	original, cancel := context.WithCancel(ctx)
	stopSession := context.AfterFunc(session, cancel)
	stopRuntime := context.AfterFunc(b.ctx, cancel)
	context.AfterFunc(original, func() { stopSession(); stopRuntime() })
	defer func() {
		if resultErr != nil {
			cancel()
		}
	}()
	ctx, releaseCancel, observation, err := b.beginChannel(original, call, rootoci.OperationReconcileOrchestratorMaintenance)
	if err != nil {
		releaseCancel()
		return nil, err
	}
	context.AfterFunc(original, releaseCancel)
	configController, _, err := producer.readers(ctx, call)
	if err != nil {
		return nil, err
	}
	if configController == nil || observation == nil || observation.registry == nil || observation.registry.roots == nil {
		return nil, rootoci.ErrUnauthorized
	}
	config := configController.config
	ctx = config.credentialContext
	if ctx == nil || config.credentialSource == nil || config.Specs == nil || config.Specs.roots == nil || config.Registrations == nil || config.Mutations == nil {
		return nil, rootoci.ErrUnauthorized
	}
	credentialDeadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || config.Founders != reader || config.Specs.revision != observation.specRevision ||
		config.Specs.roots.reply("").Head != observation.registry.roots.reply("").Head || len(observation.specWire) == 0 {
		return nil, rootoci.ErrUnauthorized
	}
	observation.capDeadline(credentialDeadline)
	verifiedSpec, err := observation.registry.verify(observation.specWire, nil)
	if err != nil || !verifiedSpec.RootSigned || verifiedSpec.ReleaseFence == nil {
		return nil, rootoci.ErrUnauthorized
	}
	location, err := observation.location(ctx)
	if err != nil {
		return nil, err
	}
	channel, found, err := releasechannel.ReadChannel(ctx, location)
	if err != nil || !found {
		return nil, rootoci.ErrUnavailable
	}
	binaries, err := channel.Verify(observation.registry.roots.current(), observation.source.Identity().Cell,
		observation.source.Identity().Environment, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// Adopted root/spec submission dates are historical, not execution grants.
	workflowDeadline := observation.source.ExpiresAt()
	for _, binary := range binaries {
		workflowDeadline = earlier(workflowDeadline, binary.ExpiresAt())
		observation.capDeadline(binary.ExpiresAt())
	}
	local, err := swarmruntime.ReadControllerHostBinding(ctx, reader, accepted, agent, request, response)
	if err != nil {
		return nil, err
	}
	identity, err := node.ReadNativeMaintenanceIdentity(ctx, local)
	if err != nil {
		return nil, err
	}
	observation.capDeadline(identity.ExpiresAt())
	origin, err := node.ReadManagerRuntimeCandidate(ctx, config.Registrations, config.Mutations, local, nodeID)
	if err != nil {
		return nil, err
	}
	if origin.Identity().RuntimeCandidateID != call.RuntimeID() || origin.Identity().NodeID != nodeID ||
		origin.SourceSHA256() != observation.source.ManagerSourceSHA256() || origin.LeaseEpoch() != observation.lease.Epoch() {
		return nil, rootoci.ErrUnauthorized
	}
	observation.capDeadline(origin.ExpiresAt())
	hostNode := observation.registry.controllerNode(observation.source.Identity().Cell, unit)
	grant, _, granted := observation.registry.hostGrant(hostNode)
	if !granted {
		return nil, rootoci.ErrUnauthorized
	}
	targetSession, err := config.Registrations.ReadManagerRuntimeSession(ctx, hostNode)
	if err != nil {
		return nil, err
	}
	carrier, ok := targetSession.SignedBinding()
	if !ok {
		return nil, rootoci.ErrUnavailable
	}
	observation.capDeadline(targetSession.ExpiresAt(), carrier.Binding.ExpiresAt)
	// The carrier only narrows selectors until native verification below.
	recipient, err := bootstrapstart.ReadControllerHostRecipient(ctx, reader, accepted, observation.specWire,
		hostNode, carrier.Binding.InstanceID, grant.PrivateIP)
	if err != nil {
		return nil, err
	}
	observation.capDeadline(recipient.Deadline())
	if recipient.ControllerSlot() != unit {
		return nil, rootoci.ErrUnauthorized
	}
	enrollment, err := completedControllerEnrollment(ctx, config, targetSession.Registration(), recipient.InstanceID())
	if err != nil {
		return nil, err
	}
	observation.capDeadline(enrollment.ExpiresAt)
	target, err := node.ReadManagerHostRecipient(ctx, config.Registrations, local, recipient, carrier.Binding.NodeID, enrollment.Query)
	if err != nil {
		return nil, err
	}
	observation.capDeadline(target.ExpiresAt())
	if target.BindingSHA256() != targetSession.BindingSHA256() || target.SourceSHA256() != origin.SourceSHA256() {
		return nil, rootoci.ErrUnauthorized
	}
	architecture, err := recipient.ReadArchitecture(ctx)
	if err != nil {
		return nil, err
	}
	binary, ok := binaries[architecture]
	if !ok || !binary.IsVerified() || binary.Receipt().SHA256 == target.Identity().BinarySHA256 {
		return nil, rootoci.ErrUnauthorized
	}
	channelWire, err := json.Marshal(channel, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	bounded, stop := context.WithDeadline(ctx, observation.deadline)
	context.AfterFunc(bounded, cancel)
	proof := &rootNativeMaintenanceSource{ctx: bounded, close: func() { stop(); cancel() }, call: call,
		observation: observation, config: config, ownhost: ownhost, generation: generation, session: session,
		agent: agent, request: request, response: response,
		local: local, origin: origin, identity: identity, recipient: recipient, target: target, binary: binary,
		channel: channel, channelWire: channelWire, accepted: acceptedWire, unit: unit, architecture: architecture,
		deadline: observation.deadline, workflowDeadline: workflowDeadline}
	if err := proof.revalidate(bounded); err != nil {
		stop()
		return nil, err
	}
	return proof, nil
}

func (p *rootNativeMaintenanceSource) localCurrent(ctx context.Context) error {
	if p == nil || ctx == nil || ctx.Err() != nil || p.ctx == nil || p.ctx.Err() != nil || p.ownhost == nil ||
		p.observation == nil || p.observation.b == nil || p.config.credentialSource == nil ||
		p.session == nil || p.session.Err() != nil || p.local == nil || p.origin == nil || p.identity == nil || p.target == nil ||
		p.recipient == nil || !p.binary.IsVerified() || !time.Now().Before(p.deadline) || !time.Now().Before(p.workflowDeadline) {
		return rootoci.ErrUnauthorized
	}
	p.ownhost.mu.RLock()
	current, err := bootstrapstart.EncodeAcceptedIdentity(p.ownhost.accepted)
	changed := err != nil || !p.matchesOwnhostLocked() || !bytes.Equal(current, p.accepted)
	p.ownhost.mu.RUnlock()
	if changed {
		return rootoci.ErrUnauthorized
	}
	return p.call.Guard(ctx)
}

// The generation alone does not change when bind refreshes an existing session.
func (p *rootNativeMaintenanceSource) matchesOwnhostLocked() bool {
	return p.ownhost.generation == p.generation && p.ownhost.node == p.observation.b.sources.Node &&
		p.ownhost.nodeID == p.origin.Identity().NodeID && p.ownhost.reader == p.observation.b.sources.Authority &&
		p.agent != nil && p.ownhost.agent == p.agent && p.ownhost.session == p.session &&
		p.ownhost.session != nil && p.ownhost.session.Err() == nil &&
		bytes.Equal(p.ownhost.transport.Request, p.request) && bytes.Equal(p.ownhost.transport.Response, p.response)
}

func (p *rootNativeMaintenanceSource) revalidate(ctx context.Context) error {
	if err := p.localCurrent(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, p.deadline)
	stop := context.AfterFunc(p.ctx, cancel)
	defer cancel()
	defer stop()
	if err := p.config.credentialSource.Guard(ctx); err != nil {
		return err
	}
	if err := p.observation.guard(ctx); err != nil {
		return err
	}
	for _, guard := range []func(context.Context) error{p.origin.Revalidate, p.identity.Revalidate, p.recipient.Verify, p.target.Revalidate} {
		if err := guard(ctx); err != nil {
			return err
		}
	}
	current, err := p.observation.b.sources.Authority.ReadRuntimeAuthority(ctx, p.observation.b.sources.Accepted, time.Now().UTC())
	if err != nil || current.Identity() != p.observation.source.Identity() || current.ManagerSourceSHA256() != p.origin.SourceSHA256() ||
		current.ExpiresAt().Before(p.workflowDeadline) {
		return rootoci.ErrUnauthorized
	}
	location, err := p.observation.location(ctx)
	if err != nil {
		return err
	}
	channel, found, err := releasechannel.ReadChannel(ctx, location)
	if err != nil || !found {
		return rootoci.ErrUnavailable
	}
	wire, err := json.Marshal(channel, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, p.channelWire) {
		return rootoci.ErrUnauthorized
	}
	binaries, err := channel.Verify(p.observation.registry.roots.current(), current.Identity().Cell, current.Identity().Environment, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, verified := range binaries {
		if !verified.IsVerified() || verified.ExpiresAt().Before(p.workflowDeadline) {
			return rootoci.ErrUnauthorized
		}
	}
	binary, ok := binaries[p.architecture]
	if !ok || binary.EnvelopeSHA256() != p.binary.EnvelopeSHA256() || binary.ExpiresAt().Before(p.workflowDeadline) ||
		p.call.RuntimeID() != p.origin.Identity().RuntimeCandidateID || p.origin.LeaseEpoch() != p.observation.lease.Epoch() ||
		p.target.Identity().InstanceID != p.recipient.InstanceID() || p.recipient.ControllerSlot() != p.unit {
		return rootoci.ErrUnauthorized
	}
	if err := p.config.credentialSource.Guard(ctx); err != nil {
		return err
	}
	if err := p.observation.guard(ctx); err != nil {
		return err
	}
	return p.localCurrent(ctx)
}
