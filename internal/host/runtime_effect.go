package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
)

// RuntimeEffectCaller is constructed only after the existing signed host request
// and current registered session have passed controller authorization.
type RuntimeEffectCaller struct {
	registration Registration
	sessionID    string
	epoch        uint64
	expiresAt    time.Time
	nonce        string
}

func (c RuntimeEffectCaller) Registration() Registration { return c.registration }
func (c RuntimeEffectCaller) SessionID() string          { return c.sessionID }
func (c RuntimeEffectCaller) Epoch() uint64              { return c.epoch }
func (c RuntimeEffectCaller) ExpiresAt() time.Time       { return c.expiresAt }
func (c RuntimeEffectCaller) Nonce() string              { return c.nonce }

// RuntimeEffectHandler derives grants from current manager-side task and DATA
// authority; this boundary supplies authenticated caller identity, never safety.
type RuntimeEffectHandler interface {
	HandleRuntimeEffect(context.Context, RuntimeEffectCaller, executionwire.RuntimeEffectQuery) (executionwire.WorkerGrantPayload, error)
}

// HostRuntimeIdentity retains the existing authenticated Agent principal.
type HostRuntimeIdentity struct {
	identity   executionwire.WorkerIdentity
	controller ed25519.PublicKey
}

func (i HostRuntimeIdentity) Identity() executionwire.WorkerIdentity { return i.identity }
func (i HostRuntimeIdentity) ControllerPublicKey() ed25519.PublicKey {
	return slices.Clone(i.controller)
}

// RuntimeWorkerIdentity binds the local worker to the actual live host session.
func (a *Agent) RuntimeWorkerIdentity(instanceID, nodeID string) (HostRuntimeIdentity, error) {
	if a.sessionLost.Load() {
		return HostRuntimeIdentity{}, errors.New("host session was lost")
	}
	if _, _, err := a.executionLease(); err != nil {
		return HostRuntimeIdentity{}, err
	}
	a.mu.RLock()
	current := a.session
	a.mu.RUnlock()
	identity := executionwire.WorkerIdentity{
		Cell: a.cfg.Cell, HostNode: a.cfg.Node, NATSUserPublicKey: a.cfg.NATSUserPublicKey,
		HostPublicKey: base64.StdEncoding.EncodeToString(a.cfg.Identity.Public().(ed25519.PublicKey)),
		HostSessionID: a.processID, RegistrationGeneration: current.RegistrationGeneration,
		InstanceID: instanceID, NodeID: nodeID,
	}
	return HostRuntimeIdentity{identity: identity, controller: slices.Clone(a.cfg.ControllerPublicKey)}, nil
}

// RuntimeEffect preserves request/reply nonce verification before exposing the
// controller envelope to the worker's independent grant verifier.
func (a *Agent) RuntimeEffect(ctx context.Context, query executionwire.RuntimeEffectQuery) (protocol.Envelope, error) {
	if a.sessionLost.Load() {
		return protocol.Envelope{}, errors.New("host session was lost")
	}
	if _, _, err := a.executionLease(); err != nil {
		return protocol.Envelope{}, err
	}
	var signed protocol.Envelope
	if _, err := a.sendToLeader(ctx, "runtime-effect", query, nil, &signed, nil); err != nil {
		return protocol.Envelope{}, err
	}
	if _, _, err := a.executionLease(); err != nil {
		return protocol.Envelope{}, err
	}
	return signed, nil
}

func (c *Controller) serveRuntimeEffect(ctx context.Context, req request, registration Registration, current session) (any, error) {
	if c.runtimeEffects == nil || registration.ManagedOCI == nil || registration.ManagedMember == nil || registration.ManagedPlacement == nil {
		return nil, errors.New("runtime effect manager or admitted member unavailable")
	}
	var query executionwire.RuntimeEffectQuery
	if err := protocol.DecodeStrict(req.Payload, &query, 64<<10); err != nil {
		return nil, err
	}
	if !entityid.Valid(query.EffectID) || !lowerHex(query.Nonce, 32) || query.Action != "acquire" && query.Action != "renew" && query.Action != "close" {
		return nil, errors.New("invalid runtime effect request")
	}
	identity := query.Identity
	if identity.Cell != c.cell || identity.HostNode != registration.Node || identity.HostPublicKey != registration.PublicKey ||
		identity.NATSUserPublicKey != registration.NATSUserPublicKey || identity.HostSessionID != req.SessionID ||
		identity.RegistrationGeneration != registration.Generation || identity.InstanceID != registration.ManagedOCI.InstanceID {
		return nil, errors.New("runtime effect differs from authenticated host identity")
	}
	if query.Task == nil || query.Task.NodeID != identity.NodeID {
		return nil, errors.New("runtime effect task assignment unavailable")
	}
	caller := RuntimeEffectCaller{registration: registration, sessionID: req.SessionID, epoch: current.Epoch, expiresAt: current.ExpiresAt, nonce: req.Nonce}
	payload, err := c.runtimeEffects.HandleRuntimeEffect(ctx, caller, query)
	if err != nil {
		return nil, err
	}
	if payload.Identity != identity || payload.TaskID != query.Task.ID || payload.ServiceID != query.Task.ServiceID ||
		payload.EffectID != query.EffectID || payload.Nonce != query.Nonce ||
		payload.Epoch != current.Epoch || payload.Revision == 0 || payload.Deadline.After(current.ExpiresAt) {
		return nil, errors.New("runtime effect grant differs from authenticated request")
	}
	if query.Action != "close" && (payload.IssuedAt.IsZero() || payload.IssuedAt.After(time.Now().Add(2*time.Second)) ||
		!payload.Deadline.After(time.Now()) || !payload.Deadline.After(payload.IssuedAt) || payload.Deadline.Sub(payload.IssuedAt) > 15*time.Second) {
		return nil, errors.New("runtime effect grant has no current bounded lifetime")
	}
	if err := c.authorityGuard(ctx, current.Epoch); err != nil {
		return nil, err
	}
	return payload, nil
}
