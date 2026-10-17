package host

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/moby/swarmkit/v2/api"
)

type GenericExecutionQuery struct {
	Action             string                `json:"action"`
	Task               *api.Task             `json:"task,omitempty"`
	ExecutionSessionID string                `json:"execution_session_id,omitempty"`
	Stop               *drainwire.SignedStop `json:"stop,omitempty"`
}

type GenericExecutionReply struct {
	Hold       *drainwire.SignedHold          `json:"hold,omitempty"`
	Challenges []drainwire.DrainStopChallenge `json:"challenges,omitempty"`
}

// GenericExecutionCaller is sealed by the existing signed request/session gate.
type GenericExecutionCaller struct {
	registration Registration
	session      drainwire.HostSession
	guard        func(context.Context) error
}

func (c GenericExecutionCaller) Registration() Registration     { return c.registration }
func (c GenericExecutionCaller) Session() drainwire.HostSession { return c.session }
func (c GenericExecutionCaller) Guard(ctx context.Context) error {
	if c.guard == nil {
		return errors.New("generic execution caller is unauthenticated")
	}
	return c.guard(ctx)
}

type GenericExecutionHandler interface {
	HandleGenericExecution(context.Context, GenericExecutionCaller, GenericExecutionQuery) (GenericExecutionReply, error)
}

func genericHostSession(registration Registration, current session) (drainwire.HostSession, error) {
	if current.SessionID == "" || current.Epoch == 0 ||
		current.RegistrationGeneration != registration.Generation || !time.Now().Before(current.ExpiresAt) {
		return drainwire.HostSession{}, errors.New("generic execution host has no authenticated current session")
	}
	instanceID := ""
	if registration.ManagedOCI != nil {
		instanceID = registration.ManagedOCI.InstanceID
	}
	return drainwire.HostSession{Cell: registration.Cell, HostNode: registration.Node, RegistrationID: registration.ID,
		InstanceID: instanceID, HostSessionID: current.SessionID,
		RegistrationGeneration: current.RegistrationGeneration, HostEpoch: current.Epoch, ExpiresAt: current.ExpiresAt}, nil
}

// CurrentGenericExecutionSession reads the original authenticated host source;
// callers cannot supply session identifiers as evidence.
func (r *Reader) CurrentGenericExecutionSession(ctx context.Context, node string) (drainwire.HostSession, error) {
	registration, current, err := r.currentContainerGenerationSession(ctx, node)
	if err != nil {
		return drainwire.HostSession{}, err
	}
	return genericHostSession(registration, current)
}

func (a *Agent) GenericExecutionSession(instanceID, nodeID string) (drainwire.HostSession, error) {
	if a.sessionLost.Load() || instanceID == "" || nodeID == "" {
		return drainwire.HostSession{}, errors.New("generic execution host session unavailable")
	}
	current, deadline, err := a.executionLease()
	if err != nil {
		return drainwire.HostSession{}, err
	}
	return drainwire.HostSession{Cell: a.cfg.Cell, HostNode: a.cfg.Node, RegistrationID: entityid.Derive("host", a.cfg.Cell, a.cfg.Node),
		InstanceID: instanceID, HostSessionID: a.processID, RegistrationGeneration: current.RegistrationGeneration, HostEpoch: current.Epoch, ExpiresAt: deadline}, nil
}

func (a *Agent) GenericExecution(ctx context.Context, query GenericExecutionQuery) (GenericExecutionReply, error) {
	var reply GenericExecutionReply
	if a.sessionLost.Load() {
		return reply, errors.New("generic execution host session was lost")
	}
	if _, _, err := a.executionLease(); err != nil {
		return reply, err
	}
	if err := a.request(ctx, "generic-execution", query, &reply); err != nil {
		return reply, err
	}
	if _, _, err := a.executionLease(); err != nil {
		return GenericExecutionReply{}, err
	}
	return reply, ctx.Err()
}

func (c *Controller) serveGenericExecution(ctx context.Context, req request, registration Registration, current session) (any, error) {
	if c.genericExecutions == nil {
		return nil, errors.New("generic execution journal is pending")
	}
	var query GenericExecutionQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if query.Action != "acquire" && query.Action != "poll" && query.Action != "stop" {
		return nil, errors.New("unsupported generic execution action")
	}
	identity, err := genericHostSession(registration, current)
	if err != nil {
		return nil, err
	}
	epoch := c.authorityEpoch()
	caller := GenericExecutionCaller{registration: registration, session: identity,
		guard: func(check context.Context) error {
			return c.recheckReplyAuthority(check, epoch, req, registration, query.Action == "acquire")
		}}
	if err := caller.Guard(ctx); err != nil {
		return nil, err
	}
	return c.genericExecutions.HandleGenericExecution(ctx, caller, query)
}
