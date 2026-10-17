package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// GenericDrainStore is implemented by the protected regional ROOT capture store.
// StoreStop must independently authenticate the exact protected capture and key.
type GenericDrainStore interface {
	// Any pending, stopped or consumed protected capture fences its exact instance.
	GuardStart(context.Context, drainwire.ExecutionHold) error
	ReadChallenges(context.Context, []drainwire.SignedHold) ([]drainwire.DrainStopChallenge, error)
	StoreStop(context.Context, drainwire.SignedStop) error
}

// GenericExecutionSigner is the finite ROOT operation. The request contains
// expectations; ROOT independently derives the complete hold before signing.
type GenericExecutionSigner interface {
	SignGenericExecution(context.Context, drainwire.ExecutionHold) (drainwire.SignedHold, error)
}

type GenericExecutionSessions struct {
	control   api.ControlClient
	authority *authority.Runtime
	signer    GenericExecutionSigner
	drains    GenericDrainStore
}

func NewGenericExecutionSessions(control api.ControlClient, runtime *authority.Runtime, signer GenericExecutionSigner, drains GenericDrainStore) (*GenericExecutionSessions, error) {
	if control == nil || runtime == nil || signer == nil || drains == nil {
		return nil, errors.New("generic execution requires ROOT signer, durable authority and protected drain store")
	}
	return &GenericExecutionSessions{control: control, authority: runtime, signer: signer, drains: drains}, nil
}

func (s *GenericExecutionSessions) ListHolds(ctx context.Context, instanceID string) ([]drainwire.SignedHold, error) {
	all, err := s.authority.ListGenericExecutions(ctx)
	if err != nil {
		return nil, err
	}
	var holds []drainwire.SignedHold
	for _, hold := range all {
		if instanceID == "" || hold.Hold.InstanceID == instanceID {
			holds = append(holds, hold)
		}
	}
	return holds, nil
}

func (s *GenericExecutionSessions) HandleGenericExecution(ctx context.Context, caller host.GenericExecutionCaller, q host.GenericExecutionQuery) (host.GenericExecutionReply, error) {
	var empty host.GenericExecutionReply
	observed := s.authority.Current()
	identity := caller.Session()
	if observed.ExpiresAt.Before(identity.ExpiresAt) {
		identity.ExpiresAt = observed.ExpiresAt
	}
	// Waits and same-epoch renewals cannot extend this request's source lease.
	ctx, cancel := context.WithDeadline(ctx, identity.ExpiresAt)
	defer cancel()
	if err := caller.Guard(ctx); err != nil {
		return empty, err
	}
	epoch := observed.Epoch
	if err := s.authority.Guard(ctx, epoch); err != nil {
		return empty, err
	}
	holds, err := s.ListHolds(ctx, "")
	if err != nil {
		return empty, err
	}
	if q.Action == "acquire" {
		if !entityid.Valid(q.ExecutionSessionID) || q.Task == nil || q.Stop != nil {
			return empty, errors.New("generic execution acquire lacks exact task and execution identity")
		}
		hash, err := executionwire.TaskSHA256(q.Task)
		if err != nil {
			return empty, err
		}
		actualNode, err := s.control.GetNode(ctx, &api.GetNodeRequest{NodeID: q.Task.NodeID})
		if err != nil || actualNode == nil || actualNode.Node == nil {
			return empty, errors.Join(ErrGenericExecutionPending, err)
		}
		identity.InstanceID = actualNode.Node.Spec.Annotations.Labels[LabelInstanceID]
		fingerprint, err := ContainerTaskFingerprint(q.Task)
		if err != nil {
			return empty, err
		}
		for _, signed := range holds {
			h := signed.Hold
			if h.ExecutionSessionID == q.ExecutionSessionID {
				if h.InstanceID != identity.InstanceID || h.OriginalEpoch != epoch || !time.Now().Before(h.ExpiresAt) || !h.HostSession.SameIdentity(identity) || h.TaskID != q.Task.ID || h.ServiceID != q.Task.ServiceID || h.NodeID != q.Task.NodeID || h.TaskSHA256 != hash || h.ExecutionSHA256 != fingerprint {
					return empty, errors.New("generic execution retry changed its original identity")
				}
				if err := s.verifyCurrent(ctx, caller, q.Task, hash, h.InstanceID); err != nil {
					return empty, err
				}
				if err := s.drains.GuardStart(ctx, h); err != nil {
					return empty, err
				}
				return host.GenericExecutionReply{Hold: &signed}, nil
			}
			// A task ID cannot execute twice under another local or host session.
			if h.TaskID == q.Task.ID {
				return empty, errors.New("generic task already has another original execution hold")
			}
		}
		h := drainwire.ExecutionHold{HostSession: identity, OriginalEpoch: epoch, NodeID: q.Task.NodeID, TaskID: q.Task.ID, ServiceID: q.Task.ServiceID,
			TaskSHA256: hash, ExecutionSHA256: fingerprint, ExecutionSessionID: q.ExecutionSessionID, IssuedAt: time.Now().UTC()}
		if err := s.verifyCurrent(ctx, caller, q.Task, hash, h.InstanceID); err != nil {
			return empty, err
		}
		if err := s.drains.GuardStart(ctx, h); err != nil {
			return empty, err
		}
		signed, err := s.signer.SignGenericExecution(ctx, h)
		if err != nil {
			return empty, err
		}
		if signed.Hold.Validate() != nil || signed.Hold.IssuedAt.Before(h.IssuedAt) || signed.Hold.IssuedAt.After(time.Now().UTC()) || signed.Hold.ExpiresAt.After(h.ExpiresAt) {
			return empty, errors.New("ROOT generic execution changed original source lifetime")
		}
		expected := h
		expected.IssuedAt, expected.ExpiresAt = signed.Hold.IssuedAt, signed.Hold.ExpiresAt
		if signed.Hold != expected {
			return empty, errors.New("ROOT generic execution changed exact original identity")
		}
		commitCtx, finish := context.WithDeadline(ctx, signed.Hold.ExpiresAt)
		defer finish()
		if err := verifyGenericExecutionManager(commitCtx, s.control, signed); err != nil {
			return empty, err
		}
		if err := s.authority.BeginGenericExecution(commitCtx, epoch, signed, func(check context.Context) error {
			if err := s.verifyCurrent(check, caller, q.Task, hash, signed.Hold.InstanceID); err != nil {
				return err
			}
			return s.drains.GuardStart(check, signed.Hold)
		}); err != nil {
			return empty, err
		}
		return host.GenericExecutionReply{Hold: &signed}, nil
	}
	var current []drainwire.SignedHold
	for _, signed := range holds {
		if signed.Hold.HostSession.SameIdentity(identity) {
			current = append(current, signed)
		}
	}
	if q.Action == "poll" {
		challenges, err := s.drains.ReadChallenges(ctx, current)
		if err != nil {
			return empty, err
		}
		for _, c := range challenges {
			matched := false
			for _, h := range current {
				if c.Matches(h.Hold) {
					matched = true
					break
				}
			}
			if !matched || c.Validate(time.Now().UTC()) != nil || c.Epoch != epoch {
				return empty, errors.New("protected challenge differs from original authenticated execution")
			}
		}
		return host.GenericExecutionReply{Challenges: challenges}, caller.Guard(ctx)
	}
	if q.Action != "stop" || q.Stop == nil {
		return empty, errors.New("generic execution stop evidence missing")
	}
	proof := *q.Stop
	matched := false
	for _, h := range current {
		if proof.Challenge.Matches(h.Hold) {
			matched = true
			break
		}
	}
	if !matched {
		return empty, errors.New("generic stopped proof lacks its retained original execution hold")
	}
	node, err := s.control.GetNode(ctx, &api.GetNodeRequest{NodeID: proof.Challenge.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return empty, errors.Join(errors.New("actual worker signing node unavailable"), err)
	}
	clusters, err := s.control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || clusters == nil || len(clusters.Clusters) != 1 || clusters.Clusters[0] == nil {
		return empty, errors.Join(errors.New("actual worker cluster unavailable"), err)
	}
	cluster := clusters.Clusters[0]
	if err := drainwire.VerifySignedStop(proof, proof.Challenge, node.Node.Certificate.Certificate, cluster.RootCA.CACert, cluster.ID, time.Now().UTC()); err != nil {
		return empty, err
	}
	if err := caller.Guard(ctx); err != nil {
		return empty, err
	}
	if err := s.drains.StoreStop(ctx, proof); err != nil {
		return empty, err
	}
	return empty, caller.Guard(ctx)
}

func (s *GenericExecutionSessions) verifyCurrent(ctx context.Context, caller host.GenericExecutionCaller, expected *api.Task, hash, instanceID string) error {
	if err := caller.Guard(ctx); err != nil {
		return err
	}
	fingerprint, err := ContainerTaskFingerprint(expected)
	if err != nil {
		return err
	}
	identity := caller.Session()
	if instanceID == "" {
		return ErrGenericExecutionPending
	}
	identity.InstanceID = instanceID
	// Managed registrations also retain their independent OCI instance binding.
	registration := caller.Registration()
	if registration.ManagedOCI != nil && registration.ManagedOCI.InstanceID != instanceID {
		return errors.New("generic execution OCI registration changed")
	}
	if err := verifyGenericExecutionAssignment(ctx, s.control, drainwire.ExecutionHold{HostSession: identity,
		NodeID: expected.NodeID, TaskID: expected.ID, ServiceID: expected.ServiceID, TaskSHA256: hash, ExecutionSHA256: fingerprint}); err != nil {
		return err
	}
	return caller.Guard(ctx)
}

// Used by local witness comparison without granting authority to task hashes.
func sameGenericHold(a, b drainwire.SignedHold) bool {
	left, e1 := json.Marshal(a, json.Deterministic(true))
	right, e2 := json.Marshal(b, json.Deterministic(true))
	return e1 == nil && e2 == nil && string(left) == string(right)
}
