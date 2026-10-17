package swarmruntime

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
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

type GenericExecutionSessions struct {
	control   api.ControlClient
	authority *authority.Runtime
	manager   *Node
	drains    GenericDrainStore
}

func NewGenericExecutionSessions(control api.ControlClient, runtime *authority.Runtime, manager *Node, drains GenericDrainStore) (*GenericExecutionSessions, error) {
	if control == nil || runtime == nil || manager == nil || manager.role != "manager" || drains == nil {
		return nil, errors.New("generic execution requires actual manager, durable authority and protected drain store")
	}
	return &GenericExecutionSessions{control: control, authority: runtime, manager: manager, drains: drains}, nil
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
				if err := s.verifyCurrent(ctx, caller, q.Task, hash); err != nil {
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
		if err := s.verifyCurrent(ctx, caller, q.Task, hash); err != nil {
			return empty, err
		}
		if err := s.drains.GuardStart(ctx, h); err != nil {
			return empty, err
		}
		wire, err := drainwire.HoldSigningBytes(h)
		if err != nil {
			return empty, err
		}
		key, chain, err := s.manager.nodeSigningKey()
		if err != nil {
			return empty, err
		}
		digest := sha256.Sum256(wire)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return empty, err
		}
		signed := drainwire.SignedHold{Hold: h, CertificateChain: chain, Signature: signature}
		if err := s.authority.BeginGenericExecution(ctx, epoch, signed, func(check context.Context) error {
			if err := s.verifyCurrent(check, caller, q.Task, hash); err != nil {
				return err
			}
			return s.drains.GuardStart(check, h)
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

func (s *GenericExecutionSessions) verifyCurrent(ctx context.Context, caller host.GenericExecutionCaller, expected *api.Task, hash string) error {
	if err := caller.Guard(ctx); err != nil {
		return err
	}
	got, err := s.control.GetTask(ctx, &api.GetTaskRequest{TaskID: expected.ID})
	if err != nil || got == nil || got.Task == nil {
		return errors.Join(errors.New("generic execution actual task unavailable"), err)
	}
	task := got.Task
	actual, err := executionwire.TaskSHA256(task)
	if err != nil || actual != hash || task.DesiredState != api.TaskStateRunning || task.Status.State < api.TaskStateAssigned || task.Status.State > api.TaskStateRunning {
		return errors.New("generic execution task differs from current manager assignment")
	}
	if _, err := DecodeContainer(task); err != nil {
		return err
	}
	node, err := s.control.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return errors.Join(errors.New("generic execution actual node unavailable"), err)
	}
	n := node.Node
	i := caller.Session()
	role, scope := "container", "platform"
	if task.ServiceAnnotations.Labels[LabelRole] == FunctionWorkerRole {
		role, scope = "wasm", "tenant"
	}
	labels := n.Spec.Annotations.Labels
	if n.ID != task.NodeID || n.Spec.Annotations.Name != i.RegistrationID || n.Role != api.NodeRoleWorker || n.Spec.DesiredRole != api.NodeRoleWorker ||
		n.Spec.Membership != api.NodeMembershipAccepted || n.Spec.Availability != api.NodeAvailabilityActive ||
		labels[LabelInstanceID] == "" || i.InstanceID != "" && labels[LabelInstanceID] != i.InstanceID || labels[LabelHostRole] != role || labels[LabelExecutionScope] != scope ||
		n.Certificate.CN != n.ID || n.Certificate.Role != api.NodeRoleWorker || len(n.Certificate.Certificate) == 0 {
		return errors.New("generic execution requires exact admitted ACTIVE worker")
	}
	// Compare the authenticated registration again after actual manager reads.
	registration := caller.Registration()
	if registration.ManagedOCI != nil && registration.ManagedOCI.InstanceID != labels[LabelInstanceID] {
		return errors.New("generic execution OCI registration changed")
	}
	return caller.Guard(ctx)
}

// Used by local witness comparison without granting authority to task hashes.
func sameGenericHold(a, b drainwire.SignedHold) bool {
	left, e1 := json.Marshal(a, json.Deterministic(true))
	right, e2 := json.Marshal(b, json.Deterministic(true))
	return e1 == nil && e2 == nil && string(left) == string(right)
}
