package swarmruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionleader"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// EffectSessions retains the workload read gate until durable execution effects
// have expired and independently stopped. Request cancellation never releases it.
type EffectSessions struct {
	control   api.ControlClient
	authority *authority.Runtime
	producer  *executionleader.Producer
	volumes   *oci.VolumeMountObserver
	recovery  sync.Mutex
	recovered uint64
	mu        sync.Mutex
	scopes    map[authority.WorkloadScope]*runtimeEffectScope
}

type runtimeEffectScope struct {
	mu         sync.Mutex
	release    func()
	context    context.Context
	epoch      uint64
	challenges map[string]runtimeStopChallenge
}

type runtimeStopChallenge struct {
	nonce  string
	effect authority.RuntimeEffect
	epoch  uint64
	issued time.Time
}

func NewEffectSessions(control api.ControlClient, runtime *authority.Runtime, producer *executionleader.Producer, volumes *oci.VolumeMountObserver) (*EffectSessions, error) {
	if control == nil || runtime == nil || producer == nil || volumes == nil {
		return nil, errors.New("runtime effects require manager, durable authority, DATA producer and OCI observer")
	}
	return &EffectSessions{control: control, authority: runtime, producer: producer, volumes: volumes, scopes: make(map[authority.WorkloadScope]*runtimeEffectScope)}, nil
}

func (s *EffectSessions) scope(scope authority.WorkloadScope) *runtimeEffectScope {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.scopes[scope]
	if held == nil {
		held = &runtimeEffectScope{challenges: make(map[string]runtimeStopChallenge)}
		s.scopes[scope] = held
	}
	return held
}

// scopeEffectContext shares the authority's existing nested read gate while
// retaining cancellation and deadlines from the individual authenticated RPC.
type scopeEffectContext struct {
	context.Context
	held context.Context
}

func (c scopeEffectContext) Value(key any) any {
	if value := c.held.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

func (s *EffectSessions) retain(ctx context.Context, epoch uint64, scope authority.WorkloadScope, held *runtimeEffectScope) error {
	if held.release != nil {
		return s.authority.Guard(ctx, epoch)
	}
	effectContext := authority.WithActiveWorkloadEffectContext(context.Background())
	release, err := s.authority.BeginActiveWorkloadEffect(scopeEffectContext{Context: ctx, held: effectContext}, epoch, scope)
	if err != nil {
		return err
	}
	held.context, held.epoch, held.release = effectContext, epoch, release
	return nil
}

// recover restores every unresolved scope, including retired registrations,
// before this leader may deliver a new grant.
func (s *EffectSessions) recover(ctx context.Context, epoch uint64) error {
	s.recovery.Lock()
	defer s.recovery.Unlock()
	if s.recovered == epoch {
		return s.authority.Guard(ctx, epoch)
	}
	effects, err := s.authority.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil {
		return err
	}
	for _, effect := range effects {
		held := s.scope(effect.Scope)
		held.mu.Lock()
		err = s.retain(ctx, epoch, effect.Scope, held)
		clear(held.challenges)
		held.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := s.authority.Guard(ctx, epoch); err != nil {
		return err
	}
	s.recovered = epoch
	return nil
}

func (s *EffectSessions) current(ctx context.Context) (uint64, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return 0, authority.ErrFenced
	}
	current := s.authority.Current()
	if !current.CanMutate() {
		return 0, authority.ErrFenced
	}
	if err := s.authority.Guard(ctx, current.Epoch); err != nil {
		return 0, err
	}
	return current.Epoch, nil
}

func (s *EffectSessions) HandleRuntimeEffect(ctx context.Context, caller host.RuntimeEffectCaller, query executionwire.RuntimeEffectQuery) (executionwire.WorkerGrantPayload, error) {
	var empty executionwire.WorkerGrantPayload
	epoch, err := s.current(ctx)
	if err != nil || caller.Epoch() != epoch {
		return empty, errors.Join(authority.ErrFenced, err)
	}
	registration := caller.Registration()
	if registration.ManagedPlacement == nil || registration.ManagedMember == nil || registration.ManagedOCI == nil || query.Task == nil ||
		query.Identity.Cell != registration.Cell || query.Identity.HostNode != registration.Node || query.Identity.InstanceID != registration.ManagedOCI.InstanceID ||
		query.Identity.NodeID != query.Task.NodeID ||
		query.Action != "close" && (query.Identity.HostPublicKey != registration.PublicKey || query.Identity.NATSUserPublicKey != registration.NATSUserPublicKey ||
			query.Identity.RegistrationGeneration != registration.Generation || query.Identity.HostSessionID != caller.SessionID()) {
		return empty, errors.New("runtime effect caller differs from admitted worker")
	}
	if err := s.recover(ctx, epoch); err != nil {
		return empty, err
	}
	scope := authority.WorkloadScope{DatabaseID: registration.ManagedPlacement.DatabaseID, PartitionID: registration.ManagedPlacement.PartitionID}
	held := s.scope(scope)
	held.mu.Lock()
	defer held.mu.Unlock()
	if err := s.retain(ctx, epoch, scope, held); err != nil {
		return empty, err
	}
	ctx = scopeEffectContext{Context: ctx, held: held.context}
	hash, err := executionwire.TaskSHA256(query.Task)
	if err != nil {
		return empty, err
	}
	effects, err := s.authority.ListRuntimeEffectHistory(ctx, scope)
	if err != nil {
		return empty, err
	}
	var existing *authority.RuntimeEffect
	for i := range effects {
		if effects[i].EffectID == query.EffectID {
			existing = &effects[i]
			break
		}
	}
	if existing != nil && !sameRuntimeWorker(*existing, registration, query, hash) {
		return empty, errors.New("runtime effect differs from its original admitted identity")
	}
	if query.Action == "close" {
		if existing == nil {
			return empty, errors.New("runtime effect was never durably granted")
		}
		return s.close(ctx, epoch, held, *existing, query)
	}
	if query.Action != "acquire" && query.Action != "renew" {
		return empty, errors.New("unsupported runtime effect action")
	}
	// A surviving old-epoch gate cannot be joined by a new-epoch producer.
	// Its old effects must settle before admitting more execution in this scope.
	if held.epoch != epoch {
		return empty, authority.ErrFenced
	}
	actual, err := s.currentTask(ctx, registration, query.Task, hash)
	if err != nil {
		return empty, err
	}
	if existing != nil {
		if existing.Phase != authority.RuntimeEffectHeld || existing.Epoch != epoch || !time.Now().Before(existing.ExpiresAt) {
			return empty, authority.ErrFenced
		}
		material, err := runtimeMaterial(*existing)
		if err != nil {
			return empty, err
		}
		if err := s.producer.VerifyCurrent(ctx, actual, caller, material); err != nil {
			return empty, err
		}
		if query.Action == "renew" {
			deadline, err := s.deadline(caller)
			if err != nil {
				return empty, err
			}
			if deadline.Before(existing.ExpiresAt) {
				return empty, authority.ErrFenced
			}
			existing.ExpiresAt = deadline
			sequence, err := s.authority.RenewRuntimeEffect(ctx, epoch, *existing, existing.Sequence)
			if err != nil {
				return empty, err
			}
			existing.Sequence = sequence
		}
		return s.readback(ctx, epoch, *existing, query.Nonce, time.Now().UTC())
	}
	if query.Action != "acquire" {
		return empty, errors.New("runtime effect renewal has no original grant")
	}
	material, err := s.producer.Resolve(ctx, actual, caller)
	if err != nil {
		return empty, err
	}
	wire, err := json.Marshal(material, json.Deterministic(true))
	if err != nil {
		return empty, err
	}
	deadline, err := s.deadline(caller)
	if err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	payload := executionwire.WorkerGrantPayload{Identity: query.Identity, TaskID: actual.ID, ServiceID: actual.ServiceID,
		TaskSHA256: hash, EffectID: query.EffectID, Epoch: epoch, IssuedAt: now, Deadline: deadline, Material: material, Phase: authority.RuntimeEffectHeld}
	admission, err := executionwire.WorkerAdmissionSHA256(payload)
	if err != nil {
		return empty, err
	}
	effect := authority.RuntimeEffect{EffectID: query.EffectID, Scope: scope, RegistrationID: registration.ID,
		HostSessionID: query.Identity.HostSessionID, WorkerPublicKey: query.Identity.HostPublicKey, NATSUserPublicKey: query.Identity.NATSUserPublicKey,
		RegistrationGeneration: query.Identity.RegistrationGeneration, InstanceID: query.Identity.InstanceID, NodeID: query.Identity.NodeID,
		TaskID: actual.ID, ServiceID: actual.ServiceID, TaskSHA256: hash, AdmissionSHA256: admission, Material: wire,
		MaterialSHA256: fmt.Sprintf("%x", sha256.Sum256(wire)), Epoch: epoch, IssuedAt: now, ExpiresAt: deadline, Phase: authority.RuntimeEffectHeld}
	sequence, err := s.authority.BeginRuntimeEffect(ctx, epoch, effect)
	if err != nil {
		return empty, err
	}
	effect.Sequence = sequence
	return s.readback(ctx, epoch, effect, query.Nonce, now)
}

func sameRuntimeWorker(effect authority.RuntimeEffect, registration host.Registration, query executionwire.RuntimeEffectQuery, hash string) bool {
	return effect.RegistrationID == registration.ID && effect.HostSessionID == query.Identity.HostSessionID &&
		effect.WorkerPublicKey == query.Identity.HostPublicKey && effect.NATSUserPublicKey == query.Identity.NATSUserPublicKey &&
		effect.RegistrationGeneration == query.Identity.RegistrationGeneration && effect.InstanceID == query.Identity.InstanceID &&
		effect.NodeID == query.Identity.NodeID && effect.TaskID == query.Task.ID && effect.ServiceID == query.Task.ServiceID && effect.TaskSHA256 == hash
}

func (s *EffectSessions) currentTask(ctx context.Context, registration host.Registration, requested *api.Task, hash string) (*api.Task, error) {
	response, err := s.control.GetTask(ctx, &api.GetTaskRequest{TaskID: requested.ID})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Task == nil {
		return nil, errors.New("manager task unavailable")
	}
	task := response.Task
	actualHash, err := executionwire.TaskSHA256(task)
	if err != nil || actualHash != hash || task.DesiredState != api.TaskStateRunning || task.Status.State < api.TaskStateAssigned || task.Status.State > api.TaskStateRunning {
		return nil, errors.New("manager task differs from current running assignment")
	}
	node, err := s.admittedNode(ctx, registration, task.NodeID)
	if err != nil {
		return nil, err
	}
	if node.Status.State != api.NodeStatus_READY || node.Spec.Availability != api.NodeAvailabilityActive {
		return nil, errors.New("manager task host is not ready for current execution")
	}
	return task, nil
}

func (s *EffectSessions) admittedNode(ctx context.Context, registration host.Registration, nodeID string) (*api.Node, error) {
	response, err := s.control.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	if response == nil || response.Node == nil || registration.ManagedOCI == nil {
		return nil, errors.New("manager worker unavailable")
	}
	region, err := oci.Region(registration.ManagedOCI.Region).OCIRegion()
	if err != nil {
		return nil, err
	}
	node := response.Node
	labels := node.Spec.Annotations.Labels
	if node.ID != nodeID || node.Role != api.NodeRoleWorker || node.Spec.DesiredRole != api.NodeRoleWorker || node.Spec.Membership != api.NodeMembershipAccepted ||
		node.Spec.Annotations.Name != registration.ID || labels[LabelRegion] != region || labels[LabelHostRole] != "container" ||
		labels[LabelExecutionScope] != "platform" || labels[LabelInstanceID] != registration.ManagedOCI.InstanceID ||
		node.Certificate.CN != nodeID || node.Certificate.Role != api.NodeRoleWorker || len(node.Certificate.Certificate) == 0 {
		return nil, errors.New("manager worker differs from independently admitted host identity")
	}
	return node, nil
}

func (s *EffectSessions) deadline(caller host.RuntimeEffectCaller) (time.Time, error) {
	now := time.Now().UTC()
	deadline := now.Add(15 * time.Second)
	for _, limit := range []time.Time{s.authority.Current().ExpiresAt, caller.ExpiresAt()} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	if !deadline.After(now.Add(3 * time.Second)) {
		return time.Time{}, authority.ErrFenced
	}
	return deadline.UTC(), nil
}

func runtimeMaterial(effect authority.RuntimeEffect) (executionwire.WorkerGrantMaterial, error) {
	var material executionwire.WorkerGrantMaterial
	if err := json.Unmarshal(effect.Material, &material, json.RejectUnknownMembers(true)); err != nil {
		return material, err
	}
	wire, err := json.Marshal(material, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, effect.Material) {
		return material, errors.New("retained runtime material is not canonical")
	}
	return material, nil
}

func runtimePayload(effect authority.RuntimeEffect, nonce string, issued time.Time) (executionwire.WorkerGrantPayload, error) {
	material, err := runtimeMaterial(effect)
	if err != nil {
		return executionwire.WorkerGrantPayload{}, err
	}
	var registration host.Registration
	if err := json.Unmarshal(material.Registration, &registration, json.RejectUnknownMembers(true)); err != nil {
		return executionwire.WorkerGrantPayload{}, err
	}
	payload := executionwire.WorkerGrantPayload{Identity: executionwire.WorkerIdentity{Cell: registration.Cell, HostNode: registration.Node,
		NATSUserPublicKey: effect.NATSUserPublicKey, HostPublicKey: effect.WorkerPublicKey, InstanceID: effect.InstanceID, NodeID: effect.NodeID,
		HostSessionID: effect.HostSessionID, RegistrationGeneration: effect.RegistrationGeneration}, TaskID: effect.TaskID, ServiceID: effect.ServiceID,
		TaskSHA256: effect.TaskSHA256, EffectID: effect.EffectID, Nonce: nonce, Epoch: effect.Epoch, Revision: effect.Sequence,
		IssuedAt: issued, Deadline: effect.ExpiresAt, Material: material, Phase: effect.Phase}
	digest, err := executionwire.WorkerAdmissionSHA256(payload)
	if err != nil || digest != effect.AdmissionSHA256 {
		return executionwire.WorkerGrantPayload{}, errors.New("retained runtime admission differs from journal")
	}
	return payload, nil
}

func (s *EffectSessions) readback(ctx context.Context, epoch uint64, expected authority.RuntimeEffect, nonce string, issued time.Time) (executionwire.WorkerGrantPayload, error) {
	var empty executionwire.WorkerGrantPayload
	history, err := s.authority.ListRuntimeEffectHistory(ctx, expected.Scope)
	if err != nil {
		return empty, err
	}
	for _, effect := range history {
		if effect.EffectID != expected.EffectID {
			continue
		}
		want, err := json.Marshal(expected, json.Deterministic(true))
		if err != nil {
			return empty, err
		}
		got, err := json.Marshal(effect, json.Deterministic(true))
		if err != nil || !bytes.Equal(want, got) || effect.Sequence != expected.Sequence {
			return empty, authority.ErrConflict
		}
		if err := s.authority.Guard(ctx, epoch); err != nil {
			return empty, err
		}
		payload, err := runtimePayload(effect, nonce, issued)
		payload.LeaderEpoch = epoch
		return payload, err
	}
	return empty, errors.New("runtime effect durable readback unavailable")
}

func (s *EffectSessions) close(ctx context.Context, epoch uint64, held *runtimeEffectScope, effect authority.RuntimeEffect, query executionwire.RuntimeEffectQuery) (executionwire.WorkerGrantPayload, error) {
	var empty executionwire.WorkerGrantPayload
	if effect.Phase != authority.RuntimeEffectSettled {
		sequence, err := s.authority.CloseRuntimeEffect(ctx, epoch, effect.Scope, effect.EffectID, effect.Sequence)
		if err != nil {
			return empty, err
		}
		effect.Phase, effect.Sequence = authority.RuntimeEffectClosing, sequence
	}
	if effect.Phase == authority.RuntimeEffectClosing && !time.Now().Before(effect.ExpiresAt) {
		if query.StopProof != nil {
			challenge, exists := held.challenges[effect.EffectID]
			if !exists {
				return empty, errors.New("runtime stop challenge unavailable; request a fresh challenge")
			}
			sequence, err := s.authority.SettleRuntimeEffect(ctx, epoch, effect.Scope, effect.EffectID, effect.Sequence, func(check context.Context, latest authority.RuntimeEffect) error {
				return s.verifyRuntimeStop(check, epoch, latest, challenge, *query.StopProof)
			})
			if err != nil {
				return empty, err
			}
			effect.Phase, effect.Sequence = authority.RuntimeEffectSettled, sequence
			delete(held.challenges, effect.EffectID)
		} else {
			challenge, exists := held.challenges[effect.EffectID]
			if !exists || challenge.effect.Sequence != effect.Sequence || challenge.epoch != epoch || time.Since(challenge.issued) > 10*time.Second {
				var nonce [32]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					return empty, err
				}
				held.challenges[effect.EffectID] = runtimeStopChallenge{nonce: hex.EncodeToString(nonce[:]), effect: effect, epoch: epoch, issued: time.Now().UTC()}
			}
		}
	}
	payload, err := s.readback(ctx, epoch, effect, query.Nonce, effect.IssuedAt)
	if err != nil {
		return empty, err
	}
	if effect.Phase == authority.RuntimeEffectClosing && !time.Now().Before(effect.ExpiresAt) {
		payload.StopChallenge = held.challenges[effect.EffectID].nonce
	}
	if effect.Phase == authority.RuntimeEffectSettled {
		if err := s.releaseSettled(ctx, effect.Scope, held); err != nil {
			return empty, err
		}
	}
	return payload, nil
}

func (s *EffectSessions) releaseSettled(ctx context.Context, scope authority.WorkloadScope, held *runtimeEffectScope) error {
	pending, err := s.authority.ListUnresolvedRuntimeEffects(ctx, scope)
	if err != nil {
		return err
	}
	if len(pending) == 0 && held.release != nil {
		held.release()
		held.release, held.context, held.epoch = nil, nil, 0
		clear(held.challenges)
	}
	return nil
}

// Reconcile settles only exact OCI TERMINATED instances after the latest grant
// expiry; a missing task, stopped instance or failed provider read retains holds.
func (s *EffectSessions) Reconcile(ctx context.Context) error {
	epoch, err := s.current(ctx)
	if err != nil {
		return err
	}
	if err := s.recover(ctx, epoch); err != nil {
		return err
	}
	effects, err := s.authority.ListAllUnresolvedRuntimeEffects(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, effect := range effects {
		held := s.scope(effect.Scope)
		held.mu.Lock()
		if !time.Now().Before(effect.ExpiresAt) {
			_, err := s.authority.SettleRuntimeEffect(ctx, epoch, effect.Scope, effect.EffectID, effect.Sequence, func(check context.Context, latest authority.RuntimeEffect) error {
				observation, err := s.volumes.ObserveTerminatedInstance(check, latest.InstanceID)
				if err != nil {
					return err
				}
				if !observation.IsVerified() || observation.InstanceID() != latest.InstanceID {
					return errors.New("runtime stop OCI identity differs")
				}
				return nil
			})
			if err != nil {
				failures = append(failures, err)
			}
		}
		if err := s.releaseSettled(ctx, effect.Scope, held); err != nil {
			failures = append(failures, err)
		}
		held.mu.Unlock()
	}
	s.mu.Lock()
	retained := maps.Clone(s.scopes)
	s.mu.Unlock()
	for scope, held := range retained {
		held.mu.Lock()
		if held.release != nil {
			if err := s.releaseSettled(ctx, scope, held); err != nil {
				failures = append(failures, err)
			}
		}
		held.mu.Unlock()
	}
	return errors.Join(failures...)
}

// Run keeps reconciling after callers disappear. Leader loss preserves every
// local gate; durable R3 records recover the same holds after process restart.
func (s *EffectSessions) Run(ctx context.Context) error {
	ticks := time.Tick(time.Second)
	for {
		_ = s.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks:
		}
	}
}
