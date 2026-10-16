package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nkeys"
)

const workerGrantLifetime = 15 * time.Second
const workerStopReserve = 3 * time.Second
const workerRenewInterval = 3 * time.Second

type WorkerIdentity = executionwire.WorkerIdentity
type RuntimeEffectQuery = executionwire.RuntimeEffectQuery
type WorkerGrantPayload = executionwire.WorkerGrantPayload

// WorkerTransport is untrusted I/O. The existing host.Agent implements it;
// only the pinned controller signature can seal a worker grant.
type WorkerTransport interface {
	RuntimeEffect(context.Context, RuntimeEffectQuery) (protocol.Envelope, error)
}

type VerifiedWorkerGrant struct {
	payload           WorkerGrantPayload
	material          []byte
	materialSHA256    string
	admissionSHA256   string
	challengeIssuedAt time.Time
	envelope          protocol.Envelope
}

func (g VerifiedWorkerGrant) Identity() WorkerIdentity { return g.payload.Identity }
func (g VerifiedWorkerGrant) Material() (WorkerGrantMaterial, error) {
	var material WorkerGrantMaterial
	err := json.Unmarshal(g.material, &material)
	return material, err
}
func (g VerifiedWorkerGrant) TaskSHA256() string      { return g.payload.TaskSHA256 }
func (g VerifiedWorkerGrant) Epoch() uint64           { return g.payload.Epoch }
func (g VerifiedWorkerGrant) Deadline() time.Time     { return g.payload.Deadline }
func (g VerifiedWorkerGrant) EffectID() string        { return g.payload.EffectID }
func (g VerifiedWorkerGrant) Revision() uint64        { return g.payload.Revision }
func (g VerifiedWorkerGrant) MaterialSHA256() string  { return g.materialSHA256 }
func (g VerifiedWorkerGrant) AdmissionSHA256() string { return g.admissionSHA256 }

type workerTaskSession struct {
	task        *api.Task
	grant       VerifiedWorkerGrant
	pins        *RuntimePins
	observation RuntimeObservation
	stopped     bool
	closing     bool
}

type WorkerSession struct {
	transport  WorkerTransport
	identity   WorkerIdentity
	controller ed25519.PublicKey
	client     *containerd.Client
	stopSigner RuntimeStopSigner
	guardRoot  string
	mu         sync.Mutex
	acquire    sync.Mutex
	source     *Source
	tasks      map[string]*workerTaskSession
}

func NewWorkerSessionFromAgent(agent *host.Agent, instanceID, nodeID string, client *containerd.Client) (*WorkerSession, error) {
	if agent == nil {
		return nil, ErrUnsafe
	}
	admitted, err := agent.RuntimeWorkerIdentity(instanceID, nodeID)
	if err != nil {
		return nil, err
	}
	return NewWorkerSession(agent, admitted.Identity(), admitted.ControllerPublicKey(), client)
}

func NewWorkerSession(transport WorkerTransport, identity WorkerIdentity, controller ed25519.PublicKey, client *containerd.Client) (*WorkerSession, error) {
	hostKey, err := base64.StdEncoding.Strict().DecodeString(identity.HostPublicKey)
	if err != nil || len(hostKey) != ed25519.PublicKeySize || transport == nil || client == nil || len(controller) != ed25519.PublicKeySize ||
		identity.Cell == "" || identity.HostNode == "" || identity.NodeID == "" || !strings.HasPrefix(identity.InstanceID, "ocid1.instance.") ||
		!nkeys.IsValidPublicUserKey(identity.NATSUserPublicKey) || !entityid.Valid(identity.HostSessionID) || identity.RegistrationGeneration == 0 {
		return nil, ErrUnsafe
	}
	return &WorkerSession{transport: transport, identity: identity, controller: slices.Clone(controller), client: client, tasks: make(map[string]*workerTaskSession)}, nil
}
func (s *WorkerSession) bindSource(source *Source) error {
	if s == nil || source == nil {
		return ErrUnsafe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source != nil {
		return ErrUnsafe
	}
	s.source = source
	return nil
}

func (s *WorkerSession) request(ctx context.Context, task *api.Task, action, effectID string, proofs ...*executionwire.SignedRuntimeStop) (VerifiedWorkerGrant, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || task == nil || task.NodeID != s.identity.NodeID {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return VerifiedWorkerGrant{}, err
	}
	identity := s.identity
	if action == "close" {
		s.mu.Lock()
		if held := s.tasks[hash]; held != nil && held.grant.EffectID() == effectID {
			identity = held.grant.Identity()
		}
		s.mu.Unlock()
	}
	query := RuntimeEffectQuery{Action: action, EffectID: effectID, Nonce: hex.EncodeToString(nonce[:]), Task: task.Copy(), Identity: identity}
	if len(proofs) > 0 {
		if action != "close" || len(proofs) != 1 {
			return VerifiedWorkerGrant{}, ErrUnsafe
		}
		query.StopProof = proofs[0]
	}
	envelope, err := s.transport.RuntimeEffect(ctx, query)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedWorkerGrant{}, err
	}
	var response struct {
		Nonce     string         `json:"nonce"`
		Node      string         `json:"node"`
		SessionID string         `json:"session_id"`
		Epoch     uint64         `json:"epoch"`
		Operation string         `json:"operation"`
		Error     string         `json:"error,omitempty"`
		Retryable bool           `json:"retryable,omitzero"`
		Payload   jsontext.Value `json:"payload,omitempty"`
	}
	if err := protocol.DecodeStrict([]byte(envelope.Payload), &response, 512<<10); err != nil {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	if response.Node != s.identity.HostNode || response.SessionID != s.identity.HostSessionID || response.Operation != "runtime-effect" || response.Epoch == 0 ||
		len(response.Nonce) != 32 || response.Error != "" {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	now := time.Now().UTC()
	scope := protocol.EnvelopeScope{Region: s.identity.Cell, Kind: "host.response.runtime-effect", Actor: "controller", OperationID: entityid.Derive("host-request", response.Nonce), Epoch: response.Epoch}
	if err := protocol.VerifyEnvelope(envelope, scope, s.controller, now, protocol.VerifyPolicy{MaxLifetime: 10 * time.Second, ClockSkew: 2 * time.Second}); err != nil {
		return VerifiedWorkerGrant{}, err
	}
	var payload WorkerGrantPayload
	if err := protocol.DecodeStrict(response.Payload, &payload, 512<<10); err != nil {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	if payload.Identity != identity || payload.TaskID != task.ID || payload.ServiceID != task.ServiceID || payload.TaskSHA256 != hash || payload.EffectID != effectID ||
		payload.Nonce != query.Nonce || payload.Epoch == 0 || payload.Epoch > response.Epoch || action != "close" && payload.Epoch != response.Epoch || payload.Revision == 0 || payload.IssuedAt.IsZero() || payload.IssuedAt.After(now.Add(2*time.Second)) ||
		payload.Deadline.IsZero() || action != "close" && (!payload.Deadline.After(now.Add(workerStopReserve)) || !payload.Deadline.After(payload.IssuedAt) || payload.Deadline.Sub(payload.IssuedAt) > workerGrantLifetime) {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	if action == "close" && payload.Phase != "closing" && payload.Phase != "settled" || action != "close" && (payload.Phase != "held" || payload.StopChallenge != "") {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	material, err := json.Marshal(payload.Material, json.Deterministic(true))
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	admission, err := WorkerAdmissionSHA256(payload)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	envelope.Payload = envelope.Payload.Clone()
	return VerifiedWorkerGrant{envelope: envelope, payload: payload, material: material, materialSHA256: fmt.Sprintf("%x", sha256.Sum256(material)), admissionSHA256: admission, challengeIssuedAt: envelope.IssuedAt}, nil
}

// WorkerAdmissionSHA256 computes the shared inert identity digest.
func WorkerAdmissionSHA256(payload WorkerGrantPayload) (string, error) {
	return executionwire.WorkerAdmissionSHA256(payload)
}

func (s *WorkerSession) Resolve(ctx context.Context, task *api.Task) (VerifiedWorkerGrant, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || task == nil {
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	s.acquire.Lock()
	defer s.acquire.Unlock()
	s.mu.Lock()
	if s.source == nil || s.stopSigner == nil || s.guardRoot == "" {
		s.mu.Unlock()
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	if existing := s.tasks[hash]; existing != nil {
		grant, closing, stopped := existing.grant, existing.closing, existing.stopped
		s.mu.Unlock()
		if closing || stopped || !grant.Deadline().After(time.Now().Add(workerStopReserve)) {
			return VerifiedWorkerGrant{}, ErrUnsafe
		}
		return grant, nil
	}
	s.mu.Unlock()
	recovered, err := s.recoverRuntime(ctx, task, hash)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	if recovered != nil {
		s.mu.Lock()
		s.tasks[hash] = recovered
		s.mu.Unlock()
		go s.stopRecovered(task.Copy(), hash, recovered)
		return VerifiedWorkerGrant{}, ErrUnsafe
	}
	effectID := entityid.Derive("runtime-effect", s.identity.HostSessionID, hash)
	grant, err := s.request(ctx, task, "acquire", effectID)
	if err != nil {
		return VerifiedWorkerGrant{}, err
	}
	if err := s.persistGrant(grant); err != nil {
		// The manager may already hold the effect; retain it for expiry settlement.
		held := &workerTaskSession{task: task.Copy(), grant: grant, closing: true}
		s.mu.Lock()
		s.tasks[hash] = held
		s.mu.Unlock()
		go s.settleStopped(task.Copy(), hash, held)
		return VerifiedWorkerGrant{}, err
	}
	held := &workerTaskSession{task: task.Copy(), grant: grant}
	s.mu.Lock()
	s.tasks[hash] = held
	s.mu.Unlock()
	go s.renew(hash, held)
	go s.watchdog(hash, held)
	return grant, nil
}

func (s *WorkerSession) VerifyCurrent(ctx context.Context, task *api.Task, grant VerifiedWorkerGrant) error {
	if s == nil || ctx == nil || ctx.Err() != nil || task == nil || grant.admissionSHA256 == "" {
		return ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	held := s.tasks[hash]
	if held == nil || held.closing || held.stopped || held.grant.AdmissionSHA256() != grant.AdmissionSHA256() ||
		!held.grant.Deadline().After(time.Now().Add(workerStopReserve)) {
		return ErrUnsafe
	}
	return nil
}

func (s *WorkerSession) TrackRuntime(ctx context.Context, task *api.Task, pins RuntimePins, observation RuntimeObservation) error {
	if s == nil || ctx == nil || task == nil {
		return ErrUnsafe
	}
	hash, err := TaskSHA256(task)
	if err != nil {
		return err
	}
	observed, err := (RuntimeObserver{Client: s.client}).Observe(ctx, pins)
	if err != nil || observed != observation {
		return errors.Join(ErrUnsafe, err)
	}
	s.mu.Lock()
	held := s.tasks[hash]
	if held == nil || pins.ContainerSpecSHA256 != hash || observed.ContainerID != "ts-"+task.ID {
		s.mu.Unlock()
		return ErrUnsafe
	}
	if held.pins != nil && (held.observation.Process != observed.Process || held.observation.ContainerID != observed.ContainerID || held.observation.PIDNamespace != observed.PIDNamespace || held.observation.MountNamespace != observed.MountNamespace) {
		s.mu.Unlock()
		return ErrUnsafe
	}
	held.pins = &pins
	held.observation = observed
	grant := held.grant
	expired := held.closing || held.stopped || !held.grant.Deadline().After(time.Now().Add(workerStopReserve))
	s.mu.Unlock()
	if persistErr := s.persistRuntime(grant, pins, observed); persistErr != nil || s.VerifyCurrent(ctx, task, grant) != nil {
		expired = true
	}
	if expired {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return errors.Join(ErrUnsafe, s.stopRuntime(stopCtx, task, hash))
	}
	return nil
}

// WithTaskEffect retains only a local execution scope; the manager's durable
// task session remains held across callbacks and across a running writer.
func (s *WorkerSession) WithTaskEffect(ctx context.Context, task *api.Task, effect func(context.Context) error) error {
	grant, err := s.Resolve(ctx, task)
	if err != nil {
		return err
	}
	if effect == nil {
		return ErrUnsafe
	}
	ctx, cancel := context.WithDeadline(ctx, grant.Deadline().Add(-workerStopReserve))
	defer cancel()
	held := &workerHeld{session: s, hash: grant.TaskSHA256(), admission: grant.AdmissionSHA256()}
	held.active.Store(true)
	defer held.active.Store(false)
	ctx = context.WithValue(ctx, workerHeldKey{}, held)
	if err := s.VerifyCurrent(ctx, task, grant); err != nil {
		return err
	}
	err = effect(ctx)
	return errors.Join(err, s.VerifyCurrent(ctx, task, grant))
}

type workerHeldKey struct{}
type workerHeld struct {
	session         *WorkerSession
	hash, admission string
	active          atomic.Bool
}

func (s *WorkerSession) renew(hash string, held *workerTaskSession) {
	for range time.Tick(workerRenewInterval) {
		s.mu.Lock()
		grant, closing, stopped, source := held.grant, held.closing, held.stopped, s.source
		pins, previous := held.pins, held.observation
		s.mu.Unlock()
		if closing || stopped {
			return
		}
		deadline := grant.Deadline().Add(-workerStopReserve)
		if !time.Now().Before(deadline) {
			return
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		_, err := source.ResolveRuntime(ctx, held.task)
		if err == nil && pins != nil {
			var current RuntimeObservation
			current, err = (RuntimeObserver{Client: s.client}).Observe(ctx, *pins)
			if err == nil && (current.Process != previous.Process || current.ContainerID != previous.ContainerID || current.PIDNamespace != previous.PIDNamespace || current.MountNamespace != previous.MountNamespace) {
				err = ErrUnsafe
			}
			if err == nil {
				err = source.RecordRuntime(ctx, held.task, current)
			}
		}
		if err == nil {
			grant, err = s.request(ctx, held.task, "renew", grant.EffectID())
		}
		cancel()
		if err != nil {
			continue
		}
		s.mu.Lock()
		accept := !held.closing && !held.stopped && grant.AdmissionSHA256() == held.grant.AdmissionSHA256() && grant.Revision() > held.grant.Revision() && grant.Deadline().After(held.grant.Deadline())
		s.mu.Unlock()
		if accept && s.persistGrant(grant) == nil {
			s.mu.Lock()
			if !held.closing && !held.stopped && grant.Revision() > held.grant.Revision() {
				held.grant = grant
			}
			s.mu.Unlock()
		}
	}
}

// The deadline watcher never waits for a renewal request or its validation.
func (s *WorkerSession) watchdog(hash string, held *workerTaskSession) {
	for {
		s.mu.Lock()
		deadline, closing, stopped := held.grant.Deadline().Add(-workerStopReserve), held.closing, held.stopped
		s.mu.Unlock()
		if closing || stopped {
			return
		}
		if wait := time.Until(deadline); wait > 0 {
			<-time.After(wait)
			continue
		}
		if s.expire(hash, held) {
			return
		}
	}
}

func (s *WorkerSession) expire(hash string, held *workerTaskSession) bool {
	s.mu.Lock()
	if held.closing || held.stopped {
		s.mu.Unlock()
		return true
	}
	if held.grant.Deadline().Add(-workerStopReserve).After(time.Now()) {
		s.mu.Unlock()
		return false
	}
	held.closing = true
	grant, task, source := held.grant, held.task.Copy(), s.source
	s.mu.Unlock()
	ctx, cancel := context.WithDeadline(context.Background(), grant.Deadline())
	defer cancel()
	// Withdrawal precedes the exact stop even if its acknowledgement is lost.
	withdrawCtx, withdrawCancel := context.WithTimeout(ctx, time.Second)
	withdrawResult := make(chan error, 1)
	go func() { withdrawResult <- source.WithdrawTask(withdrawCtx, task, grant) }()
	var withdrawErr error
	select {
	case withdrawErr = <-withdrawResult:
	case <-withdrawCtx.Done():
		withdrawErr = withdrawCtx.Err()
	}
	withdrawCancel()
	stopErr := s.stopRuntime(ctx, task, hash)
	// A failed withdrawal or stop leaves the durable effect unresolved. The
	// settlement observer still retries, allowing a delayed actual stop to settle.
	_ = errors.Join(withdrawErr, stopErr)
	s.settleStopped(task, hash, held)
	return true
}

func (s *WorkerSession) settleStopped(task *api.Task, hash string, held *workerTaskSession) {
	for {
		s.mu.Lock()
		grant, signer := held.grant, s.stopSigner
		s.mu.Unlock()
		if wait := time.Until(grant.Deadline()); wait > 0 {
			<-time.After(wait)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		closing, err := s.request(ctx, task, "close", grant.EffectID())
		if err == nil && (closing.AdmissionSHA256() != grant.AdmissionSHA256() || closing.Deadline().Before(grant.Deadline()) || closing.Revision() < grant.Revision()) {
			err = ErrUnsafe
		}
		if err == nil {
			s.mu.Lock()
			held.grant = closing
			s.mu.Unlock()
			if closing.payload.Phase == "settled" {
				s.mu.Lock()
				held.stopped = true
				s.mu.Unlock()
				cancel()
				return
			}
			var observed ObservedRuntimeStop
			observed, err = s.ObserveRuntimeStop(ctx, task, closing, closing.payload.StopChallenge)
			if err == nil && signer != nil {
				var proof executionwire.SignedRuntimeStop
				proof, err = signer.SignRuntimeStop(ctx, observed)
				if err == nil {
					var settled VerifiedWorkerGrant
					settled, err = s.request(ctx, task, "close", closing.EffectID(), &proof)
					if err == nil && settled.payload.Phase == "settled" && settled.AdmissionSHA256() == closing.AdmissionSHA256() && settled.Deadline().Equal(closing.Deadline()) && settled.Revision() >= closing.Revision() {
						s.mu.Lock()
						held.grant, held.stopped = settled, true
						s.mu.Unlock()
						cancel()
						return
					}
				}
			}
		}
		cancel()
		<-time.After(workerRenewInterval)
	}
}

func (s *WorkerSession) stopRuntime(ctx context.Context, task *api.Task, hash string) error {
	ctx = namespaces.WithNamespace(ctx, "terrascale")
	container, err := s.client.LoadContainer(ctx, "ts-"+task.ID)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	labels, err := container.Labels(ctx)
	if err != nil {
		return err
	}
	if labels["terrascale.task"] != task.ID || labels["terrascale.service"] != task.ServiceID || labels["terrascale.spec"] != hash || labels["terrascale.task-binding"] != hash {
		return ErrUnsafe
	}
	process, err := container.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	status, err := process.Status(ctx)
	if err != nil {
		return err
	}
	if status.Status == containerd.Stopped {
		return nil
	}
	if status.Status != containerd.Created && status.Status != containerd.Running {
		return ErrUnsafe
	}
	s.mu.Lock()
	held := s.tasks[hash]
	var pins *RuntimePins
	var expected RuntimeObservation
	if held != nil {
		pins, expected = held.pins, held.observation
	}
	s.mu.Unlock()
	if pins == nil {
		return ErrUnsafe
	}
	actual, err := (RuntimeObserver{Client: s.client}).Observe(ctx, *pins)
	if err != nil || actual.Process != expected.Process || actual.ContainerID != expected.ContainerID || actual.PIDNamespace != expected.PIDNamespace || actual.MountNamespace != expected.MountNamespace || int(process.Pid()) != expected.Process.PID {
		return errors.Join(ErrUnsafe, err)
	}
	wait, err := process.Wait(ctx)
	if err != nil {
		return err
	}
	if err := process.Kill(ctx, syscall.SIGKILL, containerd.WithKillAll); err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case exit := <-wait:
		_, _, err := exit.Result()
		return err
	}
}

func (s *WorkerSession) CheckHeld(ctx context.Context, task *api.Task) error {
	if s == nil || ctx == nil || task == nil {
		return ErrUnsafe
	}
	held, ok := ctx.Value(workerHeldKey{}).(*workerHeld)
	hash, err := TaskSHA256(task)
	if !ok || err != nil || !held.active.Load() || held.session != s || held.hash != hash {
		return ErrUnsafe
	}
	s.mu.Lock()
	current := s.tasks[hash]
	if current == nil {
		s.mu.Unlock()
		return ErrUnsafe
	}
	grant := current.grant
	s.mu.Unlock()
	if held.admission != grant.AdmissionSHA256() {
		return ErrUnsafe
	}
	return s.VerifyCurrent(ctx, task, grant)
}

func (s *WorkerSession) ownsSource(source *Source) bool {
	if s == nil || source == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.source == source
}
