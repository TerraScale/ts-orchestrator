package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Only an actual maintenance exchange can create an event; installation and
// acquisition clear it. Retained events are never changed by later renewals.
type managerRuntimeRenewalEvent struct {
	work              context.Context
	previous, current session
	request, response protocol.Envelope
	deadline          time.Time
}

func cloneManagerRuntimeSession(s session) session {
	if s.ManagerRuntimeBinding != nil {
		s.ManagerRuntimeBinding = new(s.ManagerRuntimeBinding.Clone())
	}
	return s
}

func newManagerRuntimeRenewalEvent(work context.Context, previous, current session, req, reply protocol.Envelope) *managerRuntimeRenewalEvent {
	req.Payload = req.Payload.Clone()
	reply.Payload = reply.Payload.Clone()
	return &managerRuntimeRenewalEvent{work: work, previous: cloneManagerRuntimeSession(previous), current: cloneManagerRuntimeSession(current), request: req, response: reply}
}

// ManagerRuntimeRenewal proves one independently admitted host renewal only.
// Native identity, process, runtime and regional role still require admission.
type ManagerRuntimeRenewal struct {
	reader               *Reader
	agent                *Agent
	original             context.Context
	event                *managerRuntimeRenewalEvent
	registration         Registration
	registrationRevision uint64
	revision             uint64
	admittedAt           time.Time
	digest               string
}

func (p *ManagerRuntimeRenewal) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

func (p *ManagerRuntimeRenewal) ExpiresAt() time.Time {
	if p == nil || p.event == nil {
		return time.Time{}
	}
	return p.event.deadline
}

func (p *ManagerRuntimeRenewal) SourceRevision() uint64 {
	if p == nil {
		return 0
	}
	return p.revision
}

// AdmitManagerRuntimeRenewal authenticates fresh wire and its exact committed
// revision before retaining an immutable source. It does not renew old calls.
func (r *Reader) AdmitManagerRuntimeRenewal(ctx context.Context, actualAgent *Agent, exactPredecessor SignedManagerRuntimeBinding) (*ManagerRuntimeRenewal, error) {
	if r == nil || r.controller == nil || r.controller.conn == nil || actualAgent == nil || ctx == nil || ctx.Err() != nil {
		return nil, errManagerRuntimeSessionUnavailable
	}
	actualAgent.mu.RLock()
	event := actualAgent.managerRenewal
	actualAgent.mu.RUnlock()
	if event == nil || event.work == nil || !sameManagerCarrier(event.previous.ManagerRuntimeBinding, &exactPredecessor) ||
		!sameManagerCarrier(event.current.ManagerRuntimeBinding, &exactPredecessor) {
		return nil, errors.New("no actual renewal of the exact manager predecessor")
	}
	p := &ManagerRuntimeRenewal{reader: r, agent: actualAgent, original: ctx, event: event}
	bounded, cancel, err := p.readContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	registration, registrationRevision, _, _, err := r.managerRuntimeSession(bounded, actualAgent.cfg.Node)
	if err != nil {
		return nil, err
	}
	p.registration, p.registrationRevision = registration, registrationRevision
	p.admittedAt = time.Now().UTC()
	result, err := p.verifyTranscript(p.admittedAt)
	if err != nil {
		return nil, err
	}
	p.revision = result.SessionRevision
	js, err := r.controller.conn.JetStream()
	if err != nil {
		return nil, err
	}
	msg, err := js.GetMsg("KV_"+stateBucket, p.revision, nats.Context(bounded))
	if err != nil {
		return nil, err
	}
	if msg == nil || msg.Sequence != p.revision || msg.Subject != "$KV."+stateBucket+"."+sessionKey(r.controller.cell, registration.Node) ||
		msg.Header.Get("KV-Operation") != "" || msg.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		len(msg.Data) > 64<<10 || !bytes.Equal(msg.Data, result.Payload) {
		return nil, errors.New("manager renewal differs from its exact committed session revision")
	}
	wire, err := json.Marshal(struct {
		Request, Response protocol.Envelope
		Previous          session
	}{event.request, event.response, event.previous}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("terrascale.manager-runtime-renewal.v1\x00"), wire...))
	p.digest = hex.EncodeToString(digest[:])
	if err := p.Revalidate(bounded); err != nil {
		return nil, err
	}
	// Historical authentication is available only after fresh first admission.
	if _, err := p.verifyTranscript(time.Now().UTC()); err != nil {
		return nil, err
	}
	if bounded.Err() != nil {
		return nil, bounded.Err()
	}
	return p, nil
}

func (p *ManagerRuntimeRenewal) readContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if p == nil || p.reader == nil || p.agent == nil || p.original == nil || p.event == nil || p.event.work == nil ||
		ctx == nil || ctx.Err() != nil || p.original.Err() != nil || p.event.work.Err() != nil || !time.Now().Before(p.event.deadline) {
		return nil, nil, errors.New("original manager renewal source expired or cancelled")
	}
	bounded, cancel := context.WithDeadline(ctx, p.event.deadline)
	stopOriginal := context.AfterFunc(p.original, cancel)
	stopWork := context.AfterFunc(p.event.work, cancel)
	return bounded, func() { stopOriginal(); stopWork(); cancel() }, nil
}

func (p *ManagerRuntimeRenewal) verifyTranscript(at time.Time) (response, error) {
	fail := func() (response, error) { return response{}, errors.New("manager renewal transcript binding mismatch") }
	e := p.event
	var req request
	if err := protocol.DecodeStrict(e.request.Payload, &req, 64<<10); err != nil {
		return response{}, err
	}
	req.Envelope = e.request
	registration, b := p.registration, e.previous.ManagerRuntimeBinding
	if b == nil || b.Binding.Validate() != nil || req.Operation != "session" || req.Node != registration.Node ||
		req.NATSUserPublicKey != registration.NATSUserPublicKey || req.SessionID != e.previous.SessionID || req.Epoch != e.previous.Epoch ||
		!req.IssuedAt.After(e.previous.LastIssuedAt) || !req.IssuedAt.Before(e.previous.ExpiresAt) {
		return fail()
	}
	key, err := decodePublicKey(registration.PublicKey)
	if err != nil {
		return response{}, err
	}
	if err := verifyRequest(req, key, p.reader.controller.cell, at); err != nil {
		return response{}, err
	}
	var operation sessionOperation
	if err := decodeStrict(req.Payload, &operation); err != nil {
		return response{}, err
	}
	if operation.Kind != "renew" || !sameManagerCarrier(operation.ManagerRuntimeBinding, b) {
		return fail()
	}
	if err := protocol.VerifyEnvelope(e.response, protocol.EnvelopeScope{Region: p.reader.controller.cell, Kind: "host.response.session", Actor: "controller", OperationID: entityid.Derive("host-request", req.Nonce), Epoch: req.Epoch}, p.agent.cfg.ControllerPublicKey, at, protocol.VerifyPolicy{MaxLifetime: requestTTL, ClockSkew: maxClockSkew}); err != nil {
		return response{}, err
	}
	var result response
	if err := decodeStrict(e.response.Payload, &result); err != nil {
		return response{}, err
	}
	if result.Error != "" || result.Retryable || result.SessionRevision == 0 || result.SessionRevision <= b.Binding.SourceRevision ||
		result.Nonce != req.Nonce || result.Node != req.Node || result.SessionID != req.SessionID || result.Epoch != req.Epoch || result.Operation != req.Operation ||
		e.response.IssuedAt.Before(req.IssuedAt.Add(-maxClockSkew)) {
		return fail()
	}
	var accepted session
	if err := decodeStrict(result.Payload, &accepted); err != nil {
		return response{}, err
	}
	if !sameJSON(accepted, e.current) || accepted.SessionID != req.SessionID || accepted.Epoch != req.Epoch ||
		accepted.RegistrationGeneration != registration.Generation || e.previous.RegistrationGeneration != registration.Generation ||
		accepted.LastNonce != req.Nonce || !accepted.LastIssuedAt.Equal(req.IssuedAt) || accepted.LastPayloadSHA256 != sessionPayloadSHA256(req) ||
		!accepted.ExpiresAt.Equal(req.IssuedAt.Add(sessionTTL)) || !accepted.ExpiresAt.After(e.previous.ExpiresAt) ||
		!sameManagerCarrier(accepted.ManagerRuntimeBinding, b) || e.deadline.IsZero() || e.deadline.After(accepted.ExpiresAt) {
		return fail()
	}
	binding, a := b.Binding, p.agent
	if p.reader.controller.cell != registration.Cell || a.cfg.Cell != registration.Cell || a.cfg.Environment != registration.Environment ||
		a.cfg.Node != registration.Node || a.cfg.NATSUserPublicKey != registration.NATSUserPublicKey || len(a.cfg.Identity) != ed25519.PrivateKeySize ||
		base64.StdEncoding.EncodeToString(a.cfg.Identity.Public().(ed25519.PublicKey)) != registration.PublicKey ||
		a.processID != req.SessionID || binding.Cell != registration.Cell || binding.Environment != registration.Environment ||
		binding.HostID != registration.ID || binding.HostNode != registration.Node || binding.HostPublicKey != registration.PublicKey ||
		binding.NATSUserPublicKey != registration.NATSUserPublicKey || binding.HostSessionID != req.SessionID || binding.HostSessionEpoch != req.Epoch ||
		binding.RegistrationGeneration != registration.Generation || binding.RegistrationRevision != p.registrationRevision {
		return fail()
	}
	return result, nil
}

// Revalidate may authenticate retained wire at its private first admission time.
// Later outer renewals establish currentness, never a later source deadline.
func (p *ManagerRuntimeRenewal) Revalidate(ctx context.Context) error {
	bounded, cancel, err := p.readContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if p.digest == "" || p.revision == 0 || p.admittedAt.IsZero() {
		return errors.New("manager renewal was not independently admitted")
	}
	result, err := p.verifyTranscript(p.admittedAt)
	if err != nil {
		return err
	}
	if result.SessionRevision != p.revision || p.agent.sessionLost.Load() {
		return errManagerRuntimeSessionUnavailable
	}
	registration, registrationRevision, current, revision, err := p.reader.managerRuntimeSession(bounded, p.registration.Node)
	if err != nil {
		return err
	}
	accepted, deadline, err := p.agent.executionLease()
	if err != nil {
		return err
	}
	original := p.event.current
	if registrationRevision != p.registrationRevision || !sameJSON(registration, p.registration) || revision < p.revision ||
		current.SessionID != original.SessionID || current.Epoch != original.Epoch || current.RegistrationGeneration != original.RegistrationGeneration ||
		accepted.SessionID != original.SessionID || accepted.Epoch != original.Epoch || accepted.RegistrationGeneration != original.RegistrationGeneration ||
		current.ExpiresAt.Before(original.ExpiresAt) || accepted.ExpiresAt.Before(original.ExpiresAt) || deadline.Before(p.event.deadline) ||
		!sameManagerCarrier(current.ManagerRuntimeBinding, original.ManagerRuntimeBinding) || !sameManagerCarrier(accepted.ManagerRuntimeBinding, original.ManagerRuntimeBinding) ||
		bounded.Err() != nil || p.original.Err() != nil || p.event.work.Err() != nil || p.agent.sessionLost.Load() || !time.Now().Before(p.event.deadline) {
		return errors.New("original manager renewal source or exact predecessor changed")
	}
	return nil
}
