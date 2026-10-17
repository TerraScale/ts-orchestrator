package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

var errManagerRuntimeSessionUnavailable = errors.New("manager runtime host session is absent or inactive")

func sameManagerCarrier(left, right *SignedManagerRuntimeBinding) bool {
	return sameJSON(left, right)
}

// SetManagerRuntimeBinding installs inert bytes on this actual Agent. Native
// manager authority is verified independently by the eventual consumer.
func (a *Agent) SetManagerRuntimeBinding(ctx context.Context, signed SignedManagerRuntimeBinding) error {
	if a == nil || ctx == nil || ctx.Err() != nil || a.sessionLost.Load() {
		return errors.New("manager runtime host session unavailable")
	}
	if err := signed.Binding.Validate(); err != nil {
		return err
	}
	a.sessionRenewMu.Lock()
	defer a.sessionRenewMu.Unlock()
	s, deadline, err := a.executionLease()
	if err != nil {
		return err
	}
	b := signed.Binding
	if b.Cell != a.cfg.Cell || b.Environment != a.cfg.Environment || b.HostNode != a.cfg.Node ||
		b.HostPublicKey != base64.StdEncoding.EncodeToString(a.cfg.Identity.Public().(ed25519.PublicKey)) ||
		b.NATSUserPublicKey != a.cfg.NATSUserPublicKey || b.HostSessionID != a.processID || b.HostSessionID != s.SessionID ||
		b.HostSessionEpoch != s.Epoch || b.RegistrationGeneration != s.RegistrationGeneration ||
		!time.Now().Before(b.ExpiresAt) || b.IssuedAt.After(time.Now()) {
		return errors.New("manager runtime binding differs from actual Agent session")
	}
	if old := s.ManagerRuntimeBinding; old != nil {
		if sameManagerCarrier(old, &signed) {
			return nil
		}
		if b.SourceRevision <= old.Binding.SourceRevision {
			return errors.New("manager runtime observation did not advance")
		}
	}
	if b.ExpiresAt.Before(deadline) {
		deadline = b.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	copy := signed.Clone()
	var next session
	if _, err := a.sendToLeader(ctx, "session", sessionOperation{Kind: "renew", ManagerRuntimeBinding: &copy}, &next, nil, nil); err != nil {
		return err
	}
	if next.SessionID != s.SessionID || next.Epoch != s.Epoch || !sameManagerCarrier(next.ManagerRuntimeBinding, &copy) ||
		!next.ExpiresAt.After(s.ExpiresAt) || ctx.Err() != nil || !time.Now().Before(deadline) {
		return errors.New("manager runtime carrier installation changed session")
	}
	if _, _, err := a.executionLease(); err != nil {
		return err
	}
	return a.acceptSession(next)
}

func applyManagerRuntimeCarrier(next *session, old session, registration Registration, req request, operation sessionOperation, revision, registrationRevision uint64, now time.Time) error {
	signed := operation.ManagerRuntimeBinding
	if signed == nil {
		return nil
	}
	if operation.Kind != "renew" {
		return errors.New("manager runtime binding requires an existing session")
	}
	if sameManagerCarrier(old.ManagerRuntimeBinding, signed) {
		return nil
	}
	b := signed.Binding
	if err := b.Validate(); err != nil {
		return err
	}
	if b.Cell != registration.Cell || b.Environment != registration.Environment || b.HostID != registration.ID || b.HostNode != registration.Node ||
		b.HostPublicKey != registration.PublicKey || b.NATSUserPublicKey != registration.NATSUserPublicKey ||
		b.RegistrationRevision != registrationRevision || b.RegistrationGeneration != registration.Generation || b.HostSessionID != req.SessionID || b.HostSessionEpoch != req.Epoch ||
		b.SourceRevision != revision || b.IssuedAt.After(now) || !now.Before(b.ExpiresAt) || b.ExpiresAt.After(old.ExpiresAt) {
		return errors.New("manager runtime carrier differs from original current host session")
	}
	if prior := old.ManagerRuntimeBinding; prior != nil && b.SourceRevision <= prior.Binding.SourceRevision {
		return errors.New("manager runtime carrier source did not advance")
	}
	copy := signed.Clone()
	next.ManagerRuntimeBinding = &copy
	return nil
}

// ManagerRuntimeSession observes host metadata only; its carrier cannot grant
// native manager or process authority without independent signature verification.
type ManagerRuntimeSession struct {
	reader               *Reader
	original             context.Context
	registration         Registration
	registrationRevision uint64
	current              session
	revision             uint64
	deadline             time.Time
}

func (s *ManagerRuntimeSession) Registration() Registration {
	wire, _ := protocol.EncodeJSON(s.registration)
	var copy Registration
	_ = protocol.DecodeStrict(wire, &copy, 64<<10)
	return copy
}
func (s *ManagerRuntimeSession) SessionID() string            { return s.current.SessionID }
func (s *ManagerRuntimeSession) SessionEpoch() uint64         { return s.current.Epoch }
func (s *ManagerRuntimeSession) RegistrationRevision() uint64 { return s.registrationRevision }
func (s *ManagerRuntimeSession) SourceRevision() uint64       { return s.revision }
func (s *ManagerRuntimeSession) ExpiresAt() time.Time         { return s.deadline }
func (s *ManagerRuntimeSession) SignedBinding() (SignedManagerRuntimeBinding, bool) {
	if s.current.ManagerRuntimeBinding == nil {
		return SignedManagerRuntimeBinding{}, false
	}
	return s.current.ManagerRuntimeBinding.Clone(), true
}

// BindingSHA256 excludes the mutable outer renewal revision. The exact signed
// source revision and immutable expiry are already inside the signed envelope.
func (s *ManagerRuntimeSession) BindingSHA256() string {
	if s == nil || s.current.ManagerRuntimeBinding == nil {
		return ""
	}
	wire, err := json.Marshal(struct {
		Binding              *SignedManagerRuntimeBinding `json:"binding"`
		Registration         Registration                 `json:"registration"`
		RegistrationRevision uint64                       `json:"registration_revision"`
	}{s.current.ManagerRuntimeBinding, s.registration, s.registrationRevision}, json.Deterministic(true))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("terrascale.manager-runtime-carrier.v1\x00"), wire...))
	return hex.EncodeToString(digest[:])
}

func (r *Reader) ReadManagerRuntimeSession(ctx context.Context, node string) (*ManagerRuntimeSession, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.controller == nil {
		return nil, errors.New("manager runtime session source unavailable")
	}
	registration, registrationRevision, current, revision, err := r.managerRuntimeSession(ctx, node)
	if err != nil {
		return nil, err
	}
	deadline := current.ExpiresAt
	if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	s := &ManagerRuntimeSession{reader: r, original: ctx, registration: registration, registrationRevision: registrationRevision, current: current, revision: revision, deadline: deadline}
	if err := s.Revalidate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (r *Reader) managerRuntimeSession(ctx context.Context, node string) (Registration, uint64, session, uint64, error) {
	fail := func(err error) (Registration, uint64, session, uint64, error) {
		return Registration{}, 0, session{}, 0, err
	}
	c := r.controller
	registration, regRevision, exists, err := c.readRegistration(ctx, node)
	if err != nil {
		return fail(err)
	}
	if !exists || registration.ManagedOCI != nil || registration.ManagedMember != nil || registration.ManagedPlacement != nil {
		return fail(errManagerRuntimeSessionUnavailable)
	}
	retired, _, err := c.readRetirement(ctx, node)
	if err != nil {
		return fail(err)
	}
	if retired.Retired {
		return fail(errManagerRuntimeSessionUnavailable)
	}
	current, revision, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, node))
	if err != nil {
		return fail(err)
	}
	if !exists || current.SessionID == "" || current.Epoch == 0 || current.RegistrationGeneration != registration.Generation || !time.Now().Before(current.ExpiresAt) {
		return fail(errManagerRuntimeSessionUnavailable)
	}
	return registration, regRevision, current, revision, nil
}

func (s *ManagerRuntimeSession) Revalidate(ctx context.Context) error {
	if s == nil || s.reader == nil || s.original == nil || ctx == nil || ctx.Err() != nil || s.original.Err() != nil || !time.Now().Before(s.deadline) {
		return errors.New("original manager runtime session expired or cancelled")
	}
	ctx, cancel := context.WithDeadline(ctx, s.deadline)
	stop := context.AfterFunc(s.original, cancel)
	defer cancel()
	defer stop()
	registration, regRevision, current, revision, err := s.reader.managerRuntimeSession(ctx, s.registration.Node)
	if err != nil {
		return err
	}
	if regRevision != s.registrationRevision || !sameJSON(registration, s.registration) || revision < s.revision ||
		current.RegistrationGeneration != s.current.RegistrationGeneration || current.SessionID != s.current.SessionID || current.Epoch != s.current.Epoch ||
		!sameManagerCarrier(current.ManagerRuntimeBinding, s.current.ManagerRuntimeBinding) || !time.Now().Before(s.deadline) || s.original.Err() != nil {
		return errors.New("original manager runtime registration or session carrier changed")
	}
	return ctx.Err()
}

// FindManagerRuntimeSession searches the existing ordered inventory, never an
// additional origin index. A duplicate native identity is a refusal.
func (r *Reader) FindManagerRuntimeSession(ctx context.Context, nodeID string) (*ManagerRuntimeSession, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.controller == nil || !managerNativeID(nodeID) {
		return nil, errors.New("manager runtime native identity unavailable")
	}
	c := r.controller
	prefix := protocol.Control(c.cell, "host", "registration", c.cell) + "."
	info, err := c.controlLogSubjects(ctx, prefix+"*")
	if err != nil {
		return nil, err
	}
	var found *ManagerRuntimeSession
	for subject := range info.State.Subjects {
		node, ok := strings.CutPrefix(subject, prefix)
		if !ok {
			return nil, errors.New("manager runtime inventory malformed")
		}
		_, _, current, _, err := r.managerRuntimeSession(ctx, node)
		if errors.Is(err, errManagerRuntimeSessionUnavailable) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if current.ManagerRuntimeBinding == nil || current.ManagerRuntimeBinding.Binding.NodeID != nodeID {
			continue
		}
		if found != nil {
			return nil, errors.New("manager runtime native identity is ambiguous")
		}
		found, err = r.ReadManagerRuntimeSession(ctx, node)
		if err != nil {
			return nil, err
		}
	}
	if found == nil {
		return nil, errors.New("manager runtime native session not found")
	}
	if err := found.Revalidate(ctx); err != nil {
		return nil, err
	}
	return found, nil
}
