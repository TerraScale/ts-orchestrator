package host

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ManagerRuntimeRenewalHandoff excludes session-changing RPCs only while ROOT
// independently checks, signs and installs one successor. It grants no authority.
type ManagerRuntimeRenewalHandoff struct {
	mu         sync.Mutex
	proof      *ManagerRuntimeRenewal
	ctx        context.Context
	cancel     context.CancelFunc
	stopWork   func() bool
	stopClose  func() bool
	closed     bool
	dispatched bool
}

func (h *ManagerRuntimeRenewalHandoff) Proof() *ManagerRuntimeRenewal {
	if h == nil {
		return nil
	}
	return h.proof
}

func (h *ManagerRuntimeRenewalHandoff) Context() context.Context {
	if h == nil {
		return nil
	}
	return h.ctx
}

// BeginManagerRuntimeRenewal never queues an exclusive request-gate waiter:
// slow ordinary RPCs must remain concurrent with the actual renewal watchdog.
func (r *Reader) BeginManagerRuntimeRenewal(ctx context.Context, actualAgent *Agent, exactPredecessor SignedManagerRuntimeBinding) (*ManagerRuntimeRenewalHandoff, error) {
	if ctx == nil || ctx.Err() != nil || actualAgent == nil || r == nil || r.controller == nil {
		return nil, errManagerRuntimeSessionUnavailable
	}
	_, originalDeadline, err := actualAgent.executionLease()
	if err != nil {
		return nil, err
	}
	actualAgent.mu.RLock()
	originalEvent := actualAgent.managerRenewal
	actualAgent.mu.RUnlock()
	if originalEvent == nil || originalEvent.work == nil || originalEvent.work.Err() != nil {
		return nil, errors.New("actual Agent maintenance context is unavailable")
	}
	acquire, cancelAcquire := context.WithDeadline(ctx, originalDeadline)
	stopWork := context.AfterFunc(originalEvent.work, cancelAcquire)
	defer cancelAcquire()
	defer stopWork()
	for {
		if acquire.Err() != nil || actualAgent.sessionLost.Load() {
			return nil, errors.New("original manager handoff acquisition expired or cancelled")
		}
		if actualAgent.sessionRenewMu.TryLock() {
			if actualAgent.sessionRequestMu.TryLock() {
				break
			}
			actualAgent.sessionRenewMu.Unlock()
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-acquire.Done():
			timer.Stop()
			return nil, acquire.Err()
		case <-timer.C:
		}
	}
	owned := true
	defer func() {
		if owned {
			actualAgent.sessionRequestMu.Unlock()
			actualAgent.sessionRenewMu.Unlock()
		}
	}()
	current, _, err := actualAgent.executionLease()
	if err != nil {
		return nil, err
	}
	if acquire.Err() != nil || originalEvent.work.Err() != nil || !sameManagerCarrier(current.ManagerRuntimeBinding, &exactPredecessor) {
		return nil, errors.New("original manager predecessor changed while acquiring handoff")
	}
	if err := actualAgent.renewSessionLocked(acquire, originalEvent.work); err != nil {
		return nil, err
	}
	proof, err := r.AdmitManagerRuntimeRenewal(ctx, actualAgent, exactPredecessor)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithDeadline(ctx, proof.ExpiresAt())
	h := &ManagerRuntimeRenewalHandoff{proof: proof, ctx: bounded, cancel: cancel}
	h.mu.Lock()
	h.stopWork = context.AfterFunc(proof.event.work, cancel)
	// Publish ownership before installing cancellation cleanup. Cleanup can run
	// immediately, but cannot release either gate while Install owns h.mu.
	owned = false
	h.stopClose = context.AfterFunc(bounded, h.Close)
	h.mu.Unlock()
	if bounded.Err() != nil {
		h.Close()
		return nil, bounded.Err()
	}
	return h, nil
}

// Close consumes the handoff before releasing either gate. A synchronous
// installation owns h.mu until bounded transport/readback has finished.
func (h *ManagerRuntimeRenewalHandoff) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closeLocked()
}

func (h *ManagerRuntimeRenewalHandoff) closeLocked() {
	if h.closed || h.proof == nil {
		return
	}
	h.closed = true
	h.cancel()
	if h.stopWork != nil {
		h.stopWork()
	}
	if h.stopClose != nil {
		h.stopClose()
	}
	h.proof.agent.sessionRequestMu.Unlock()
	h.proof.agent.sessionRenewMu.Unlock()
}

// Install dispatches at most once, then checks the exact independently read
// successor. A failed or ambiguous attempt is terminal and never retransmitted.
func (h *ManagerRuntimeRenewalHandoff) Install(ctx context.Context, signed SignedManagerRuntimeBinding) (*ManagerRuntimeSession, error) {
	if h == nil {
		return nil, errManagerRuntimeSessionUnavailable
	}
	h.mu.Lock()
	defer func() { h.closeLocked(); h.mu.Unlock() }()
	if h.closed || h.dispatched || h.proof == nil || h.ctx == nil || h.ctx.Err() != nil || ctx == nil || ctx.Err() != nil {
		return nil, errors.New("manager renewal handoff is terminal or cancelled")
	}
	p, a := h.proof, h.proof.agent
	bounded, cancel := context.WithDeadline(ctx, p.ExpiresAt())
	stop := context.AfterFunc(h.ctx, cancel)
	defer cancel()
	defer stop()
	if err := signed.Binding.Validate(); err != nil {
		return nil, err
	}
	if signed.Binding.SourceRevision != p.SourceRevision() || signed.Binding.ExpiresAt.After(p.ExpiresAt()) ||
		signed.Binding.IssuedAt.Before(p.event.request.IssuedAt) || sameManagerCarrier(&signed, p.event.current.ManagerRuntimeBinding) {
		return nil, errors.New("successor differs from the exact independently admitted renewal source")
	}
	if err := p.Revalidate(bounded); err != nil {
		return nil, err
	}
	registration, registrationRevision, current, revision, err := p.reader.managerRuntimeSession(bounded, p.registration.Node)
	if err != nil {
		return nil, err
	}
	if registrationRevision != p.registrationRevision || !sameJSON(registration, p.registration) || revision != p.revision || !sameJSON(current, p.event.current) {
		return nil, errors.New("exact renewal source changed before successor dispatch")
	}
	a.mu.RLock()
	live := a.managerRenewal == p.event && sameJSON(a.session, p.event.current) && !a.sessionSafeUntil.Before(p.ExpiresAt()) &&
		!a.sessionLost.Load() && bounded.Err() == nil && h.ctx.Err() == nil && p.original.Err() == nil && p.event.work.Err() == nil && time.Now().Before(p.ExpiresAt())
	a.mu.RUnlock()
	if !live {
		return nil, errManagerRuntimeSessionUnavailable
	}
	h.dispatched = true
	if err := a.setManagerRuntimeBindingLocked(bounded, signed, &managerRuntimeInstallSeal{proof: p, caller: ctx, handoff: h.ctx}); err != nil {
		return nil, err
	}
	published, err := p.reader.ReadManagerRuntimeSession(bounded, p.registration.Node)
	if err != nil {
		return nil, err
	}
	actual, found := published.SignedBinding()
	if !found || !sameManagerCarrier(&actual, &signed) || published.registrationRevision != p.registrationRevision || !sameJSON(published.registration, p.registration) ||
		published.current.SessionID != p.event.current.SessionID || published.current.Epoch != p.event.current.Epoch ||
		published.current.RegistrationGeneration != p.event.current.RegistrationGeneration || published.revision <= p.revision ||
		published.current.ExpiresAt.Before(p.event.current.ExpiresAt) {
		return nil, errors.New("manager renewal successor differs from exact committed readback")
	}
	a.mu.RLock()
	live = sameJSON(a.session, published.current) && !a.sessionLost.Load() && bounded.Err() == nil && h.ctx.Err() == nil &&
		p.original.Err() == nil && p.event.work.Err() == nil && time.Now().Before(p.ExpiresAt()) && time.Now().Before(signed.Binding.ExpiresAt)
	a.mu.RUnlock()
	if !live {
		return nil, errors.New("manager renewal completed after original cancellation or source expiry")
	}
	deadline := p.ExpiresAt()
	if signed.Binding.ExpiresAt.Before(deadline) {
		deadline = signed.Binding.ExpiresAt
	}
	if original, ok := p.original.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	// This is a new readback observation under the original caller, not the
	// short transport context canceled when the synchronous handoff closes.
	return &ManagerRuntimeSession{reader: p.reader, original: p.original, work: p.event.work, registration: published.registration,
		registrationRevision: published.registrationRevision, current: published.current, revision: published.revision, deadline: deadline}, nil
}

// A synchronous acceptance seal reads original sources directly under Agent.mu;
// asynchronous context cancellation delivery cannot authorize a late mutation.
type managerRuntimeInstallSeal struct {
	proof           *ManagerRuntimeRenewal
	caller, handoff context.Context
}

func (s *managerRuntimeInstallSeal) validLocked(a *Agent, next session) bool {
	p := s.proof
	if p == nil || p.agent != a || p.event == nil || p.original == nil || p.event.work == nil ||
		s.caller == nil || s.handoff == nil || s.caller.Err() != nil || s.handoff.Err() != nil ||
		p.original.Err() != nil || p.event.work.Err() != nil || a.sessionLost.Load() || !time.Now().Before(p.ExpiresAt()) ||
		a.managerRenewal != p.event || !sameJSON(a.session, p.event.current) || a.sessionSafeUntil.Before(p.ExpiresAt()) {
		return false
	}
	b := next.ManagerRuntimeBinding
	return b != nil && b.Binding.SourceRevision == p.revision && !b.Binding.ExpiresAt.After(p.ExpiresAt()) && time.Now().Before(b.Binding.ExpiresAt) &&
		next.SessionID == p.event.current.SessionID && next.Epoch == p.event.current.Epoch && next.RegistrationGeneration == p.registration.Generation &&
		b.Binding.RegistrationRevision == p.registrationRevision
}
