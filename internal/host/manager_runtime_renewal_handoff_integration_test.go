//go:build linux

package host

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go/jetstream"
)

func managerHandoffSuccessor(t *testing.T, h *ManagerRuntimeRenewalHandoff, key *ecdsa.PrivateKey) SignedManagerRuntimeBinding {
	t.Helper()
	p := h.Proof()
	signed := p.event.current.ManagerRuntimeBinding.Clone()
	signed.Binding.SourceRevision = p.SourceRevision()
	signed.Binding.IssuedAt = time.Now().UTC()
	signed.Binding.ExpiresAt = p.ExpiresAt()
	signManagerBindingFixture(t, &signed, key)
	return signed
}

func managerHandoffDesired(ctx context.Context, a *Agent) error {
	var reply desiredReply
	return a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{"terrabase"}, &reply)
}

func TestManagerRuntimeRenewalHandoffSerializesAuthorizeCASAndOneInstall(t *testing.T) {
	r, a, predecessor, stopWork, nativeKey := managerRenewalTransport(t)
	old := awaitManagerRenewal(t, r, a, predecessor, 0)
	h, err := r.BeginManagerRuntimeRenewal(t.Context(), a, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	proof := h.Proof()
	originalDeadline, originalDigest := proof.ExpiresAt(), proof.Digest()
	queued := make(chan error, 1)
	go func() { queued <- managerHandoffDesired(t.Context(), a) }()
	// Root checks/signing may span ordinary maintenance ticks. A concurrent
	// real authorized request must not rewrite its exact predecessor revision.
	select {
	case err := <-queued:
		t.Fatalf("authorized RPC escaped the handoff before publication: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	current, revision, _, err := r.controller.sessionSnapshot(t.Context(), sessionKey(a.cfg.Cell, a.cfg.Node))
	if err != nil || revision != proof.SourceRevision() || !sameManagerCarrier(current.ManagerRuntimeBinding, &predecessor) {
		t.Fatalf("actual CAS source changed during independent handoff: %v", err)
	}
	if err := proof.Revalidate(h.Context()); err != nil {
		t.Fatal(err)
	}
	successor := managerHandoffSuccessor(t, h, nativeKey)
	published, err := h.Install(h.Context(), successor)
	if err != nil {
		t.Fatal(err)
	}
	if published.SourceRevision() <= proof.SourceRevision() || successor.Binding.SourceRevision != proof.SourceRevision() ||
		!proof.ExpiresAt().Equal(originalDeadline) || proof.Digest() != originalDigest {
		t.Fatal("installation changed the original authenticated source or adopted an incidental revision")
	}
	select {
	case err := <-queued:
		if err != nil {
			t.Fatal("queued actual authorize CAS did not resume after handoff:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued actual authorize CAS did not resume")
	}
	if err := old.Revalidate(t.Context()); err == nil {
		t.Fatal("old binding proof followed the successor")
	}
	if err := proof.Revalidate(t.Context()); err == nil {
		t.Fatal("renewal proof followed its changed carrier")
	}
	a.sessionRenewMu.Lock()
	_, before, _, err := r.controller.sessionSnapshot(t.Context(), sessionKey(a.cfg.Cell, a.cfg.Node))
	if err != nil {
		a.sessionRenewMu.Unlock()
		t.Fatal(err)
	}
	_, second := h.Install(t.Context(), successor)
	actual, after, _, readErr := r.controller.sessionSnapshot(t.Context(), sessionKey(a.cfg.Cell, a.cfg.Node))
	a.sessionRenewMu.Unlock()
	if second == nil || readErr != nil || before != after || !sameManagerCarrier(actual.ManagerRuntimeBinding, &successor) {
		t.Fatal("terminal installation dispatched again or changed the committed carrier")
	}
	if err := published.Revalidate(t.Context()); err != nil {
		t.Fatal("independently read successor did not survive ordinary authorize CAS:", err)
	}
	awaitManagerRenewal(t, r, a, successor, published.SourceRevision())
	stopWork()
	if published.Revalidate(context.Background()) == nil {
		t.Fatal("new readback ignored its original actual Agent work cancellation")
	}
}

type delayedManagerDesiredRead struct {
	authority.HostMutationStore
	once             sync.Once
	started, release chan struct{}
}

func (d *delayedManagerDesiredRead) ReadHostMutation(ctx context.Context, kind authority.HostMutationKind, subject string) (authority.LogEntry, error) {
	if kind == authority.MutationDesired {
		d.once.Do(func() {
			close(d.started)
			select {
			case <-d.release:
			case <-ctx.Done():
			}
		})
	}
	return d.HostMutationStore.ReadHostMutation(ctx, kind, subject)
}

func TestManagerRuntimeRenewalBusyOrdinaryRPCDoesNotStarveMaintenance(t *testing.T) {
	delay := &delayedManagerDesiredRead{started: make(chan struct{}), release: make(chan struct{})}
	r, a, predecessor, _, _ := managerRenewalTransport(t, func(c *Controller) {
		delay.HostMutationStore = c.mutations
		c.mutations = delay
	})
	old := awaitManagerRenewal(t, r, a, predecessor, 0)
	requestCtx, cancelRequest := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelRequest()
	done := make(chan error, 1)
	go func() { done <- managerHandoffDesired(requestCtx, a) }()
	select {
	case <-delay.started:
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary actual authorized RPC did not reach delayed durable read")
	}
	acquisition, cancel := context.WithTimeout(t.Context(), 2200*time.Millisecond)
	defer cancel()
	beginDone := make(chan error, 1)
	go func() {
		h, err := r.BeginManagerRuntimeRenewal(acquisition, a, predecessor)
		if h != nil {
			h.Close()
		}
		beginDone <- err
	}()
	fresh := awaitManagerRenewal(t, r, a, predecessor, old.SourceRevision()+1)
	select {
	case err := <-beginDone:
		t.Fatalf("busy gate ended before genuine maintenance advanced: %v", err)
	default:
	}
	if !fresh.ExpiresAt().After(old.ExpiresAt()) || !old.ExpiresAt().Equal(old.event.deadline) {
		t.Fatal("ordinary RPC blocked actual renewal or extended the old proof")
	}
	select {
	case err := <-beginDone:
		if err == nil {
			t.Fatal("busy gate was admitted while an ordinary RPC remained in flight")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("busy handoff ignored original acquisition deadline")
	}
	close(delay.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("long ordinary RPC did not complete:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ordinary RPC remained blocked")
	}
	if err := old.Revalidate(t.Context()); err != nil {
		t.Fatal("bounded busy refusal replaced the existing binding:", err)
	}
}

func TestManagerRuntimeRenewalHandoffCancellationRejectsLateInstall(t *testing.T) {
	for _, termination := range []string{"cancel", "deadline", "close", "work"} {
		t.Run(termination, func(t *testing.T) {
			r, a, predecessor, stopWork, nativeKey := managerRenewalTransport(t)
			awaitManagerRenewal(t, r, a, predecessor, 0)
			original, cancel := context.WithCancel(t.Context())
			if termination == "deadline" {
				cancel()
				original, cancel = context.WithTimeout(t.Context(), 200*time.Millisecond)
			}
			defer cancel()
			h, err := r.BeginManagerRuntimeRenewal(original, a, predecessor)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			signed := managerHandoffSuccessor(t, h, nativeKey)
			switch termination {
			case "close":
				h.Close()
			case "work":
				stopWork()
			case "deadline":
				<-original.Done()
			default:
				cancel()
			}
			h.Close()
			if _, err := h.Install(context.Background(), signed); err == nil {
				t.Fatal("late installation escaped terminal ownership or original cancellation")
			}
			current, _, _, err := r.controller.sessionSnapshot(t.Context(), sessionKey(a.cfg.Cell, a.cfg.Node))
			if err != nil || !sameManagerCarrier(current.ManagerRuntimeBinding, &predecessor) {
				t.Fatalf("late installation changed the existing binding: %v", err)
			}
		})
	}
}

// Delay the real committed write's return, rather than fabricating a receipt.
type delayedManagerSessionWrite struct {
	jetstream.KeyValue
	armed              atomic.Bool
	committed, release chan struct{}
}

func (d *delayedManagerSessionWrite) Update(ctx context.Context, key string, value []byte, expected uint64) (uint64, error) {
	revision, err := d.KeyValue.Update(ctx, key, value, expected)
	if err == nil && key == sessionKey("gru", "node-a") && d.armed.CompareAndSwap(true, false) {
		close(d.committed)
		select {
		case <-d.release:
		case <-ctx.Done():
		}
	}
	return revision, err
}

func TestManagerRuntimeRenewalCancelledInflightInstallCannotAcceptLateResponse(t *testing.T) {
	for _, termination := range []string{"caller", "work"} {
		t.Run(termination, func(t *testing.T) {
			delay := &delayedManagerSessionWrite{committed: make(chan struct{}), release: make(chan struct{})}
			r, a, predecessor, stopWork, nativeKey := managerRenewalTransport(t, func(c *Controller) {
				delay.KeyValue = c.state
				c.state = delay
			})
			awaitManagerRenewal(t, r, a, predecessor, 0)
			h, err := r.BeginManagerRuntimeRenewal(t.Context(), a, predecessor)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			successor := managerHandoffSuccessor(t, h, nativeKey)
			delay.armed.Store(true)
			install, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := h.Install(install, successor); done <- err }()
			select {
			case <-delay.committed:
			case <-time.After(5 * time.Second):
				t.Fatal("installation did not reach the real durable commit")
			}
			workStopped := make(chan struct{})
			if termination == "work" {
				go func() { stopWork(); close(workStopped) }()
			} else {
				cancel()
				close(workStopped)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled in-flight install published a successful observation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled install ignored bounded transport cancellation")
			}
			select {
			case <-workStopped:
			case <-time.After(5 * time.Second):
				t.Fatal("actual cancelled work did not join")
			}
			// An ambiguous durable effect is real; it cannot be turned into a locally
			// accepted session by a late reply or a repeated installation attempt.
			a.sessionRenewMu.Lock()
			defer a.sessionRenewMu.Unlock()
			close(delay.release)
			if _, err := h.Install(context.Background(), successor); err == nil {
				t.Fatal("ambiguous cancelled install dispatched again")
			}
			a.mu.RLock()
			accepted := cloneManagerRuntimeSession(a.session)
			a.mu.RUnlock()
			if !sameManagerCarrier(accepted.ManagerRuntimeBinding, &predecessor) {
				t.Fatal("cancelled actual Agent accepted a late response")
			}
			current, _, _, err := r.controller.sessionSnapshot(t.Context(), sessionKey(a.cfg.Cell, a.cfg.Node))
			if err != nil || !sameManagerCarrier(current.ManagerRuntimeBinding, &successor) {
				t.Fatalf("fixture did not retain the genuine ambiguous durable effect: %v", err)
			}
			if termination == "work" {
				// Keep transport/caller contexts live to prove the local acceptance
				// seal reads actual work directly, without cancellation callbacks.
				seal := &managerRuntimeInstallSeal{proof: h.Proof(), caller: t.Context(), handoff: t.Context()}
				if err := a.acceptSessionContext(t.Context(), current, nil, seal); err == nil {
					t.Fatal("local acceptance ignored original work while transport context remained live")
				}
			}
		})
	}
}
