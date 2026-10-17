//go:build linux

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

// This exercises actual host signatures, transport, maintenance and durable CAS.
// Its inert carrier is not a positive native manager/process/root admission.
func managerRenewalTransport(t *testing.T) (*Reader, *Agent, SignedManagerRuntimeBinding, context.CancelFunc) {
	t.Helper()
	c, conn, _, _, controllerKey := testController(t)
	key := registerTestHost(t, c)
	controllerCtx, stopController := context.WithCancel(t.Context())
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- c.Run(controllerCtx) }()
	t.Cleanup(func() { stopController(); <-controllerDone })
	select {
	case <-c.Ready():
	case err := <-controllerDone:
		t.Fatalf("controller exited before subscriptions: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not subscribe")
	}
	a, err := NewAgent(AgentConfig{Cell: "gru", Node: "node-a", Environment: "production", Roles: []string{"terrabase"},
		NATSUserPublicKey: testNATSUserKey("node-a"), Conn: conn, Identity: key, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		ClockCheck: func() error { return nil }, WorkloadIdentity: testAgentIdentity(),
		Runner: &memoryRunner{observed: make(map[string]Observation)}, InstallRoot: testAgentInstallRoot(t), StateRoot: testAgentStateRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(t.Context(), ReaderConfig{Cell: c.cell, Conn: conn, State: c.state, StateReplicas: 1, HostMutations: c.mutations, ControlLog: c.controlLog})
	if err != nil {
		t.Fatal(err)
	}
	original, err := r.ReadManagerRuntimeSession(t.Context(), a.cfg.Node)
	if err != nil {
		t.Fatal(err)
	}
	signed, _, _, nativeKey := managerBindingFixture(t)
	registration := original.Registration()
	signed.Binding.HostID, signed.Binding.HostNode = registration.ID, registration.Node
	signed.Binding.HostPublicKey, signed.Binding.NATSUserPublicKey = registration.PublicKey, registration.NATSUserPublicKey
	signed.Binding.HostSessionID, signed.Binding.HostSessionEpoch = original.SessionID(), original.SessionEpoch()
	signed.Binding.RegistrationGeneration, signed.Binding.RegistrationRevision = registration.Generation, original.RegistrationRevision()
	signed.Binding.SourceRevision = original.SourceRevision()
	signManagerBindingFixture(t, &signed, nativeKey)
	if err := a.SetManagerRuntimeBinding(t.Context(), signed); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AdmitManagerRuntimeRenewal(t.Context(), a, signed); err == nil {
		t.Fatal("binding installation masqueraded as maintenance renewal")
	}
	work, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.maintainSessionLease(work, func(error) { cancel() })
	}()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return r, a, signed, stop
}

func awaitManagerRenewal(t *testing.T, r *Reader, a *Agent, predecessor SignedManagerRuntimeBinding, after uint64) *ManagerRuntimeRenewal {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		a.mu.RLock()
		event := a.managerRenewal
		a.mu.RUnlock()
		if event != nil {
			proof, err := r.AdmitManagerRuntimeRenewal(t.Context(), a, predecessor)
			if err == nil && proof.SourceRevision() > after {
				return proof
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("no independently admitted actual renewal before timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestManagerRuntimeRenewalTransportPinsReceiptAndFirstDeadline(t *testing.T) {
	r, a, predecessor, stop := managerRenewalTransport(t)
	held := awaitManagerRenewal(t, r, a, predecessor, 0)
	deadline, digest, revision := held.ExpiresAt(), held.Digest(), held.SourceRevision()
	if digest == "" || revision == 0 || !deadline.Equal(held.event.deadline) || !deadline.After(time.Now().Add(requestTTL)) {
		t.Fatal("proof lost its independently accepted execution source")
	}
	var result response
	if err := decodeStrict(held.event.response.Payload, &result); err != nil {
		t.Fatal(err)
	}
	js, err := a.cfg.Conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := js.GetMsg("KV_"+stateBucket, revision, nats.Context(t.Context()))
	if err != nil || msg == nil || !bytes.Equal(msg.Data, result.Payload) || result.SessionRevision != revision {
		t.Fatalf("signed receipt does not name exact committed bytes: %v", err)
	}
	// Transport freshness is shorter than the independently admitted source.
	timer := time.NewTimer(time.Until(held.event.request.ExpiresAt.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
	if _, err := held.verifyTranscript(time.Now().UTC()); err == nil {
		t.Fatal("expired wire remained fresh for a new admission")
	}
	if err := held.Revalidate(t.Context()); err != nil {
		t.Fatal("retained admitted source followed transport expiry instead of its original execution deadline:", err)
	}
	fresh := awaitManagerRenewal(t, r, a, predecessor, revision)
	if fresh.Digest() == digest || !fresh.ExpiresAt().After(deadline) || !held.ExpiresAt().Equal(deadline) || held.Digest() != digest || held.SourceRevision() != revision {
		t.Fatal("later actual renewal mutated the held original proof")
	}
	// Keep the actual last event long enough to reject first admission of
	// expired wire while an already admitted source remains valid.
	a.sessionRenewMu.Lock()
	a.mu.RLock()
	last := a.managerRenewal
	a.mu.RUnlock()
	select {
	case <-t.Context().Done():
		a.sessionRenewMu.Unlock()
		t.Fatal(t.Context().Err())
	case <-time.After(time.Until(last.request.ExpiresAt.Add(20 * time.Millisecond))):
	}
	_, expiredAdmission := r.AdmitManagerRuntimeRenewal(t.Context(), a, predecessor)
	retainedGuard := fresh.Revalidate(t.Context())
	a.sessionRenewMu.Unlock()
	if expiredAdmission == nil || retainedGuard != nil {
		t.Fatalf("expired initial wire and retained source were not distinguished: admission=%v guard=%v", expiredAdmission, retainedGuard)
	}
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-time.After(time.Until(deadline.Add(20 * time.Millisecond))):
	}
	if err := held.Revalidate(context.Background()); err == nil {
		t.Fatal("later renewal revived the original expired proof")
	}
	live := awaitManagerRenewal(t, r, a, predecessor, fresh.SourceRevision())
	if err := live.Revalidate(t.Context()); err != nil {
		t.Fatal("independently admitted new source did not remain available:", err)
	}
	stop()
	if err := live.Revalidate(context.Background()); err == nil {
		t.Fatal("Background replaced the original cancelled Agent work context")
	}
}

func TestManagerRuntimeRenewalRejectsChangedSourceAndOriginalCancellation(t *testing.T) {
	r, a, predecessor, _ := managerRenewalTransport(t)
	held := awaitManagerRenewal(t, r, a, predecessor, 0)
	operation, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	cancelled, err := r.AdmitManagerRuntimeRenewal(operation, a, predecessor)
	if err != nil {
		t.Fatal(err)
	}
	operationDeadline, _ := operation.Deadline()
	if !cancelled.ExpiresAt().After(operationDeadline) {
		cancel()
		t.Fatal("source expiry followed the shorter operation deadline")
	}
	cancel()
	if cancelled.Revalidate(context.Background()) == nil {
		t.Fatal("Background replaced original admission cancellation")
	}
	wrong := predecessor.Clone()
	wrong.Signature[0] ^= 1
	if _, err := r.AdmitManagerRuntimeRenewal(t.Context(), a, wrong); err == nil {
		t.Fatal("different exact predecessor was admitted")
	}
	if (&ManagerRuntimeRenewal{}).Revalidate(t.Context()) == nil {
		t.Fatal("zero proof was admitted")
	}
	// Hold maintenance while observing independently changed durable state.
	a.sessionRenewMu.Lock()
	defer a.sessionRenewMu.Unlock()
	c := r.controller
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, a.cfg.Node))
	if err != nil {
		t.Fatal(err)
	}
	shortened := cloneManagerRuntimeSession(current)
	shortened.ExpiresAt = held.event.current.ExpiresAt.Add(-time.Second)
	if _, err := c.cas(t.Context(), sessionKey(c.cell, a.cfg.Node), shortened, revision); err != nil {
		t.Fatal(err)
	}
	if held.Revalidate(t.Context()) == nil {
		t.Fatal("shortened current source survived independent guard")
	}
}

func TestManagerRuntimeRenewalRejectsReplacedCarrierAndRegistration(t *testing.T) {
	for _, change := range []string{"carrier", "registration"} {
		t.Run(change, func(t *testing.T) {
			r, a, predecessor, _ := managerRenewalTransport(t)
			held := awaitManagerRenewal(t, r, a, predecessor, 0)
			a.sessionRenewMu.Lock()
			defer a.sessionRenewMu.Unlock()
			c := r.controller
			if change == "registration" {
				registration := held.registration
				registration.Generation++
				if _, err := c.Register(t.Context(), registration); err != nil {
					t.Fatal(err)
				}
			} else {
				current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, a.cfg.Node))
				if err != nil {
					t.Fatal(err)
				}
				current = cloneManagerRuntimeSession(current)
				current.ManagerRuntimeBinding.Binding.RuntimeCandidateID = entityid.New()
				if _, err := c.cas(t.Context(), sessionKey(c.cell, a.cfg.Node), current, revision); err != nil {
					t.Fatal(err)
				}
			}
			if held.Revalidate(t.Context()) == nil {
				t.Fatalf("changed %s retained old proof", change)
			}
		})
	}
}

func TestManagerRuntimeRenewalRequiresExactReceiptAtFirstAdmission(t *testing.T) {
	r, a, predecessor, _ := managerRenewalTransport(t)
	held := awaitManagerRenewal(t, r, a, predecessor, 0)
	a.sessionRenewMu.Lock()
	defer a.sessionRenewMu.Unlock()
	c := r.controller
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, a.cfg.Node))
	if err != nil {
		t.Fatal(err)
	}
	// Genuine later writes evict the receipt from this History:2 bucket.
	for range 2 {
		revision, err = c.cas(t.Context(), sessionKey(c.cell, a.cfg.Node), current, revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.AdmitManagerRuntimeRenewal(t.Context(), a, predecessor); err == nil {
		t.Fatal("new admission inferred an evicted exact revision from current state")
	}
	if err := held.Revalidate(t.Context()); err != nil {
		t.Fatal("already independently admitted receipt required retained stream history:", err)
	}
}

func TestSessionResponseReceiptNamesActualReplayCommit(t *testing.T) {
	c, conn, _, _, controllerKey := testController(t)
	key := registerTestHost(t, c)
	conflicts := &sessionConflictState{KeyValue: c.state}
	c.state = conflicts
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-c.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not subscribe")
	}
	req := signedHostRequest(t, key, "session", entityid.New(), 0, sessionOperation{Kind: "acquire"})
	var prior uint64
	for attempt := range 3 {
		if attempt == 2 {
			// Exhaust the replay loop; its final fallback must receipt the
			// successful write too, rather than guessing revision+1.
			conflicts.conflicts.Store(8)
		}
		var accepted session
		var signed protocol.Envelope
		if err := exchangeWithEnvelope(t.Context(), conn, c.cell, controllerKey.Public().(ed25519.PublicKey), req, &accepted, &signed); err != nil {
			t.Fatal(err)
		}
		var result response
		if err := decodeStrict(signed.Payload, &result); err != nil {
			t.Fatal(err)
		}
		if result.SessionRevision <= prior {
			t.Fatal("exact replay echoed an earlier revision instead of its actual CAS write")
		}
		js, err := conn.JetStream()
		if err != nil {
			t.Fatal(err)
		}
		msg, err := js.GetMsg("KV_"+stateBucket, result.SessionRevision, nats.Context(t.Context()))
		if err != nil || msg == nil || !bytes.Equal(msg.Data, result.Payload) {
			t.Fatalf("replay receipt does not name exact bytes: %v", err)
		}
		prior = result.SessionRevision
	}
}
