package brokerauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type fixedClockSample struct {
	bound ClockBound
	err   error
}

func (probe fixedClockSample) Measure() (ClockBound, error) { return probe.bound, probe.err }

func TestMeasureHealthyClockRequiresFreshBound(t *testing.T) {
	now := time.Now()
	valid := fixedClockSample{bound: ClockBound{SampledAt: now, MaxError: MaxClockError}}
	if _, err := MeasureHealthyClock(valid); err != nil {
		t.Fatalf("fresh bounded clock rejected: %v", err)
	}
	for _, test := range []struct {
		name  string
		probe ClockProbe
	}{
		{"missing", nil},
		{"probe-error", fixedClockSample{err: errors.New("NTP unavailable")}},
		{"zero", fixedClockSample{bound: ClockBound{MaxError: time.Millisecond}}},
		{"0000000000RNVXNPAX5Y5BB8RY", fixedClockSample{bound: ClockBound{SampledAt: now.Add(-2 * time.Second), MaxError: time.Millisecond}}},
		{"future", fixedClockSample{bound: ClockBound{SampledAt: now.Add(time.Second), MaxError: time.Millisecond}}},
		{"negative-error", fixedClockSample{bound: ClockBound{SampledAt: now, MaxError: -time.Millisecond}}},
		{"excess-error", fixedClockSample{bound: ClockBound{SampledAt: now, MaxError: MaxClockError + time.Millisecond}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := MeasureHealthyClock(test.probe); err == nil {
				t.Fatal("invalid NTP clock bound accepted")
			}
		})
	}
}

func TestTicketBindsDurableClaimBrokerNonceAndMonotonicDeadline(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("gru", "broker-a", "account-a")
	if err != nil {
		t.Fatal(err)
	}
	finish := time.Now().Add(-100 * time.Millisecond)
	start := finish.Add(-30 * time.Millisecond)
	claim := Claim{Cell: "gru", Account: "account-a", Sequence: 11, Hash: "exact-hash", JWT: "exact-jwt", Epoch: 2}
	lease := authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000FHEQV98X4ASD7RXW", Ready: true, Epoch: 2, Revision: 22,
		ExpiresAt: finish.Add(8 * time.Second)}
	ticket := Ticket{TicketRequest: request, DeploymentID: lease.DeploymentID, Epoch: 2, LeaseRevision: 22, ClaimSequence: 11,
		ClaimHash: claim.Hash, ClaimJWT: claim.JWT, IssuedAt: start.UTC(),
		ExpiresAt: start.Add(5 * time.Second).UTC(), LeaseExpiresAt: lease.ExpiresAt.UTC(),
		IssuerClockErrorNanos: int64(20 * time.Millisecond)}
	sign := func(ticket Ticket) SignedTicket {
		t.Helper()
		payload, err := json.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		return SignedTicket{Payload: payload, Signature: ed25519.Sign(private, payload)}
	}
	bound := ClockBound{SampledAt: time.Now(), MaxError: 20 * time.Millisecond}
	if !bound.SampledAt.After(finish) {
		t.Fatal("clock sample must follow the received ticket")
	}
	_, deadline, err := VerifyTicket(sign(ticket), public, request, start, finish, bound, claim, lease)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.After(finish) || deadline.After(ticket.ExpiresAt.Add(-40*time.Millisecond)) {
		t.Fatalf("deadline %s did not conservatively account for both measured clock errors", deadline)
	}
	checks := []struct {
		name    string
		signed  SignedTicket
		request TicketRequest
		bound   ClockBound
		claim   Claim
		lease   authority.Snapshot
		finish  time.Time
	}{
		{"wrong nonce", sign(ticket), TicketRequest{Cell: request.Cell, Broker: request.Broker, Account: request.Account, Nonce: "different"}, bound, claim, lease, finish},
		{"different durable hash", sign(ticket), request, bound, Claim{Cell: claim.Cell, Account: claim.Account, Sequence: claim.Sequence, Hash: "0000000000V4MRM46HP1SNGDYW", JWT: claim.JWT, Epoch: claim.Epoch}, lease, finish},
		{"stale clock", sign(ticket), request, ClockBound{SampledAt: finish.Add(-2 * time.Second), MaxError: 20 * time.Millisecond}, claim, lease, finish},
		{"clock error too large", sign(ticket), request, ClockBound{SampledAt: finish, MaxError: MaxClockError + time.Millisecond}, claim, lease, finish},
		{"slow reply", sign(ticket), request, bound, claim, lease, start.Add(MaxTicketRoundTrip + time.Millisecond)},
		{"new epoch", sign(ticket), request, bound, claim, authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", Ready: true, Epoch: 3, Revision: 23, ExpiresAt: lease.ExpiresAt}, finish},
		// A revocation commits the next claim. A ticket the leader signed
		// for the pre-revocation claim must not admit the broker, even within
		// its lifetime and the same authority epoch.
		{"revoked by the next claim", sign(ticket), request, bound, Claim{Cell: claim.Cell, Account: claim.Account, Sequence: claim.Sequence + 1, Hash: "revoked-hash", JWT: "revoked-jwt", Epoch: claim.Epoch}, lease, finish},
	}
	for _, test := range checks {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := VerifyTicket(test.signed, public, test.request, start, test.finish, test.bound, test.claim, test.lease); err == nil {
				t.Fatal("invalid ticket was accepted")
			}
		})
	}
	bad := sign(ticket)
	bad.Signature[0] ^= 1
	if _, _, err := VerifyTicket(bad, public, request, start, finish, bound, claim, lease); err == nil {
		t.Fatal("tampered ticket was accepted")
	}
	for _, deploymentID := range []string{"", "legacy-deployment", "01ARZ3NDEKTSV4RRFFQ69G5FAW"} {
		foreign := ticket
		foreign.DeploymentID = deploymentID
		if _, _, err := VerifyTicket(sign(foreign), public, request, start, finish, bound, claim, lease); err == nil {
			t.Fatalf("ticket for deployment %q was accepted", deploymentID)
		}
	}
	late := ticket
	late.ExpiresAt = lease.ExpiresAt.Add(time.Millisecond)
	if _, _, err := VerifyTicket(sign(late), public, request, start, finish, bound, claim, lease); err == nil {
		t.Fatal("ticket extending beyond confirmed authority expiry was accepted")
	}
	// The reply arrived before expiry, but verification happened after it.
	// Processing delay must consume validity rather than create a new deadline.
	lateReceipt := ticket
	lateReceipt.IssuedAt = time.Now().Add(-2 * time.Second).UTC()
	lateReceipt.ExpiresAt = time.Now().Add(-10 * time.Millisecond).UTC()
	if !lateReceipt.ExpiresAt.After(finish) {
		t.Fatal("late receipt fixture must expire after network receipt")
	}
	if _, _, err := VerifyTicket(sign(lateReceipt), public, request, start, finish, bound, claim, lease); err == nil {
		t.Fatal("late verification extended an already expired ticket")
	}
}

type pausedTicketFencer struct {
	entered  chan struct{}
	release  chan struct{}
	snapshot authority.Snapshot
}

func (f *pausedTicketFencer) Current() authority.Snapshot { return f.snapshot }
func (f *pausedTicketFencer) Guard(ctx context.Context, _ uint64) error {
	close(f.entered)
	select {
	case <-f.release:
		return authority.ErrFenced
	case <-ctx.Done():
		return ctx.Err()
	}
}

type healthyTicketClock struct{}

func (healthyTicketClock) Measure() (ClockBound, error) {
	return ClockBound{SampledAt: time.Now(), MaxError: time.Millisecond}, nil
}

func TestDelayedIssuerCannotSignAfterLeaderLoss(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fencer := &pausedTicketFencer{entered: make(chan struct{}), release: make(chan struct{}),
		snapshot: authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000FHEQV98X4ASD7RXW", OwnerID: "0000000000WG6WAQW746KJBD69", Ready: true, Leader: true,
			Epoch: 1, Revision: 1, ExpiresAt: time.Now().Add(5 * time.Second)}}
	issuer := Issuer{Store: &Store{cell: "gru", fencer: fencer}, Account: "account-a",
		Brokers: map[string]struct{}{"broker-a": {}}, Key: private, Clock: healthyTicketClock{}}
	request, err := NewRequest("gru", "broker-a", "account-a")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	result := make(chan error, 1)
	go func() { _, err := issuer.Issue(ctx, request); result <- err }()
	select {
	case <-fencer.entered:
	case <-time.After(time.Second):
		t.Fatal("issuer did not reach Guard")
	}
	close(fencer.release)
	select {
	case err := <-result:
		if !errors.Is(err, authority.ErrFenced) {
			t.Fatalf("delayed old leader ticket = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("issuer remained stuck after leader loss")
	}
}
