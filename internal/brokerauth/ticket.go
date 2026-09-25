package brokerauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

const (
	TicketLifetime     = 10 * time.Second
	MaxTicketWireBytes = 2 * (maxAccountJWTBytes + 8192)
	MaxTicketRoundTrip = 2 * time.Second
	MaxClockError      = 250 * time.Millisecond
	MaxClockSampleAge  = time.Second
)

// ClockBound is an NTP-measured upper bound on UTC clock error. SampledAt must
// retain Go's monotonic component on the same process that checks it.
type ClockBound struct {
	SampledAt time.Time
	MaxError  time.Duration
}

type ClockProbe interface{ Measure() (ClockBound, error) }

func (b ClockBound) valid(now time.Time) bool {
	return !b.SampledAt.IsZero() && b.MaxError >= 0 && b.MaxError <= MaxClockError &&
		!now.Before(b.SampledAt) && now.Sub(b.SampledAt) <= MaxClockSampleAge
}

// TicketRequest is bound to one broker's fresh random challenge.
type TicketRequest struct {
	Cell    string `json:"cell"`
	Broker  string `json:"broker"`
	Account string `json:"account"`
	Nonce   string `json:"nonce"`
}

func NewRequest(cell, broker, account string) (TicketRequest, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return TicketRequest{}, err
	}
	return TicketRequest{Cell: cell, Broker: broker, Account: account,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce[:])}, nil
}

type Ticket struct {
	TicketRequest
	Epoch                 uint64    `json:"epoch"`
	LeaseRevision         uint64    `json:"leaseRevision"`
	ClaimSequence         uint64    `json:"claimSequence"`
	ClaimHash             string    `json:"claimHash"`
	ClaimJWT              string    `json:"claimJWT"`
	IssuedAt              time.Time `json:"issuedAt"`
	ExpiresAt             time.Time `json:"expiresAt"`
	LeaseExpiresAt        time.Time `json:"leaseExpiresAt"`
	IssuerClockErrorNanos int64     `json:"issuerClockErrorNanos"`
}

// SignedTicket signs the exact serialized payload. Verifiers never reserialize
// before checking the Ed25519 signature.
type SignedTicket struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Issuer struct {
	Store   *Store
	Account string
	Brokers map[string]struct{}
	Key     ed25519.PrivateKey
	Clock   ClockProbe
}

func (i *Issuer) Issue(ctx context.Context, request TicketRequest) (SignedTicket, error) {
	if i == nil || i.Store == nil || i.Clock == nil || len(i.Key) != ed25519.PrivateKeySize ||
		i.Store.fencer == nil ||
		request.Cell != i.Store.cell || request.Account != i.Account || !brokerToken.MatchString(request.Broker) {
		return SignedTicket{}, errors.New("broker ticket issuer or request is invalid")
	}
	if _, ok := i.Brokers[request.Broker]; !ok {
		return SignedTicket{}, errors.New("broker is not admitted for ticket issuance")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 {
		return SignedTicket{}, errors.New("broker ticket nonce is invalid")
	}
	i.Store.mu.Lock()
	defer i.Store.mu.Unlock()
	snapshot := i.Store.fencer.Current()
	if !snapshot.CanMutate() || snapshot.Scope != request.Cell {
		return SignedTicket{}, authority.ErrNotLeader
	}
	if err := i.Store.fencer.Guard(ctx, snapshot.Epoch); err != nil {
		return SignedTicket{}, err
	}
	authorizedAt := time.Now()
	snapshot = i.Store.fencer.Current()
	if !snapshot.CanMutate() || snapshot.Scope != request.Cell || snapshot.Epoch == 0 {
		return SignedTicket{}, authority.ErrFenced
	}
	claim, err := i.Store.Read(ctx, request.Account)
	if err != nil {
		return SignedTicket{}, err
	}
	if claim.Epoch > snapshot.Epoch || claim.Sequence >= snapshot.Revision {
		return SignedTicket{}, authority.ErrFenced
	}
	observed, err := authority.Observe(ctx, i.Store.js, request.Cell)
	if err != nil || !observed.Ready || observed.Epoch != snapshot.Epoch ||
		observed.CandidateID != snapshot.CandidateID || observed.OwnerID != snapshot.OwnerID ||
		observed.Revision < snapshot.Revision {
		return SignedTicket{}, authority.ErrFenced
	}
	bound, err := i.Clock.Measure()
	if err != nil || !bound.valid(time.Now()) {
		return SignedTicket{}, errors.New("issuer NTP clock health is unavailable")
	}
	issued := authorizedAt
	expires := issued.Add(TicketLifetime)
	if leaseDeadline := snapshot.ExpiresAt.Add(-bound.MaxError); leaseDeadline.Before(expires) {
		expires = leaseDeadline
	}
	if !expires.After(issued.Add(bound.MaxError)) {
		return SignedTicket{}, authority.ErrFenced
	}
	if !time.Now().Add(bound.MaxError).Before(expires) {
		return SignedTicket{}, authority.ErrFenced
	}
	current, err := i.Store.Read(ctx, request.Account)
	if err != nil || current.Sequence != claim.Sequence || current.Hash != claim.Hash {
		return SignedTicket{}, ErrClaimChanged
	}
	ticket := Ticket{TicketRequest: request, Epoch: snapshot.Epoch, LeaseRevision: snapshot.Revision,
		ClaimSequence: claim.Sequence, ClaimHash: claim.Hash, ClaimJWT: claim.JWT,
		IssuedAt: issued.UTC(), ExpiresAt: expires.UTC(), LeaseExpiresAt: snapshot.ExpiresAt.UTC(),
		IssuerClockErrorNanos: int64(bound.MaxError)}
	payload, err := json.Marshal(ticket)
	if err != nil {
		return SignedTicket{}, err
	}
	return SignedTicket{Payload: payload, Signature: ed25519.Sign(i.Key, payload)}, nil
}

// VerifyTicket returns a local monotonic deadline for both admission and
// forced closure of existing bridged sessions. The observed claim and lease
// must come from the durable leader-read control stream, not resolver cache.
func VerifyTicket(signed SignedTicket, public ed25519.PublicKey, request TicketRequest,
	started, finished time.Time, bound ClockBound, claim Claim, lease authority.Snapshot) (Ticket, time.Time, error) {
	verifiedAt := time.Now()
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, signed.Payload, signed.Signature) ||
		len(signed.Payload) == 0 || len(signed.Payload) > maxAccountJWTBytes+4096 ||
		finished.Before(started) || finished.After(verifiedAt) ||
		finished.Sub(started) > MaxTicketRoundTrip || !bound.valid(verifiedAt) {
		return Ticket{}, time.Time{}, errors.New("broker ticket signature, round trip, or NTP health is invalid")
	}
	var ticket Ticket
	if err := json.Unmarshal(signed.Payload, &ticket, json.RejectUnknownMembers(true)); err != nil {
		return Ticket{}, time.Time{}, fmt.Errorf("decode signed broker ticket: %w", err)
	}
	if ticket.TicketRequest != request || request.Nonce == "" ||
		ticket.ClaimSequence == 0 || ticket.ClaimSequence != claim.Sequence ||
		ticket.ClaimHash != claim.Hash || ticket.ClaimJWT != claim.JWT ||
		claim.Cell != request.Cell || claim.Account != request.Account ||
		!lease.Ready || lease.Scope != request.Cell || lease.Epoch != ticket.Epoch ||
		lease.Revision < ticket.LeaseRevision || claim.Epoch > ticket.Epoch ||
		claim.Sequence >= ticket.LeaseRevision ||
		ticket.IssuerClockErrorNanos < 0 || time.Duration(ticket.IssuerClockErrorNanos) > MaxClockError {
		return Ticket{}, time.Time{}, errors.New("broker ticket identity or durable claim has changed")
	}
	if ticket.IssuedAt.IsZero() || ticket.ExpiresAt.IsZero() || ticket.LeaseExpiresAt.IsZero() ||
		!ticket.ExpiresAt.After(ticket.IssuedAt) || ticket.ExpiresAt.Sub(ticket.IssuedAt) > TicketLifetime ||
		ticket.ExpiresAt.After(ticket.LeaseExpiresAt) || lease.ExpiresAt.Before(ticket.LeaseExpiresAt) {
		return Ticket{}, time.Time{}, errors.New("broker ticket lifetime is invalid")
	}
	issuerError := time.Duration(ticket.IssuerClockErrorNanos)
	upperNow := verifiedAt.Add(bound.MaxError + issuerError)
	if ticket.IssuedAt.After(upperNow) || !ticket.ExpiresAt.After(upperNow) ||
		!ticket.LeaseExpiresAt.After(upperNow) || !lease.ExpiresAt.After(upperNow) {
		return Ticket{}, time.Time{}, errors.New("broker ticket has expired")
	}
	deadline := verifiedAt.Add(min(ticket.ExpiresAt.Sub(upperNow),
		min(ticket.LeaseExpiresAt.Sub(upperNow), lease.ExpiresAt.Sub(upperNow))))
	return ticket, deadline, nil
}
