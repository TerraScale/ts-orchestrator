package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// TestBrokerClaimReplyRejectsForgedReceipts is the single-process form of the
// forged-reply checks in TestBrokerGateR3TicketRevocationAndOfflineFence:
// only a strict receipt signed by the broker key for this exact operation,
// authority epoch and request may report a fenced or pending revocation.
func TestBrokerClaimReplyRejectsForgedReceipts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const cell, account, epoch, expected = "gru", "ACCOUNT", uint64(7), uint64(4)
	revoked, previous := "revoked-account-jwt", "previous-account-jwt"
	wire := []byte(`{"signed":"claim apply request"}`)
	jwtDigest, requestDigest := sha256.Sum256([]byte(revoked)), sha256.Sum256(wire)
	valid := brokerClaimApplyResponse{Cell: cell, Account: account, RequestHash: hex.EncodeToString(requestDigest[:]),
		ExpectedSequence: expected, Status: "fenced", Sequence: expected + 1, Hash: hex.EncodeToString(jwtDigest[:])}
	now := time.Now().UTC()
	type receipt struct {
		response               brokerClaimApplyResponse
		kind, operation, actor string
		epoch                  uint64
		key                    ed25519.PrivateKey
		issued                 time.Time
	}
	good := receipt{valid, "broker.claim.receipt", brokerClaimOperationID(revoked), "broker-controller", epoch, private, now}
	sign := func(t *testing.T, r receipt) []byte {
		t.Helper()
		payload, err := json.Marshal(r.response)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cell, Kind: r.kind, Actor: r.actor,
			OperationID: r.operation, Generation: r.response.Sequence, Epoch: r.epoch}, r.issued, r.issued.Add(time.Minute), r.key)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(brokerClaimApplyReply{Proof: &proof})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	verify := func(data []byte) error {
		_, _, err := verifyBrokerClaimReply(data, cell, account, revoked, wire, expected, epoch, public, now)
		return err
	}
	if err := verify(sign(t, good)); err != nil {
		t.Fatalf("valid fenced receipt: %v", err)
	}
	pending := good
	pending.response.Status, pending.response.Pending = "pending", []string{"broker-c"}
	if err := verify(sign(t, pending)); err != nil {
		t.Fatalf("valid pending receipt: %v", err)
	}
	with := func(change func(*receipt)) receipt {
		r := good
		change(&r)
		return r
	}
	for _, tc := range []struct {
		name  string
		data  func(t *testing.T) []byte
		cause string
	}{

		{"replayed receipt of another claim", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.operation = brokerClaimOperationID(previous) }))
		}, "scope does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.data(t))
			if err == nil || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("forged reply accepted or rejected for the wrong reason: %v", err)
			}
		})
	}
}
