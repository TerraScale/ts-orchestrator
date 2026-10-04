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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	_, other, err := ed25519.GenerateKey(rand.Reader)
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
		{"unsigned success", func(*testing.T) []byte { return []byte(`{"status":"fenced","sequence":1,"hash":"forged"}`) }, "decode untrusted"},
		{"unsigned error", func(*testing.T) []byte { return []byte(`{"error":"control log compare-and-set conflict"}`) }, "unsigned broker claim reply"},
		{"signed wrong kind", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.kind = "broker.claim.other" }))
		}, "scope does not match"},
		{"replayed receipt of another claim", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.operation = brokerClaimOperationID(previous) }))
		}, "scope does not match"},
		{"receipt from an older epoch", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.epoch = epoch - 1 }))
		}, "scope does not match"},
		{"other key", func(t *testing.T) []byte { return sign(t, with(func(r *receipt) { r.key = other })) }, ""},
		{"expired", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.issued = now.Add(-2 * time.Minute) }))
		}, ""},
		{"other request", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.RequestHash = strings.Repeat("0", 64) }))
		}, "does not match the request"},
		{"other jwt", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.Hash = strings.Repeat("0", 64) }))
		}, "does not match the request"},
		{"other expected sequence", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.ExpectedSequence = expected + 1 }))
		}, "does not match the request"},
		{"fenced with pending brokers", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.Pending = []string{"broker-c"} }))
		}, "does not match the request"},
		{"pending without brokers", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.Status = "pending" }))
		}, "does not match the request"},
		{"unknown status", func(t *testing.T) []byte {
			return sign(t, with(func(r *receipt) { r.response.Status = "applied" }))
		}, "does not match the request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(tc.data(t))
			if err == nil || !strings.Contains(err.Error(), tc.cause) {
				t.Fatalf("forged reply accepted or rejected for the wrong reason: %v", err)
			}
		})
	}
}
