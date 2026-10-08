package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestSignedHostRequestRejectsTamperingAndExpiry(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: "session", SessionID: "014D2PF2DBSQQG28T5CY4TQKFF", Nonce: "5BSQQG28T5CY4TQKFF04HMASW9", IssuedAt: now, Payload: []byte(`{"kind":"acquire"}`)}
	if err := signRequest(&r, private, "gru"); err != nil {
		t.Fatal(err)
	}
	encoded, err := protocol.EncodeJSON(r.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(encoded, &envelope, 64<<10); err != nil {
		t.Fatal(err)
	}
	var decoded request
	if err := protocol.DecodeStrict([]byte(envelope.Payload), &decoded, 64<<10); err != nil {
		t.Fatal(err)
	}
	decoded.Envelope = envelope
	if err := verifyRequest(decoded, public, "gru", now); err != nil {
		t.Fatalf("valid signed request rejected: %v", err)
	}
	decoded.Node = "node-b"
	if err := verifyRequest(decoded, public, "gru", now); err == nil {
		t.Fatal("tampered node was accepted")
	}
	decoded.Node = "node-a"
	if err := verifyRequest(decoded, public, "gru", now.Add(-time.Second)); err != nil {
		t.Fatalf("bounded clock skew rejected: %v", err)
	}
	if err := verifyRequest(decoded, public, "gru", now.Add(-maxClockSkew-time.Millisecond)); err == nil {
		t.Fatal("excessive future clock skew accepted")
	}
	if err := verifyRequest(decoded, public, "gru", now.Add(requestTTL)); err == nil {
		t.Fatal("expired request was accepted")
	}
}

func TestForgedHostReplyCannotBecomeDesired(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	defer func() { srv.Shutdown(); srv.WaitForShutdown() }()
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = hostPublic
	r := request{Version: 1, Node: "node-a", NATSUserPublicKey: testNATSUserKey("node-a"), Operation: "desired", SessionID: "014D2PF2DBSQQG28T5CY4TQKFF", Epoch: 1, Nonce: "5BSQQG28T5CY4TQKFF04HMASW9", IssuedAt: time.Now().UTC(), Payload: []byte(`{"role":"terrabase"}`)}
	if err := signRequest(&r, hostPrivate, "gru"); err != nil {
		t.Fatal(err)
	}
	subject, err := protocol.AgentObservationSubject("gru", r.NATSUserPublicKey, r.Operation)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := conn.Subscribe(subject, func(msg *nats.Msg) {
		_ = msg.Respond([]byte(`{"nonce":"5BSQQG28T5CY4TQKFF04HMASW9","payload":{"desired":{"role":"terrabase","digest":"attacker"}}}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	var desired desiredReply
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := exchange(ctx, conn, "gru", controllerPrivate.Public().(ed25519.PublicKey), r, &desired); err == nil {
		t.Fatal("unsigned forged desired reply accepted")
	}
}

func TestStrictHostJSONRejectsDuplicateAndTrailingData(t *testing.T) {
	var out response
	for _, data := range [][]byte{[]byte(`{"nonce":"a","nonce":"b"}`), []byte(`{"nonce":"a"}garbage`), []byte(`{"nonce":"a"}{"nonce":"b"}`)} {
		if err := decodeStrict(data, &out); err == nil {
			t.Fatalf("accepted malformed JSON: %s", data)
		}
	}
}
