package rootsecret

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/nats-io/nkeys"
)

func TestNetBirdReadContextKeepsOriginalCancellationAndShortestDeadline(t *testing.T) {
	now := time.Now()
	original, cancelOriginal := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancelOriginal()
	caller, cancelCaller := context.WithDeadline(t.Context(), now.Add(2*time.Minute))
	defer cancelCaller()
	read, cancelRead := netBirdReadContext(caller, original, now.Add(3*time.Minute))
	defer cancelRead()
	if deadline, _ := read.Deadline(); !deadline.Equal(now.Add(time.Minute)) {
		t.Fatal("read outlives the retained original deadline")
	}
	cancelOriginal()
	select {
	case <-read.Done():
	case <-time.After(time.Second):
		t.Fatal("original cancellation did not interrupt the active read")
	}
	read, stop := netBirdReadContext(caller, t.Context(), now.Add(30*time.Second))
	defer stop()
	if deadline, _ := read.Deadline(); !deadline.Equal(now.Add(30 * time.Second)) {
		t.Fatal("read outlives the learned material expiry")
	}
	cancelCaller()
	if read.Err() == nil {
		t.Fatal("retained material lifetime revived a canceled caller")
	}
}

func TestNetBirdBrokerMaterialBoundsAndRedaction(t *testing.T) {
	secret := []byte("private-manager-key-never-format")
	material := NetBirdBrokerMaterial{Schema: 1, Credentials: secret, Key: secret}
	for _, value := range []any{material, &NetBirdReader{material: material}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if text := fmt.Sprintf(format, value); strings.Contains(text, string(secret)) || strings.Contains(text, fmt.Sprint([]byte(secret))) {
				t.Fatal("formatting exposed broker material")
			}
		}
	}
	wire, err := material.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNetBirdBrokerMaterial(wire)
	if err != nil || !bytes.Equal(decoded.Key, secret) {
		t.Fatal("exact bounded delivery did not round trip")
	}
	for _, invalid := range [][]byte{bytes.Repeat([]byte(" "), NetBirdBrokerMaterialLimit+1), []byte(`{"schema":1,"schema":1}`), []byte(`{"schema":1,"unexpected":"private-manager-key-never-format"}`)} {
		if _, err := DecodeNetBirdBrokerMaterial(invalid); err == nil {
			t.Fatal("accepted an oversized or ambiguous delivery")
		} else if strings.Contains(err.Error(), string(secret)) {
			t.Fatal("decode error exposed material")
		}
	}
	material.Key = bytes.Repeat([]byte("k"), NetBirdBrokerMaterialLimit)
	if _, err := material.Encode(); err == nil {
		t.Fatal("base64 expansion exceeded the fixed Vault payload bound")
	}
}

func TestNetBirdReadOpenSignatureBindsEntireOriginalTuple(t *testing.T) {
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	proof := rootoci.NetBirdReadOpen{Schema: 1, Cell: "GRU", User: public, SourceSHA256: strings.Repeat("a", 64), Nonce: "original-nonce", ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Minute)}
	signature, err := key.Sign(NetBirdReadOpenSigningBytes(proof))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := nkeys.FromPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Verify(NetBirdReadOpenSigningBytes(proof), signature) != nil {
		t.Fatal("original signed read-open failed")
	}
	for name, change := range map[string]func(*rootoci.NetBirdReadOpen){
		"cell":     func(p *rootoci.NetBirdReadOpen) { p.Cell = "FRA" },
		"user":     func(p *rootoci.NetBirdReadOpen) { p.User = "another-user" },
		"source":   func(p *rootoci.NetBirdReadOpen) { p.SourceSHA256 = strings.Repeat("b", 64) },
		"nonce":    func(p *rootoci.NetBirdReadOpen) { p.Nonce = "another-nonce" },
		"deadline": func(p *rootoci.NetBirdReadOpen) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			change(&changed)
			if verifier.Verify(NetBirdReadOpenSigningBytes(changed), signature) == nil {
				t.Fatal("signature accepted a changed original tuple")
			}
		})
	}
}

func TestNetBirdControllerPeerNameRetainsSignedSlotTLSName(t *testing.T) {
	for _, test := range []struct{ cell, slot, peer string }{
		{"GRU", "ctl-1", "gru-1-ctl-1"},
		{"SFO", "controller-a", "sfo-1-controller-a"},
		{"FRA", "ts-fra-1", "ts-fra-1"},
	} {
		if got := netBirdControllerPeerName(test.cell, test.slot); got != test.peer {
			t.Fatalf("%s/%s routes to %s, want %s", test.cell, test.slot, got, test.peer)
		}
	}
}
