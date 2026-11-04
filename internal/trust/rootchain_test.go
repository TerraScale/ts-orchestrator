package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

var (
	testChainID = ChainIdentity{DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Cell: "gru", Environment: "production"}
	testChainAt = time.Date(2026, time.October, 5, 12, 0, 0, 0, time.UTC)
)

func testRootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func testRoots(t *testing.T, keys ...ed25519.PrivateKey) Keyring {
	t.Helper()
	publics := make([]ed25519.PublicKey, 0, len(keys))
	for _, key := range keys {
		publics = append(publics, key.Public().(ed25519.PublicKey))
	}
	roots, err := ParseKeyring(publics...)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

// rotate signs the statement replacing verified's set with next's public
// keys, signed by every key in signers.
func rotate(t *testing.T, id ChainIdentity, verified VerifiedRoots, next []ed25519.PrivateKey, signers ...ed25519.PrivateKey) SignedRotation {
	t.Helper()
	publics := make([]ed25519.PublicKey, 0, len(next))
	for _, key := range next {
		publics = append(publics, key.Public().(ed25519.PublicKey))
	}
	rotation, err := NextRotation(verified, publics...)
	if err != nil {
		t.Fatal(err)
	}
	var signed SignedRotation
	for _, key := range signers {
		envelope, err := SignRotation(rotation, id, testChainAt, testChainAt.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	return signed
}

func mustVerifyChain(t *testing.T, genesis Keyring, chain RootChain) VerifiedRoots {
	t.Helper()
	verified, err := VerifyRootChain(genesis, testChainID, chain)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestRootChainRotatesAndRevokesTheReplacedRoot(t *testing.T) {
	production, err := DiscoveryGenesis()
	if err != nil || len(production) != 1 {
		t.Fatalf("reviewed production genesis: keys=%d err=%v", len(production), err)
	}
	if _, err := VerifyRootChain(production, testChainID, RootChain{Version: 1}); err != nil {
		t.Fatal(err)
	}
	r0, r1, r2 := testRootKey(t), testRootKey(t), testRootKey(t)
	genesis := testRoots(t, r0)
	start := mustVerifyChain(t, genesis, RootChain{Version: 1})
	if start.Sequence != 0 || start.Head != RootSetDigest(genesis) || len(start.Current) != 1 {
		t.Fatalf("genesis = %+v", start)
	}
	first := RootChain{Version: 1, Rotations: []SignedRotation{rotate(t, testChainID, start, []ed25519.PrivateKey{r1}, r0, r1)}}
	afterFirst := mustVerifyChain(t, genesis, first)
	second := RootChain{Version: 1, Rotations: append(first.Rotations, rotate(t, testChainID, afterFirst, []ed25519.PrivateKey{r2}, r1, r2))}
	head := mustVerifyChain(t, genesis, second)
	r2ID, _ := KeyID(r2.Public().(ed25519.PublicKey))
	if head.Sequence != 2 || len(head.Current) != 1 || head.Current[r2ID] == nil || len(head.Historical) != 3 {
		t.Fatalf("head = %+v", head)
	}
	if !second.Extends(first) || !second.Extends(RootChain{Version: 1}) || first.Extends(second) {
		t.Fatal("chain prefix order is wrong")
	}

	// Wire round trip is canonical.
	wire, err := EncodeRootChain(second)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRootChain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if again := mustVerifyChain(t, genesis, decoded); again.Head != head.Head {
		t.Fatal("decoded chain verifies to another head")
	}
	if _, err := DecodeRootChain(append([]byte(" "), wire...)); err == nil {
		t.Fatal("accepted a non-canonical chain")
	}

	// The replaced roots keep no current authority.
	scope := Scope{Domain: "terrascale.controller.service-set", DeploymentID: testChainID.DeploymentID,
		Cell: testChainID.Cell, Environment: testChainID.Environment, Role: "service-set", Slot: "services"}
	for name, key := range map[string]ed25519.PrivateKey{"genesis root": r0, "first rotated root": r1} {
		envelope, err := Sign([]byte(`{"x":1}`), scope, testChainAt, testChainAt.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCurrent(envelope, scope, head.Current, testChainAt, testPolicy()); !errors.Is(err, ErrUntrustedKey) {
			t.Fatalf("%s still has current authority: %v", name, err)
		}
		if _, err := VerifyHistorical(envelope, scope, head.Historical, testPolicy()); err != nil {
			t.Fatalf("%s lost historical authority: %v", name, err)
		}
	}
}
