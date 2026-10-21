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

// TestRootChainCompromisedOldRoot is the threat model of a leaked root: it
// can do nothing a holder of the replaced root could not do before the
// rotation, and nothing at all once a controller adopted the rotation.
func TestRootChainCompromisedOldRoot(t *testing.T) {
	r0, r1, attacker := testRootKey(t), testRootKey(t), testRootKey(t)
	genesis := testRoots(t, r0)
	start := mustVerifyChain(t, genesis, RootChain{Version: 1})
	adopted := RootChain{Version: 1, Rotations: []SignedRotation{rotate(t, testChainID, start, []ed25519.PrivateKey{r1}, r0, r1)}}
	afterRotation := mustVerifyChain(t, genesis, adopted)

	// The leaked root cannot extend the chain after it was replaced.
	extended := RootChain{Version: 1, Rotations: append(adopted.Rotations,
		rotate(t, testChainID, afterRotation, []ed25519.PrivateKey{attacker}, r0, attacker))}
	if _, err := VerifyRootChain(genesis, testChainID, extended); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("replaced root extended the chain: %v", err)
	}
	// A rival first rotation signed by the leaked root verifies on its own,
	// as anything that root signed did before, but it does not extend the
	// adopted chain, and neither does the bare genesis (a rollback).
	rival := RootChain{Version: 1, Rotations: []SignedRotation{rotate(t, testChainID, start, []ed25519.PrivateKey{attacker}, r0, attacker)}}
	mustVerifyChain(t, genesis, rival)
	if rival.Extends(adopted) || (RootChain{Version: 1}).Extends(adopted) {
		t.Fatal("a fork or rollback extends the adopted chain")
	}

	// A delegation the leaked root signs grants nothing.
	delegate := testRootKey(t)
	delegation, err := SignDelegation(Delegation{SchemaVersion: SchemaVersion,
		SubjectKeyID:     mustKeyID(t, delegate.Public().(ed25519.PublicKey)),
		SubjectPublicKey: mustPublic(t, delegate.Public().(ed25519.PublicKey)),
		Capabilities: []Capability{{Domain: "terrascale.controller.service-set", DeploymentID: testChainID.DeploymentID,
			Cell: testChainID.Cell, Environment: testChainID.Environment, Role: "service-set", Slots: []string{"services"},
			Actions: []string{"sign"}}}}, testChainAt, testChainAt.Add(time.Hour), r0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDelegationCurrent(delegation, afterRotation.Current, testChainAt, testPolicy()); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("leaked root delegated after rotation: %v", err)
	}
}

func TestRootChainRequiresMajorityAndEveryNewRoot(t *testing.T) {
	a, b, c, next := testRootKey(t), testRootKey(t), testRootKey(t), testRootKey(t)
	genesis := testRoots(t, a, b, c)
	start := mustVerifyChain(t, genesis, RootChain{Version: 1})
	for name, signers := range map[string][]ed25519.PrivateKey{
		"one of three old roots":   {a, next},
		"old roots without new":    {a, b},
		"new root alone":           {next},
		"same old root twice":      {a, a, next},
		"stranger instead of root": {a, testRootKey(t), next},
	} {
		chain := RootChain{Version: 1, Rotations: []SignedRotation{rotate(t, testChainID, start, []ed25519.PrivateKey{next}, signers...)}}
		if _, err := VerifyRootChain(genesis, testChainID, chain); err == nil {
			t.Errorf("%s: rotation accepted", name)
		}
	}
	majority := RootChain{Version: 1, Rotations: []SignedRotation{rotate(t, testChainID, start, []ed25519.PrivateKey{next}, c, a, next)}}
	if verified := mustVerifyChain(t, genesis, majority); len(verified.Current) != 1 {
		t.Fatalf("majority rotation = %+v", verified)
	}
}

func TestRootChainRejectsTampering(t *testing.T) {
	r0, r1, r2 := testRootKey(t), testRootKey(t), testRootKey(t)
	genesis := testRoots(t, r0)
	start := mustVerifyChain(t, genesis, RootChain{Version: 1})
	good := rotate(t, testChainID, start, []ed25519.PrivateKey{r1}, r0, r1)
	afterFirst := mustVerifyChain(t, genesis, RootChain{Version: 1, Rotations: []SignedRotation{good}})

	// Skipping a sequence or naming another predecessor breaks the link.
	skipped := afterFirst
	skipped.Sequence = 0
	unlinked := afterFirst
	unlinked.Head = start.Head
	for name, base := range map[string]VerifiedRoots{"sequence gap": skipped, "wrong predecessor": unlinked} {
		bad := rotate(t, testChainID, base, []ed25519.PrivateKey{r2}, r1, r2)
		if _, err := VerifyRootChain(genesis, testChainID, RootChain{Version: 1, Rotations: []SignedRotation{good, bad}}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another cell's rotation does not apply here.
	other := testChainID
	other.Cell = "sfo"
	foreign := rotate(t, other, start, []ed25519.PrivateKey{r1}, r0, r1)
	if _, err := VerifyRootChain(genesis, testChainID, RootChain{Version: 1, Rotations: []SignedRotation{foreign}}); !errors.Is(err, ErrScopeMismatch) {
		t.Errorf("foreign cell: %v", err)
	}
	// Signatures over two different statements.
	mixed := rotate(t, testChainID, start, []ed25519.PrivateKey{r2}, r2)
	mixed.Signatures = append(mixed.Signatures, good.Signatures[0])
	if _, err := VerifyRootChain(genesis, testChainID, RootChain{Version: 1, Rotations: []SignedRotation{mixed}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("mixed statements: %v", err)
	}
	// A flipped signature.
	flipped := rotate(t, testChainID, start, []ed25519.PrivateKey{r1}, r0, r1)
	flipped.Signatures[0].Signature = good.Signatures[1].Signature
	if _, err := VerifyRootChain(genesis, testChainID, RootChain{Version: 1, Rotations: []SignedRotation{flipped}}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("flipped signature: %v", err)
	}
	if _, err := VerifyRootChain(genesis, testChainID, RootChain{Version: 1, Rotations: []SignedRotation{{}}}); err == nil {
		t.Error("accepted an unsigned rotation")
	}
	// A statement is applied only inside its validity window.
	if err := RotationCurrent(good, testChainAt); err != nil {
		t.Errorf("current rotation: %v", err)
	}
	if err := RotationCurrent(good, testChainAt.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired rotation: %v", err)
	}
}

func mustKeyID(t *testing.T, key ed25519.PublicKey) string {
	t.Helper()
	keyID, err := KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return keyID
}

func mustPublic(t *testing.T, key ed25519.PublicKey) string {
	t.Helper()
	encoded, err := EncodeDelegatedPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRootChainRequiresVersionOne(t *testing.T) {
	for _, wire := range []string{`{"rotations":[]}`, `{"rotations":[],"version":0}`, `{"rotations":[],"version":2}`, `{"rotations":[],"version":null}`} {
		if _, err := DecodeRootChain([]byte(wire)); err == nil {
			t.Fatalf("accepted unsupported root chain format: %s", wire)
		}
	}
	for _, version := range []int{0, 2} {
		if _, err := EncodeRootChain(RootChain{Version: version}); err == nil {
			t.Fatalf("encoded root chain version %d", version)
		}
	}
	wire, err := EncodeRootChain(RootChain{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := DecodeRootChain(wire)
	if err != nil || chain.Version != 1 || len(chain.Rotations) != 0 {
		t.Fatalf("version one genesis chain: %+v, %v", chain, err)
	}
}
