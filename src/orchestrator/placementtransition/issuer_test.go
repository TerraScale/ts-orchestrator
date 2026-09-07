package placementtransition

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"testing"
)

type memoryJournal struct {
	s        state
	revision uint64
	unknown  bool
}

func TestIndependentGenesisWireVector(t *testing.T) {
	data, err := os.ReadFile("testdata/genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKey     string `json:"public_key_hex"`
		RequestDigest string `json:"request_digest"`
		Proof         Signed `json:"proof"`
	}
	if err := json.Unmarshal(data, &v, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var proof Proof
	if err := verify(v.Proof, key, &proof); err != nil {
		t.Fatal(err)
	}
	d, err := RequestDigest(proof.Request)
	if err != nil || d != v.RequestDigest || d != proof.RequestDigest {
		t.Fatal("request digest mismatch", err)
	}
	var genesis GenesisGrant
	if proof.GenesisGrant == nil || verify(*proof.GenesisGrant, key, &genesis) != nil || genesis.RequestDigest != d {
		t.Fatal("invalid genesis vector")
	}
}

func TestFenceQuorumCoversEveryPreviousRegion(t *testing.T) {
	i, _, keys := setup(t)
	r := request()
	r.Members = append(r.Members, Member{"c", "FRA", hash([]byte("c"))}, Member{"d", "FRA", hash([]byte("d"))})
	g := grant(t, r, keys["genesis"])
	if _, err := i.Issue(t.Context(), r, &g, nil); err != nil {
		t.Fatal(err)
	}
	r.OperationID = "next"
	r.PriorEpoch = 1
	r.Epoch = 2
	r.Generation = 2
	a := drain(t, r, "a", keys["a"])
	b := drain(t, r, "b", keys["b"])
	c := drain(t, r, "c", keys["c"])
	if _, err := i.Issue(t.Context(), r, nil, []Signed{a, b}); !errors.Is(err, ErrInvalid) {
		t.Fatal("two seats in only one region passed", err)
	}
	if _, err := i.Issue(t.Context(), r, nil, []Signed{a, c}); err != nil {
		t.Fatal(err)
	}
}

func (j *memoryJournal) TransactRevision(_ context.Context, _ bool, f func(*state, uint64) error) error {
	b, _ := json.Marshal(j.s)
	var next state
	_ = json.Unmarshal(b, &next)
	if err := f(&next, j.revision+1); err != nil {
		return err
	}
	if err := validState(next); err != nil {
		return err
	}
	j.s = next
	j.revision++
	if j.unknown {
		j.unknown = false
		return errors.New("unknown commit outcome")
	}
	return nil
}
func setup(t *testing.T) (*Issuer, *memoryJournal, map[string]ed25519.PrivateKey) {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	pubs := map[string]ed25519.PublicKey{}
	for _, id := range []string{"gru", "genesis", "a", "b", "c", "d"} {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[id] = k
		pubs[id] = p
	}
	j := &memoryJournal{s: emptyState()}
	return &Issuer{j, "gru", keys["gru"], 3, "lease3", map[string]ed25519.PublicKey{"genesis": pubs["genesis"]}, map[string]ed25519.PublicKey{"a": pubs["a"], "b": pubs["b"], "c": pubs["c"], "d": pubs["d"]}, nil}, j, keys
}
func request() Request {
	return Request{"op1", "prod/cluster", 0, 1, 1, []Member{{"a", "GRU", hash([]byte("a"))}, {"b", "GRU", hash([]byte("b"))}}}
}
func grant(t *testing.T, r Request, key ed25519.PrivateKey) Signed {
	t.Helper()
	d, e := RequestDigest(r)
	if e != nil {
		t.Fatal(e)
	}
	s, e := SignEvidence("genesis", key, GenesisGrant{"genesis_grant", "explicit-grant", d})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func drain(t *testing.T, r Request, id string, key ed25519.PrivateKey) Signed {
	t.Helper()
	d, _ := RequestDigest(r)
	s, e := SignEvidence(id, key, DrainReceipt{"old_epoch_drained_fenced", id, r.ScopeID, r.PriorEpoch, 1, d, hash([]byte("durable-frontier"))})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestExplicitGenesisAndUnknownRetry(t *testing.T) {
	i, j, keys := setup(t)
	r := request()
	if _, e := i.Issue(t.Context(), r, nil, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	g := grant(t, r, keys["genesis"])
	j.unknown = true
	if s, e := i.Issue(t.Context(), r, &g, nil); e == nil || len(s.Payload) != 0 {
		t.Fatal("unknown returned proof")
	}
	first, e := i.Issue(t.Context(), r, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	second, e := i.Load(t.Context(), r.OperationID)
	if e != nil || string(first.Payload) != string(second.Payload) {
		t.Fatal("retry changed proof", e)
	}
	r.Generation++
	if _, e := i.Issue(t.Context(), r, &g, nil); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestRequiresOldRF2FenceQuorum(t *testing.T) {
	i, _, keys := setup(t)
	r := request()
	g := grant(t, r, keys["genesis"])
	if _, e := i.Issue(t.Context(), r, &g, nil); e != nil {
		t.Fatal(e)
	}
	r.OperationID = "op2"
	r.PriorEpoch = 1
	r.Epoch = 2
	r.Generation = 2
	r.Members = []Member{{"b", "GRU", hash([]byte("b2"))}, {"c", "GRU", hash([]byte("c2"))}}
	a, b := drain(t, r, "a", keys["a"]), drain(t, r, "b", keys["b"])
	for _, receipts := range [][]Signed{nil, {a, a}, {a, drain(t, r, "c", keys["c"])}} {
		if _, e := i.Issue(t.Context(), r, nil, receipts); !errors.Is(e, ErrInvalid) {
			t.Fatal("incomplete accepted", e)
		}
	}
	corrupt := cloneSigned(b)
	corrupt.Payload[0] = 'x'
	if _, e := i.Issue(t.Context(), r, nil, []Signed{a, corrupt}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := i.Issue(t.Context(), r, nil, []Signed{a}); e != nil {
		t.Fatal(e)
	}
	r.OperationID = "competing"
	if _, e := i.Issue(t.Context(), r, nil, []Signed{a, b}); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestGenesisBoundToRequestAndNeverReused(t *testing.T) {
	i, _, keys := setup(t)
	r := request()
	g := grant(t, r, keys["genesis"])
	altered := r
	altered.ScopeID = "other"
	if _, e := i.Issue(t.Context(), altered, &g, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := i.Issue(t.Context(), r, &g, nil); e != nil {
		t.Fatal(e)
	}
	altered.OperationID = "other-op"
	g = grant(t, altered, keys["genesis"])
	if _, e := i.Issue(t.Context(), altered, &g, nil); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}

func TestIssuerResolvesEnrolledMemberReceiptWithoutTrustingSuppliedKey(t *testing.T) {
	for _, scenario := range []string{"enrolled", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			issuer, journal, keys := setup(t)
			prior := request()
			g := grant(t, prior, keys["genesis"])
			if _, err := issuer.Issue(t.Context(), prior, &g, nil); err != nil {
				t.Fatal(err)
			}
			next := prior
			next.OperationID, next.PriorEpoch, next.Epoch, next.Generation = "successor", 1, 2, 2
			next.Members = []Member{{"b", "GRU", hash([]byte("b2"))}, {"c", "GRU", hash([]byte("c2"))}}
			delete(issuer.memberKeys, "c")
			issuer.memberKey = func(_ context.Context, member Member) (ed25519.PublicKey, error) {
				if member.Identity != "c" || member.Region != "GRU" {
					t.Fatalf("unbound receipt lookup: %+v", member)
				}
				if scenario == "unavailable" {
					return nil, errors.New("enrollment unavailable")
				}
				return keys["c"].Public().(ed25519.PublicKey), nil
			}
			before := journal.revision
			proof, err := issuer.Issue(t.Context(), next, nil, []Signed{drain(t, next, "a", keys["a"])})
			if scenario != "enrolled" {
				if err == nil || len(proof.Payload) != 0 || journal.revision != before {
					t.Fatalf("unverified key changed authority: %v", err)
				}
				return
			}
			if err != nil || len(proof.Payload) == 0 {
				t.Fatalf("enrolled receipt rejected: %v", err)
			}
			var admitted Proof
			if json.Unmarshal(proof.Payload, &admitted) != nil || len(admitted.MemberReceiptKeys) != 2 || !ed25519.PublicKey(admitted.MemberReceiptKeys["c"]).Equal(keys["c"].Public()) {
				t.Fatal("signed successor did not bind exact admitted keys")
			}
		})
	}
}

func TestIssuerCannotChangeKeyOfRetainedIdentity(t *testing.T) {
	issuer, journal, keys := setup(t)
	prior := request()
	g := grant(t, prior, keys["genesis"])
	if _, err := issuer.Issue(t.Context(), prior, &g, nil); err != nil {
		t.Fatal(err)
	}
	next := prior
	next.OperationID, next.PriorEpoch, next.Epoch, next.Generation = "successor", 1, 2, 2
	issuer.memberKeys["b"] = keys["c"].Public().(ed25519.PublicKey)
	before := journal.revision
	if proof, err := issuer.Issue(t.Context(), next, nil, []Signed{drain(t, next, "a", keys["a"])}); !errors.Is(err, ErrConflict) || len(proof.Payload) != 0 || journal.revision != before {
		t.Fatalf("retained identity key replaced: %v", err)
	}
}

// This chain is also the independent Go wire vector consumed by TerraBase's
// durable proof-chain verifier. Export is explicit so normal tests are read-only.
func TestSignedDynamicMemberInventoryChain(t *testing.T) {
	keys := map[string]ed25519.PrivateKey{}
	for index, id := range []string{"gru", "genesis", "a", "b", "c", "d"} {
		var seed [ed25519.SeedSize]byte
		for i := range seed {
			seed[i] = byte(index + 1)
		}
		keys[id] = ed25519.NewKeyFromSeed(seed[:])
	}
	public := func(id string) ed25519.PublicKey { return keys[id].Public().(ed25519.PublicKey) }
	journal := &memoryJournal{s: emptyState()}
	issuer := &Issuer{journal: journal, keyID: "gru", key: keys["gru"], epoch: 3, leaseID: "lease3", genesisKeys: map[string]ed25519.PublicKey{"genesis": public("genesis")}, memberKeys: map[string]ed25519.PublicKey{"a": public("a"), "b": public("b")}}
	lookups := []string{}
	issuer.memberKey = func(_ context.Context, member Member) (ed25519.PublicKey, error) {
		if member.Region != "GRU" || member.Identity != "c" && member.Identity != "d" {
			return nil, ErrInvalid
		}
		lookups = append(lookups, member.Identity)
		return public(member.Identity), nil
	}
	first := Request{OperationID: "op1", ScopeID: "production/test-cluster", Epoch: 1, Generation: 1, Members: []Member{{"a", "GRU", hash([]byte("a1"))}, {"b", "GRU", hash([]byte("b1"))}}}
	g := grant(t, first, keys["genesis"])
	one, err := issuer.Issue(t.Context(), first, &g, nil)
	if err != nil {
		t.Fatal(err)
	}
	second := Request{OperationID: "op2", ScopeID: first.ScopeID, PriorEpoch: 1, Epoch: 2, Generation: 2, Members: []Member{{"b", "GRU", hash([]byte("b2"))}, {"c", "GRU", hash([]byte("c2"))}}}
	two, err := issuer.Issue(t.Context(), second, nil, []Signed{drain(t, second, "a", keys["a"])})
	if err != nil {
		t.Fatal(err)
	}
	clear(issuer.memberKeys) // Successor/restart no longer has old static pins.
	third := Request{OperationID: "op3", ScopeID: first.ScopeID, PriorEpoch: 2, Epoch: 3, Generation: 3, Members: []Member{{"c", "GRU", hash([]byte("c3"))}, {"d", "GRU", hash([]byte("d3"))}}}
	digest, _ := RequestDigest(third)
	fenced, err := SignEvidence("c", keys["c"], DrainReceipt{Kind: "old_epoch_drained_fenced", MemberIdentity: "c", ScopeID: third.ScopeID, PriorEpoch: 2, PriorGeneration: 2, RequestDigest: digest, FrontierDigest: hash([]byte("durable-frontier-2"))})
	if err != nil {
		t.Fatal(err)
	}
	three, err := issuer.Issue(t.Context(), third, nil, []Signed{fenced})
	if err != nil {
		t.Fatal(err)
	}
	var proof Proof
	if err := verify(three, public("gru"), &proof); err != nil || len(proof.MemberReceiptKeys) != 2 || !ed25519.PublicKey(proof.MemberReceiptKeys["d"]).Equal(public("d")) {
		t.Fatalf("dynamic member chain: %v", err)
	}
	if len(lookups) != 3 || lookups[0] != "c" || lookups[1] != "c" || lookups[2] != "d" {
		t.Fatalf("old receipts escaped signed inventory: %v", lookups)
	}
	if path := os.Getenv("TS_EXPORT_PLACEMENT_INVENTORY_VECTOR"); path != "" {
		vector := struct {
			SchemaVersion    int               `json:"schema_version"`
			AuthorityKeys    map[string][]byte `json:"authority_keys"`
			GenesisKeys      map[string][]byte `json:"genesis_keys"`
			StaticMemberKeys map[string][]byte `json:"static_member_keys"`
			Proofs           []Signed          `json:"proofs"`
		}{1, map[string][]byte{"gru": public("gru")}, map[string][]byte{"genesis": public("genesis")}, map[string][]byte{"a": public("a"), "b": public("b")}, []Signed{one, two, three}}
		encoded, err := json.Marshal(vector)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
