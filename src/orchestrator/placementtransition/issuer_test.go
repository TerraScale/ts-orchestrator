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
	r.Members = append(r.Members, Member{"c", "fra", hash([]byte("c"))}, Member{"d", "fra", hash([]byte("d"))})
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
	for _, id := range []string{"gru", "genesis", "a", "b", "c"} {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		keys[id] = k
		pubs[id] = p
	}
	j := &memoryJournal{s: emptyState()}
	return &Issuer{j, "gru", keys["gru"], 3, "lease3", map[string]ed25519.PublicKey{"genesis": pubs["genesis"]}, map[string]ed25519.PublicKey{"a": pubs["a"], "b": pubs["b"], "c": pubs["c"]}}, j, keys
}
func request() Request {
	return Request{"op1", "prod/cluster", 0, 1, 1, []Member{{"a", "gru", hash([]byte("a"))}, {"b", "gru", hash([]byte("b"))}}}
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
	r.Members = []Member{{"b", "gru", hash([]byte("b2"))}, {"c", "gru", hash([]byte("c2"))}}
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
