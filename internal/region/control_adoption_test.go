package region

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// These fixtures exercise signed content transitions, never broker inception.
type controlFixture struct {
	now     time.Time
	id      cellspec.Identity
	private ed25519.PrivateKey
	genesis trust.Keyring
	chain   trust.RootChain
	before  RuntimeTrustFloor
	root    controlSource
	spec    controlSource
}

func newControlFixture(t *testing.T) controlFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	f := controlFixture{now: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		id:      cellspec.Identity{DeploymentID: "0000000000VVK5ZNRRNEED4PH3", Cell: "gru", Environment: "production"},
		private: private, genesis: genesis, chain: trust.RootChain{Version: 1}}
	wire, err := trust.EncodeRootChain(f.chain)
	if err != nil {
		t.Fatal(err)
	}
	f.root = controlSource{created: f.now.Add(-time.Hour), revision: 10, wire: wire}
	f.spec = controlSource{created: f.now.Add(-time.Minute), revision: 20, wire: f.signSpec(t, 1, f.now.Add(-2*time.Hour), private, genesis)}
	f.before = RuntimeTrustFloor{OperationID: "content-fixture", RootHead: trust.RootSetDigest(genesis), RootChainSHA256: brokerSourceDigest(wire),
		RootStreamCreated: f.root.created, RootRevision: f.root.revision, SpecStreamCreated: f.spec.created, UpdatedAt: f.now.Add(-time.Minute)}
	return f
}

func (f controlFixture) signSpec(t *testing.T, generation uint64, at time.Time, private ed25519.PrivateKey, roots trust.Keyring) []byte {
	t.Helper()
	wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: f.id, Generation: generation, RequiresBinary: 1}, nil, roots, at, time.Hour, private)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f controlFixture) rotate(t *testing.T, chain trust.RootChain, old ed25519.PrivateKey, at time.Time) (trust.RootChain, ed25519.PrivateKey, trust.VerifiedRoots) {
	t.Helper()
	id := trust.ChainIdentity{DeploymentID: f.id.DeploymentID, Environment: f.id.Environment, Cell: f.id.Cell}
	before, err := trust.VerifyRootChain(f.genesis, id, chain)
	if err != nil {
		t.Fatal(err)
	}
	public, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := trust.NextRotation(before, public)
	if err != nil {
		t.Fatal(err)
	}
	signed := trust.SignedRotation{}
	for _, signer := range []ed25519.PrivateKey{old, next} {
		envelope, err := trust.SignRotation(rotation, id, at, at.Add(time.Hour), signer)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signatures = append(signed.Signatures, envelope)
	}
	chain.Rotations = append(chain.Rotations, signed)
	after, err := trust.VerifyRootChain(f.genesis, id, chain)
	if err != nil {
		t.Fatal(err)
	}
	return chain, next, after
}

func (f controlFixture) rootSource(t *testing.T, chain trust.RootChain, revision uint64) controlSource {
	t.Helper()
	wire, err := trust.EncodeRootChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	return controlSource{created: f.root.created, revision: revision, wire: wire}
}

func TestControlAdoptionRequiresCurrentUnknownSpec(t *testing.T) {
	f := newControlFixture(t)
	if _, err := verifiedControlAdvance(f.before, f.root, f.spec, f.genesis, f.id, f.now); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("unknown expired spec: got %v, want expiry", err)
	}
	f.before.SpecGeneration, f.before.SpecSHA256, f.before.SpecRevision = 1, brokerSourceDigest(f.spec.wire), f.spec.revision
	for _, revision := range []uint64{f.spec.revision, f.spec.revision + 1} {
		source := f.spec
		source.revision = revision
		next, err := verifiedControlAdvance(f.before, f.root, source, f.genesis, f.id, f.now)
		if err != nil || next.SpecGeneration != 1 || next.SpecSHA256 != f.before.SpecSHA256 || next.SpecRevision != revision {
			t.Fatalf("exact adopted bytes at revision %d: next=%+v err=%v", revision, next, err)
		}
	}
	f.spec.wire = f.signSpec(t, 2, f.now, f.private, f.genesis)
	f.spec.revision++
	if next, err := verifiedControlAdvance(f.before, f.root, f.spec, f.genesis, f.id, f.now); err != nil || next.SpecGeneration != 2 {
		t.Fatalf("current next generation: next=%+v err=%v", next, err)
	}
}

func TestControlAdoptionRejectsSourceReplacementAndEquivocation(t *testing.T) {
	f := newControlFixture(t)
	f.spec.wire = f.signSpec(t, 1, f.now, f.private, f.genesis)
	f.before.SpecGeneration, f.before.SpecSHA256, f.before.SpecRevision = 1, brokerSourceDigest(f.spec.wire), f.spec.revision
	for name, change := range map[string]func(*RuntimeTrustFloor, *controlSource, *controlSource){
		"recreated roots":        func(_ *RuntimeTrustFloor, root, _ *controlSource) { root.created = root.created.Add(time.Second) },
		"recreated spec":         func(_ *RuntimeTrustFloor, _, spec *controlSource) { spec.created = spec.created.Add(time.Second) },
		"root revision rollback": func(_ *RuntimeTrustFloor, root, _ *controlSource) { root.revision-- },
		"spec revision rollback": func(_ *RuntimeTrustFloor, _, spec *controlSource) { spec.revision-- },
		"unpublished root":       func(before *RuntimeTrustFloor, _, _ *controlSource) { before.RootRevision = 0 },
		"missing spec":           func(_ *RuntimeTrustFloor, _, spec *controlSource) { spec.revision = 0 },
		"same generation changed wire": func(_ *RuntimeTrustFloor, _, spec *controlSource) {
			spec.wire = f.signSpec(t, 1, f.now.Add(time.Second), f.private, f.genesis)
			spec.revision++
		},
		"new generation same revision": func(_ *RuntimeTrustFloor, _, spec *controlSource) {
			spec.wire = f.signSpec(t, 2, f.now, f.private, f.genesis)
		},
	} {
		t.Run(name, func(t *testing.T) {
			before, root, spec := f.before, f.root, f.spec
			change(&before, &root, &spec)
			if _, err := verifiedControlAdvance(before, root, spec, f.genesis, f.id, f.now); err == nil {
				t.Fatal("replaced, missing or conflicting source was accepted")
			}
		})
	}
}

func TestControlAdoptionRequiresCurrentRootExtension(t *testing.T) {
	f := newControlFixture(t)
	f.before.SpecGeneration, f.before.SpecSHA256, f.before.SpecRevision = 1, brokerSourceDigest(f.spec.wire), f.spec.revision
	expired, _, _ := f.rotate(t, f.chain, f.private, f.now.Add(-2*time.Hour))
	if _, err := verifiedControlAdvance(f.before, f.rootSource(t, expired, 11), f.spec, f.genesis, f.id, f.now); !errors.Is(err, trust.ErrExpired) {
		t.Fatalf("unknown expired rotation: got %v, want expiry", err)
	}
	current, nextKey, roots := f.rotate(t, f.chain, f.private, f.now)
	root := f.rootSource(t, current, 11)
	if _, err := verifiedControlAdvance(f.before, f.rootSource(t, current, f.root.revision), f.spec, f.genesis, f.id, f.now); err == nil {
		t.Fatal("new rotation reused the protected source revision")
	}
	adopted, err := verifiedControlAdvance(f.before, root, f.spec, f.genesis, f.id, f.now)
	if err != nil || adopted.RootSequence != 1 {
		t.Fatalf("current rotation with adopted historical spec: next=%+v err=%v", adopted, err)
	}
	if _, err := verifiedControlAdvance(adopted, root, f.spec, f.genesis, f.id, f.now.Add(2*time.Hour)); err != nil {
		t.Fatalf("exact adopted historical rotation: %v", err)
	}
	fork, _, _ := f.rotate(t, f.chain, f.private, f.now)
	if _, err := verifiedControlAdvance(adopted, f.rootSource(t, fork, 12), f.spec, f.genesis, f.id, f.now); err == nil {
		t.Fatal("valid rival root chain replaced the protected prefix")
	}
	reordered := trust.RootChain{Version: 1, Rotations: []trust.SignedRotation{{Signatures: []trust.Envelope{
		current.Rotations[0].Signatures[1], current.Rotations[0].Signatures[0],
	}}}}
	if _, err := verifiedControlAdvance(adopted, f.rootSource(t, reordered, 12), f.spec, f.genesis, f.id, f.now); err == nil {
		t.Fatal("same signed root payload replaced the exact adopted wire prefix")
	}
	if _, err := verifiedControlAdvance(adopted, f.rootSource(t, f.chain, 12), f.spec, f.genesis, f.id, f.now); err == nil {
		t.Fatal("newer source revision rolled back root sequence")
	}
	spec := f.spec
	spec.revision++
	spec.wire = f.signSpec(t, 2, f.now, f.private, f.genesis)
	if _, err := verifiedControlAdvance(adopted, root, spec, f.genesis, f.id, f.now); !errors.Is(err, trust.ErrUntrustedKey) {
		t.Fatalf("new spec signed by replaced root: got %v", err)
	}
	spec.wire = f.signSpec(t, 2, f.now, nextKey, roots.Current)
	if next, err := verifiedControlAdvance(adopted, root, spec, f.genesis, f.id, f.now); err != nil || next.SpecGeneration != 2 {
		t.Fatalf("new spec signed by terminal root: next=%+v err=%v", next, err)
	}
}

func TestControlAdmissionRetainsEarliestNewWireExpiry(t *testing.T) {
	f := newControlFixture(t)
	if expiry, err := controlAdmissionExpiry(f.before, f.root, f.spec); err != nil || !expiry.Equal(f.now.Add(-time.Hour)) {
		t.Fatalf("unknown expired wire must retain its original cap: expiry=%s err=%v", expiry, err)
	}
	before := f.before
	before.SpecRevision, before.SpecSHA256 = f.spec.revision, brokerSourceDigest(f.spec.wire)
	if expiry, err := controlAdmissionExpiry(before, f.root, f.spec); err != nil || !expiry.IsZero() {
		t.Fatalf("already adopted history supplied a new current-signature cap: expiry=%s err=%v", expiry, err)
	}
	spec := f.spec
	spec.wire = f.signSpec(t, 2, f.now.Add(-30*time.Minute), f.private, f.genesis)
	for _, age := range []time.Duration{45 * time.Minute, 10 * time.Minute} {
		chain, _, _ := f.rotate(t, f.chain, f.private, f.now.Add(-age))
		root := f.rootSource(t, chain, f.root.revision+1)
		want := f.now.Add(min(time.Hour-age, 30*time.Minute))
		if expiry, err := controlAdmissionExpiry(f.before, root, spec); err != nil || !expiry.Equal(want) {
			t.Fatalf("rotation age %s: expiry=%s want=%s err=%v", age, expiry, want, err)
		}
	}
}
