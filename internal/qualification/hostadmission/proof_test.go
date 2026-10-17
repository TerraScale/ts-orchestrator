package hostadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type proofFixture struct {
	now        time.Time
	roots      trust.Keyring
	root, leaf ed25519.PrivateKey
	a          qualification.Approval
	p          qualification.Preparation
	b          Binding
}

func newProofFixture(t *testing.T) proofFixture {
	t.Helper()
	pub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(pub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 17, 4, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	c := release.ProductionExpectation{Role: release.FoundationWriterRole, Runtime: release.ProductionRuntime, Architecture: "arm64", Cell: "GRU", Environment: "production", SourceRevision: strings.Repeat("b", 40), ArtifactSHA256: digest, QualificationSHA256: digest}
	a := qualification.Approval{Schema: "terrascale.test.image-qualification.v1", Purpose: qualification.RootCredentialBoundaryPurpose, RunID: "reader1", Candidate: c,
		Tenancy: "ocid1.tenancy.oc1..test", Compartment: "ocid1.compartment.oc1..test", Subnet: "ocid1.subnet.oc1.sa-saopaulo-1.test", Namespace: "namespace", Bucket: "bucket", OCIRegion: "sa-saopaulo-1", IAMRegion: "sa-saopaulo-1",
		PeerCIDR: "10.70.1.0/24", RunnerCIDR: "10.70.2.0/24", VCNCIDR: "10.70.0.0/16", BinarySHA256: digest, KernelSHA256: digest, ContainerdSHA256: digest, RuncSHA256: digest, RunnerSHA256: digest, KernelRelease: "kernel", MaxSpendMicros: 10, ImageBytes: 8, CleanupUntil: now.Add(2 * time.Hour)}
	b := Binding{Schema: BindingSchema, Purpose: a.Purpose, RunID: a.RunID, HostName: "host0"}
	for i := range 4 {
		role := "manager"
		if i == 3 {
			role = "worker"
		}
		name := fmt.Sprintf("host%d", i)
		a.Hosts = append(a.Hosts, qualification.HostSpec{Name: name, Role: role, Shape: "VM.Standard.A1.Flex", AvailabilityDomain: "ad", FaultDomain: fmt.Sprintf("fd%d", i), OCPUs: 1, MemoryGB: 6, BootGB: 50})
		b.Hosts = append(b.Hosts, BoundHost{Name: name, InstanceID: fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.host%d", i), ImageID: "ocid1.image.oc1.sa-saopaulo-1.candidate", PrivateIP: fmt.Sprintf("10.70.1.%d", i+2)})
	}
	p := qualification.Preparation{Schema: "terrascale.test.image-qualification.principal.v1", Purpose: a.Purpose, RunID: a.RunID, Candidate: c, Tenancy: a.Tenancy, Compartment: a.Compartment, Subnet: a.Subnet, Namespace: a.Namespace, Bucket: a.Bucket, OCIRegion: a.OCIRegion, IAMRegion: a.IAMRegion, PeerCIDR: a.PeerCIDR, RunnerCIDR: a.RunnerCIDR, VCNCIDR: a.VCNCIDR, BinarySHA256: digest, KernelSHA256: digest, ContainerdSHA256: digest, RuncSHA256: digest, RunnerSHA256: digest, KernelRelease: a.KernelRelease, MaxSpendMicros: a.MaxSpendMicros, ImageBytes: a.ImageBytes, Hosts: a.Hosts, ExpiresAt: now.Add(time.Hour), CleanupUntil: a.CleanupUntil}
	return proofFixture{now: now, roots: roots, root: root, leaf: leaf, a: a, p: p, b: b}
}
func (f proofFixture) wire(t *testing.T, slot string, changeBinding func(*Binding), differentSigner bool) []byte {
	t.Helper()
	scope := qualification.Scope(f.a.RunID, f.a.Candidate, "disposable-host")
	signer := f.root
	var delegation []byte
	if slot != "" {
		signer = f.leaf
		pub := signer.Public().(ed25519.PublicKey)
		id, _ := trust.KeyID(pub)
		encoded, _ := trust.EncodeDelegatedPublicKey(pub)
		var caps []trust.Capability
		for _, role := range []string{"disposable-host", "disposable-principal"} {
			caps = append(caps, trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: role, Slots: []string{slot}, Actions: []string{"sign"}})
		}
		de, err := trust.SignDelegation(trust.Delegation{SchemaVersion: 1, SubjectKeyID: id, SubjectPublicKey: encoded, Capabilities: caps}, f.now.Add(-time.Minute), f.a.CleanupUntil, f.root)
		if err != nil {
			t.Fatal(err)
		}
		delegation, err = trust.EncodeEnvelope(de)
		if err != nil {
			t.Fatal(err)
		}
	}
	sign := func(value any, s trust.Scope, expiry time.Time, key ed25519.PrivateKey) []byte {
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		e, err := trust.Sign(payload, s, f.now, expiry, key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	approval := sign(f.a, scope, f.p.ExpiresAt, signer)
	ps := scope
	ps.Role = "disposable-principal"
	preparation := sign(f.p, ps, f.p.CleanupUntil, signer)
	b := f.b
	b.PreparationSHA256 = fingerprint(preparation)
	b.ApprovalSHA256 = fingerprint(approval)
	if changeBinding != nil {
		changeBinding(&b)
	}
	bindingSigner := signer
	if differentSigner {
		bindingSigner = f.leaf
	}
	binding := sign(b, scope, f.p.ExpiresAt, bindingSigner)
	wire, err := json.Marshal(Proof{Schema: ProofSchema, Approval: approval, Preparation: preparation, Delegation: delegation, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestFiniteReaderRequiresExplicitPurposeAndOriginalAttenuation(t *testing.T) {
	f := newProofFixture(t)
	scope := qualification.Scope(f.a.RunID, f.a.Candidate, "disposable-host")
	for _, slot := range []string{"", scope.Slot} {
		if _, err := verifyProof(f.wire(t, slot, nil, false), f.roots, f.now.Add(time.Minute)); err != nil {
			t.Fatalf("genuine original authority: %v", err)
		}
	}
	oldSlot := f.a.Candidate.Runtime + "/linux-" + f.a.Candidate.Architecture
	if _, err := verifyProof(f.wire(t, oldSlot, nil, false), f.roots, f.now.Add(time.Minute)); err == nil {
		t.Fatal("generic original delegation admitted privileged reader")
	}
	for name, change := range map[string]func(*Binding){"wrong purpose": func(b *Binding) { b.Purpose = "native-runtime-ha" }, "foreign host": func(b *Binding) { b.HostName = "other" }, "other approval": func(b *Binding) { b.ApprovalSHA256 = strings.Repeat("d", 64) }, "mixed image": func(b *Binding) {
		b.Hosts = append([]BoundHost(nil), b.Hosts...)
		b.Hosts[1].ImageID = "ocid1.image.oc1.sa-saopaulo-1.other"
	}} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyProof(f.wire(t, "", change, false), f.roots, f.now.Add(time.Minute)); err == nil {
				t.Fatal("changed signed attenuation accepted")
			}
		})
	}
	if _, err := verifyProof(f.wire(t, "", nil, true), f.roots, f.now.Add(time.Minute)); err == nil {
		t.Fatal("replacement signer accepted")
	}
	if _, err := verifyProof(f.wire(t, "", nil, false), f.roots, f.p.ExpiresAt); err == nil {
		t.Fatal("expired admission accepted")
	}
	f.a.Purpose = ""
	f.p.Purpose = ""
	if _, err := verifyProof(f.wire(t, "", nil, false), f.roots, f.now.Add(time.Minute)); err == nil {
		t.Fatal("purpose omitted accepted")
	}
}

func TestZeroStartupReaderCannotAuthorize(t *testing.T) {
	var reader StartupReader
	if reader.Guard(t.Context()) == nil || !reader.ExpiresAt().IsZero() || reader.BindingSHA256() != "" {
		t.Fatal("zero reader obtained authority")
	}
}
