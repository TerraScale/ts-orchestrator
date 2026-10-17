package principal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestSDKCleanupObserverFreezesOriginalIssuer(t *testing.T) {
	f, _ := readerFixture(t)
	if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err != nil {
		t.Fatal(err)
	}
	rotating := &rotatingIssuer{ConfigurationProvider: f.producer.issuer.Provider()}
	factory, err := ociclient.New(rotating, ociclient.Options{Region: f.prep.IAMRegion})
	if err != nil {
		t.Fatal(err)
	}
	f.producer.issuer = factory
	observer, err := f.producer.CleanupObserver(t.Context(), f.verified, f.dir)
	if err != nil {
		t.Fatal(err)
	}
	client, err := observer.Identity()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&client.BaseClient, f.server.URL)
	if _, err := client.GetTenancy(t.Context(), identity.GetTenancyRequest{TenancyId: new(f.prep.Tenancy)}); err != nil {
		t.Fatal("frozen observer changed original authenticated issuer", err)
	}
	if rotating.calls.Load() != 1 {
		t.Fatal("observer reread refreshable issuer after exact freeze")
	}
	f.mu.Lock()
	requests := f.requests
	f.mu.Unlock()
	if _, err := f.producer.CleanupObserver(t.Context(), f.verified, f.dir); err == nil {
		t.Fatal("mismatched refreshed issuer admitted for cleanup observations")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != requests {
		t.Fatal("mismatched refreshed issuer reached SDK")
	}
}

func readerFixture(t *testing.T) (*sdkFixture, []byte) {
	t.Helper()
	f := newFixture(t)
	p := &f.prep
	p.Purpose, p.Candidate.Role = qualification.RootCredentialBoundaryPurpose, release.FoundationWriterRole
	p.ArtifactDisposition, p.ReaderIAMAuthority, p.ImagePublicationBucket = qualification.RetainTestedImage, qualification.ExactHostReaders, "gru-1-head"
	p.ImageRetainUntil, p.ImageTransferUntil = f.now().Add(50*time.Minute), f.now().Add(45*time.Minute)
	p.ExpiresAt, p.CleanupUntil = f.now().Add(55*time.Minute), f.now().Add(90*time.Minute)
	p.MaterialFixtures = nil
	p.PolicyTemplate = RequiredTemplate(*p)
	f.verified = f.verify(*p)
	a := qualification.Approval{Purpose: p.Purpose, ArtifactDisposition: p.ArtifactDisposition, ReaderIAMAuthority: p.ReaderIAMAuthority, ImagePublicationBucket: p.ImagePublicationBucket, ImageRetainUntil: p.ImageRetainUntil, ImageTransferUntil: p.ImageTransferUntil, Schema: "terrascale.test.image-qualification.v1", RunID: p.RunID, Candidate: p.Candidate, Tenancy: p.Tenancy, Compartment: p.Compartment, Subnet: p.Subnet, Namespace: p.Namespace, Bucket: p.Bucket, OCIRegion: p.OCIRegion, IAMRegion: p.IAMRegion, RunnerCIDR: p.RunnerCIDR, PeerCIDR: p.PeerCIDR, VCNCIDR: p.VCNCIDR, BinarySHA256: p.BinarySHA256, KernelSHA256: p.KernelSHA256, KernelRelease: p.KernelRelease, ContainerdSHA256: p.ContainerdSHA256, RuncSHA256: p.RuncSHA256, RunnerSHA256: p.RunnerSHA256, MaxSpendMicros: p.MaxSpendMicros, ImageBytes: p.ImageBytes, Hosts: p.Hosts, CleanupUntil: p.CleanupUntil}
	scope := qualification.Scope(p.RunID, p.Candidate, "disposable-host")
	sign := func(body any) []byte {
		payload, err := json.Marshal(body, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		e, err := trust.Sign(payload, scope, f.now(), p.ImageRetainUntil, f.root)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	approval := sign(a)
	b := hostadmission.Binding{Schema: hostadmission.BindingSchema, Purpose: p.Purpose, RunID: p.RunID, PreparationSHA256: f.verified.digest, ApprovalSHA256: hash(approval), HostName: p.Hosts[0].Name}
	for i, spec := range p.Hosts {
		b.Hosts = append(b.Hosts, hostadmission.BoundHost{Name: spec.Name, InstanceID: fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.host%d", i), ImageID: "ocid1.image.oc1.sa-saopaulo-1.tested", PrivateIP: fmt.Sprintf("10.72.1.%d", i+2)})
	}
	wire, err := json.Marshal(hostadmission.Proof{Schema: hostadmission.ProofSchema, Preparation: f.verified.wire, Approval: approval, Binding: sign(b)}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return f, wire
}

func TestSDKExactReaderIAMRestartDriftExpiryAndCleanup(t *testing.T) {
	f, proof := readerFixture(t)
	if _, err := f.producer.Prepare(t.Context(), f.verified, f.dir); err != nil {
		t.Fatal(err)
	}
	plan, err := hostadmission.VerifyReaderPlan(proof, f.roots, f.now())
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.producer.PrepareReaders(t.Context(), f.verified, f.dir, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(f.verified, plan, f.now()); err != nil {
		t.Fatal(err)
	}
	second, err := f.producer.PrepareReaders(t.Context(), f.verified, f.dir, proof)
	if err != nil || first.IAM() != second.IAM() || f.creates["reader-group"] != 1 || f.creates["reader-policy"] != 1 {
		t.Fatalf("exact durable reader retry changed resources: %v", err)
	}
	group := f.resources[first.IAM().DynamicGroupID].(identity.DynamicGroup)
	drift := group
	drift.MatchingRule = new("ALL {instance.compartment.id = 'ocid1.compartment.oc1..production'}")
	f.resources[first.IAM().DynamicGroupID] = drift
	if _, err := f.producer.PrepareReaders(t.Context(), f.verified, f.dir, proof); err == nil {
		t.Fatal("changed instance principal group accepted")
	}
	f.resources[first.IAM().DynamicGroupID] = group
	f.advance(51 * time.Minute)
	if _, err := f.producer.PrepareReaders(t.Context(), f.verified, f.dir, proof); err == nil {
		t.Fatal("expired original read IAM plan renewed")
	}
	writes := len(f.writes)
	resumed, err := f.producer.ResumeForCleanup(t.Context(), f.verified, f.dir)
	if err != nil || !resumed.Prepared() || len(f.writes) != writes {
		t.Fatalf("cleanup resume recreated or failed to authenticate existing principal: %v", err)
	}
	if err := f.producer.CleanupReaders(t.Context(), f.verified, f.dir); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.resources[first.IAM().DynamicGroupID]; exists {
		t.Fatal("read instance group survived bounded cleanup")
	}
	if _, exists := f.resources[first.IAM().PolicyID]; exists {
		t.Fatal("read policy survived bounded cleanup")
	}
	if _, err := f.producer.Cleanup(t.Context(), f.verified, f.dir); err != nil {
		t.Fatal(err)
	}
}

func TestReaderIAMRequiresOriginalSignerPlanBeforeWrites(t *testing.T) {
	f, wire := readerFixture(t)
	var proof hostadmission.Proof
	if err := json.Unmarshal(wire, &proof); err != nil {
		t.Fatal(err)
	}
	bound, err := trust.DecodeEnvelope(proof.Binding)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := trust.Sign(bound.Payload, bound.Scope, bound.IssuedAt, bound.ExpiresAt, other)
	if err != nil {
		t.Fatal(err)
	}
	proof.Binding, err = trust.EncodeEnvelope(foreign)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.producer.PrepareReaders(t.Context(), f.verified, f.dir, wire); err == nil || len(f.writes) != 0 {
		t.Fatal("foreign signer produced instance IAM writes")
	}
}
