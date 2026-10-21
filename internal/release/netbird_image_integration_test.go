package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestNetBirdImageCurrentCryptoBoundary(t *testing.T) {
	t.Run("dedicated image succeeds without orchestrator baseline", func(t *testing.T) {
		fixture := newNetBirdImageFixture(t)
		image, delegation := fixture.wires(t)
		verified, err := VerifyNetBirdImageCurrent(image, delegation, fixture.roots, fixture.expected, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		if !verified.IsVerified() || verified.Receipt().Production != nil ||
			verified.EnvelopeSHA256() != fingerprintWire(t, image) || !verified.ExpiresAt().Equal(fixture.qualificationExpires) {
			t.Fatal("NetBird admission lost exact wire, qualification deadline or independent purpose")
		}
		copy := verified.Receipt()
		proof := copy.HostProduction["netbird-manager"]
		proof.Qualification[0] ^= 1
		delete(copy.HostProduction, "netbird-manager")
		if verified.Receipt().HostProduction["netbird-manager"].Qualification[0] == proof.Qualification[0] {
			t.Fatal("caller mutated admitted qualification")
		}
		if _, err := VerifyImageCurrent(image, delegation, fixture.roots, fixture.expected, fixture.now); err == nil {
			t.Fatal("dedicated NetBird signature authorized ordinary orchestrator image")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*netBirdImageFixture)
	}{
		{"missing image pin", func(f *netBirdImageFixture) { f.expected.OCIImageOCID = "" }},
		{"different image pin", func(f *netBirdImageFixture) { f.expected.OCIImageOCID += "OTHER" }},
		{"missing architecture", func(f *netBirdImageFixture) { f.expected.Architecture = "" }},
		{"amd64 caller", func(f *netBirdImageFixture) { f.expected.Architecture = "amd64" }},
		{"different region", func(f *netBirdImageFixture) { f.expected.LogicalRegion = "FRA" }},
		{"invalid environment", func(f *netBirdImageFixture) { f.expected.Environment = "invalid" }},
		{"other environment", func(f *netBirdImageFixture) { f.expected.Environment = "production" }},
		{"different signed image", func(f *netBirdImageFixture) { f.receipt.OCIImageOCID += "OTHER" }},
		{"different signed architecture", func(f *netBirdImageFixture) { f.receipt.Architecture = "amd64" }},
		{"invalid receipt", func(f *netBirdImageFixture) { f.receipt.Schema = "obsolete" }},
		{"ordinary image signature", func(f *netBirdImageFixture) { f.imageScope = ImageScope(f.receipt, f.expected.Environment) }},
		{"ordinary image delegation", func(f *netBirdImageFixture) { f.imageCapability = ImageScope(f.receipt, f.expected.Environment) }},
		{"ordinary image authority", func(f *netBirdImageFixture) {
			f.imageScope = ImageScope(f.receipt, f.expected.Environment)
			f.imageCapability = f.imageScope
		}},
		{"different dedicated slot", func(f *netBirdImageFixture) { f.imageScope.Slot = "netbird-manager" }},
		{"qualification absent", func(f *netBirdImageFixture) { f.omitQualification = true }},
		{"qualification wrong map role", func(f *netBirdImageFixture) { f.proofRole = "manager" }},
		{"qualification other image", func(f *netBirdImageFixture) { f.qualification.Candidate.ArtifactSHA256 = strings.Repeat("a", 64) }},
		{"qualification other source", func(f *netBirdImageFixture) { f.qualification.Candidate.SourceRevision = strings.Repeat("b", 40) }},
		{"qualification other CI digest", func(f *netBirdImageFixture) { f.qualification.Candidate.QualificationSHA256 = strings.Repeat("c", 64) }},
		{"qualification other cell", func(f *netBirdImageFixture) { f.qualification.Candidate.Cell = "FRA" }},
		{"qualification other environment", func(f *netBirdImageFixture) { f.qualification.Candidate.Environment = "production" }},
		{"qualification other runtime", func(f *netBirdImageFixture) { f.qualification.Candidate.Runtime = ProductionRuntime }},
		{"qualification other architecture", func(f *netBirdImageFixture) { f.qualification.Candidate.Architecture = "amd64" }},
		{"qualification other role", func(f *netBirdImageFixture) { f.qualification.Candidate.Role = "orchestrator" }},
		{"qualification ordinary gates", func(f *netBirdImageFixture) {
			f.qualification.Evidence[0].Gate, f.qualification.Evidence[1].Gate = "runtime-ha", "workload-safety"
		}},
		{"qualification ordinary delegation", func(f *netBirdImageFixture) { f.qualificationCapability.Role = "orchestrator" }},
		{"qualification future", func(f *netBirdImageFixture) { f.qualificationIssued = f.now.Add(time.Minute) }},
		{"image future", func(f *netBirdImageFixture) { f.imageIssued = f.now.Add(5 * time.Minute) }},
		{"image delegation future", func(f *netBirdImageFixture) { f.imageDelegationIssued = f.now.Add(5 * time.Minute) }},
		{"qualification delegation future", func(f *netBirdImageFixture) { f.qualificationDelegationIssued = f.now.Add(time.Minute) }},
		{"image expired", func(f *netBirdImageFixture) { f.imageExpires = f.now }},
		{"image delegation expired", func(f *netBirdImageFixture) { f.imageDelegationExpires = f.now }},
		{"qualification expired", func(f *netBirdImageFixture) { f.qualificationExpires = f.now }},
		{"qualification delegation expired", func(f *netBirdImageFixture) { f.qualificationDelegationExpires = f.now }},
		{"noncanonical image payload", func(f *netBirdImageFixture) { f.noncanonical = true }},
		{"untrusted root", func(f *netBirdImageFixture) { f.roots = trust.Keyring{} }},
		{"image signed by qualification key", func(f *netBirdImageFixture) { f.imagePrivate = f.qualificationPrivate }},
		{"qualification signed by image key", func(f *netBirdImageFixture) { f.qualificationPrivate = f.imagePrivate }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNetBirdImageFixture(t)
			test.mutate(&fixture)
			image, delegation := fixture.wires(t)
			verified, err := VerifyNetBirdImageCurrent(image, delegation, fixture.roots, fixture.expected, fixture.now)
			if err == nil || verified.IsVerified() {
				t.Fatalf("invalid NetBird authority admitted: %+v, %v", verified, err)
			}
		})
	}
}

func TestNetBirdImageCurrentAuthorityDeadlines(t *testing.T) {
	for _, authority := range []string{"image", "image delegation", "qualification", "qualification delegation", "root qualification"} {
		t.Run(authority, func(t *testing.T) {
			fixture := newNetBirdImageFixture(t)
			deadline := fixture.now.Add(5 * time.Minute)
			switch authority {
			case "image":
				fixture.imageExpires = deadline
			case "image delegation":
				fixture.imageExpires, fixture.imageDelegationExpires = deadline, deadline
			case "qualification":
				fixture.qualificationExpires = deadline
			case "qualification delegation":
				fixture.qualificationExpires, fixture.qualificationDelegationExpires = deadline, deadline
			case "root qualification":
				fixture.rootQualification, fixture.qualificationExpires = true, deadline
			}
			image, delegation := fixture.wires(t)
			verified, err := VerifyNetBirdImageCurrent(image, delegation, fixture.roots, fixture.expected, fixture.now)
			if err != nil || !verified.ExpiresAt().Equal(deadline) {
				t.Fatalf("authority deadline = %s, %v; want %s", verified.ExpiresAt(), err, deadline)
			}
			if _, err := VerifyNetBirdImageCurrent(image, delegation, fixture.roots, fixture.expected, deadline); err == nil {
				t.Fatal("expired authority admitted at exact deadline")
			}
		})
	}
}

type netBirdImageFixture struct {
	roots                                                                     trust.Keyring
	rootPrivate, imagePrivate, qualificationPrivate                           ed25519.PrivateKey
	imagePublic, qualificationPublic                                          ed25519.PublicKey
	receipt                                                                   ImageReceipt
	expected                                                                  ImageExpectation
	qualification                                                             ProductionQualification
	imageScope, imageCapability, qualificationCapability                      trust.Scope
	now, imageIssued, imageExpires, qualificationIssued, qualificationExpires time.Time
	imageDelegationIssued, imageDelegationExpires                             time.Time
	qualificationDelegationIssued, qualificationDelegationExpires             time.Time
	proofRole                                                                 string
	omitQualification, noncanonical, rootQualification                        bool
}

func newNetBirdImageFixture(t *testing.T) netBirdImageFixture {
	t.Helper()
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, private
	}
	rootPublic, rootPrivate := key()
	imagePublic, imagePrivate := key()
	qualificationPublic, qualificationPrivate := key()
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	receipt := testImageReceipt()
	receipt.Architecture = "arm64"
	qualification := ProductionQualification{Schema: ProductionQualificationSchema,
		Candidate: ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
			QualificationSHA256: receipt.QualificationSHA256, Cell: "GRU", Environment: "canary",
			Runtime: NetBirdProductionRuntime, Architecture: "arm64", Role: "netbird-manager"}}
	for _, gate := range []string{"netbird-foundation", "netbird-recovery"} {
		evidence := []byte("test-only NetBird " + gate)
		qualification.Evidence = append(qualification.Evidence, ProductionGateEvidence{
			Gate: gate, SHA256: fingerprintWire(t, evidence), Bytes: int64(len(evidence)), CompletedAt: now.Add(-time.Minute)})
	}
	return netBirdImageFixture{roots: roots, rootPrivate: rootPrivate, imagePrivate: imagePrivate,
		qualificationPrivate: qualificationPrivate, imagePublic: imagePublic, qualificationPublic: qualificationPublic,
		receipt: receipt, qualification: qualification,
		expected:   ImageExpectation{Environment: "canary", LogicalRegion: "GRU", OCIImageOCID: receipt.OCIImageOCID, Architecture: "arm64"},
		imageScope: NetBirdImageScope(receipt, "canary"), imageCapability: NetBirdImageScope(receipt, "canary"),
		qualificationCapability: ProductionQualificationScope(qualification.Candidate), proofRole: "netbird-manager",
		now: now, imageIssued: now.Add(-time.Second), imageExpires: now.Add(20 * time.Minute),
		qualificationIssued: now.Add(-time.Second), qualificationExpires: now.Add(15 * time.Minute),
		imageDelegationIssued: now.Add(-time.Hour), imageDelegationExpires: now.Add(time.Hour),
		qualificationDelegationIssued: now.Add(-time.Hour), qualificationDelegationExpires: now.Add(time.Hour)}
}

func (f netBirdImageFixture) wires(t *testing.T) ([]byte, []byte) {
	t.Helper()
	delegation := func(public ed25519.PublicKey, scope trust.Scope, issued, expires time.Time) []byte {
		keyID, err := trust.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		encodedPublic, err := trust.EncodeDelegatedPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
			SubjectKeyID: keyID, SubjectPublicKey: encodedPublic, Capabilities: []trust.Capability{{
				Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
				Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, issued, expires, f.rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return encodeEnvelope(t, envelope)
	}
	if !f.omitQualification {
		proofDelegation := delegation(f.qualificationPublic, f.qualificationCapability,
			f.qualificationDelegationIssued, f.qualificationDelegationExpires)
		qualificationKey := f.qualificationPrivate
		if f.rootQualification {
			qualificationKey, proofDelegation = f.rootPrivate, nil
		}
		proof := signDirect(t, f.qualification, ProductionQualificationScope(f.qualification.Candidate),
			qualificationKey, f.qualificationIssued, f.qualificationExpires)
		f.receipt.HostProduction = map[string]ProductionProof{f.proofRole: {Qualification: encodeEnvelope(t, proof), Delegation: proofDelegation}}
	}
	payload, err := trust.EncodePayload(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	if f.noncanonical {
		payload = append(payload, ' ')
	}
	envelope, err := trust.Sign(payload, f.imageScope, f.imageIssued, f.imageExpires, f.imagePrivate)
	if err != nil {
		t.Fatal(err)
	}
	return encodeEnvelope(t, envelope), delegation(f.imagePublic, f.imageCapability, f.imageDelegationIssued, f.imageDelegationExpires)
}
