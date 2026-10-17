package releasechannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Real independent Ed25519 authorities and the OCI SDK cross a loopback HTTP
// endpoint. This establishes source admission behavior, not native OCI safety.
func TestFoundationWriterImagePurposeSDK(t *testing.T) {
	location, backend := functionObjectEndpoint(t)
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			f := newWriterImageFixture(t, architecture)
			wire, delegation := f.wires(t)
			f.retain(backend)
			expected := CurrentImageExpectation{Cell: "GRU", Environment: "production", Architecture: architecture, Role: release.FoundationWriterRole}
			if err := PublishCurrentImage(t.Context(), location, wire, delegation, f.roots, expected, f.now); err != nil {
				t.Fatal(err)
			}
			current, found, err := ReadCurrentImage(t.Context(), location, f.roots, expected, f.now)
			if err != nil || !found {
				t.Fatalf("read dedicated purpose: found=%v err=%v", found, err)
			}
			if err := current.FoundationWriter.ValidFor(f.expected(), f.now); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(current.ReceiptWire, wire) || !current.ExpiresAt.Equal(f.qualificationExpiry) {
				t.Fatal("reader lost exact signed bytes or shortest qualification deadline")
			}
			if err := current.FoundationWriter.ValidFor(f.expected(), current.ExpiresAt); err == nil {
				t.Fatal("opaque proof survived exact expiry")
			}
			if _, _, err := ReadCurrentImage(t.Context(), location, f.roots, expected, current.ExpiresAt); err == nil {
				t.Fatal("current reader admitted expired purpose authority")
			}
			wrong := f.expected()
			wrong.OCIImageOCID += "other"
			if err := current.FoundationWriter.ValidFor(wrong, f.now); err == nil {
				t.Fatal("opaque proof authorized another image")
			}
			if err := current.FoundationWriter.ValidFor(f.expected(), f.now.Add(-time.Second)); err == nil {
				t.Fatal("opaque proof authorized a backdated operation")
			}
			for _, missing := range []string{"image", "architecture", "role"} {
				input := release.HostImageQualification{Receipt: wire, Delegation: delegation, Expected: f.expected(), Role: "manager"}
				switch missing {
				case "image":
					input.Expected.OCIImageOCID = ""
				case "architecture":
					input.Expected.Architecture = ""
				case "role":
					input.Role = "container"
				}
				if _, err := release.VerifyFoundationWriterImageCurrent(t.Context(), input, f.roots, func(ctx context.Context, digest string) (io.ReadCloser, error) {
					return OpenImageProductionEvidence(ctx, location, digest)
				}, f.now); err == nil {
					t.Fatalf("writer admitted missing exact %s pin", missing)
				}
			}
			copy := current.FoundationWriter.Image().Receipt()
			proof := copy.HostProduction[release.FoundationWriterRole]
			proof.Qualification[0] ^= 1
			if bytes.Equal(proof.Qualification, current.FoundationWriter.Image().Receipt().HostProduction[release.FoundationWriterRole].Qualification) {
				t.Fatal("caller mutated opaque proof authority")
			}
			// A reader must reopen retained bytes instead of trusting locator or receipt alone.
			backend.mu.Lock()
			object := ImageProductionEvidenceObject(f.qualification.Evidence[2].SHA256)
			backend.objects[object] = functionObject{data: []byte("changed retained root boundary"), version: 1}
			backend.mu.Unlock()
			if _, _, err := ReadCurrentImage(t.Context(), location, f.roots, expected, f.now); err == nil {
				t.Fatal("current reader admitted changed retained evidence")
			}
		})
	}
	if err := (release.VerifiedFoundationWriterImage{}).ValidFor(release.ImageExpectation{}, time.Now().UTC()); err == nil {
		t.Fatal("zero opaque proof authorized a writer")
	}
}

func TestFoundationWriterImageRejectsOtherAuthority(t *testing.T) {
	location, backend := functionObjectEndpoint(t)
	for _, scenario := range []struct {
		name   string
		change func(*writerImageFixture)
	}{
		{"v1 schema", func(f *writerImageFixture) { f.qualification.Schema = release.ProductionQualificationSchema }},
		{"generic two gates", func(f *writerImageFixture) { f.qualification.Evidence = f.qualification.Evidence[:2] }},
		{"generic role", func(f *writerImageFixture) { f.qualification.Candidate.Role = "orchestrator" }},
		{"wrong disk", func(f *writerImageFixture) { f.qualification.Candidate.ArtifactSHA256 = strings.Repeat("d", 64) }},
		{"wrong source", func(f *writerImageFixture) { f.qualification.Candidate.SourceRevision = strings.Repeat("d", 40) }},
		{"wrong CI", func(f *writerImageFixture) { f.qualification.Candidate.QualificationSHA256 = strings.Repeat("d", 64) }},
		{"wrong architecture", func(f *writerImageFixture) { f.qualification.Candidate.Architecture = "arm64" }},
		{"wrong region", func(f *writerImageFixture) { f.qualification.Candidate.Cell = "SFO" }},
		{"wrong environment", func(f *writerImageFixture) { f.qualification.Candidate.Environment = "canary" }},
		{"wrong runtime", func(f *writerImageFixture) { f.qualification.Candidate.Runtime = release.NetBirdProductionRuntime }},
		{"wrong gate order", func(f *writerImageFixture) {
			f.qualification.Evidence[0], f.qualification.Evidence[2] = f.qualification.Evidence[2], f.qualification.Evidence[0]
		}},
		{"duplicate gate", func(f *writerImageFixture) { f.qualification.Evidence[2] = f.qualification.Evidence[1] }},
		{"release signer lacks qualification", func(f *writerImageFixture) { f.qualifier = f.imageSigner }},
		{"ordinary qualification delegation", func(f *writerImageFixture) { f.qualificationCapability.Role = "orchestrator" }},
		{"expired proof", func(f *writerImageFixture) { f.qualificationExpiry = f.now }},
		{"future proof", func(f *writerImageFixture) { f.qualificationIssued = f.now.Add(time.Minute) }},
		{"expired delegation", func(f *writerImageFixture) { f.qualifierExpiry = f.now }},
		{"expired image delegation", func(f *writerImageFixture) { f.imageDelegationExpiry = f.now }},
		{"overlong proof", func(f *writerImageFixture) {
			f.qualificationExpiry = f.qualificationIssued.Add(release.MaxUpdateReceiptLifetime + time.Second)
		}},
		{"root not UID zero", func(f *writerImageFixture) { f.boundary.Hosts[0].RootUID = 42 }},
		{"ordinary UID zero", func(f *writerImageFixture) { f.boundary.Hosts[0].OrdinaryUID = 0 }},
		{"root OCI read unavailable", func(f *writerImageFixture) { f.boundary.Hosts[0].RootOCIRead = "unavailable" }},
		{"ordinary IMDS allowed", func(f *writerImageFixture) { f.boundary.Hosts[0].OrdinaryUIDIMDS = "allowed" }},
		{"ordinary signing allowed", func(f *writerImageFixture) { f.boundary.Hosts[0].OrdinaryUIDSigning = "allowed" }},
		{"IPC absent is not refusal", func(f *writerImageFixture) { f.boundary.Hosts[0].UnauthorizedIPC = "absent" }},
		{"different installed source", func(f *writerImageFixture) { f.boundary.Hosts[0].SourceRevision = strings.Repeat("d", 40) }},
		{"different tested image", func(f *writerImageFixture) { f.boundary.Hosts[0].ImageOCID += "other" }},
		{"different boundary candidate", func(f *writerImageFixture) { f.boundary.Candidate.ArtifactSHA256 = strings.Repeat("d", 64) }},
		{"missing namespace observation", func(f *writerImageFixture) { f.boundary.Hosts[0].NamespaceSHA256 = "" }},
		{"changed transcript", func(f *writerImageFixture) { f.boundary.Hosts[0].Transcript = []byte("changed transcript") }},
		{"duplicate host", func(f *writerImageFixture) { f.boundary.Hosts[1].InstanceID = f.boundary.Hosts[0].InstanceID }},
		{"incomplete native topology", func(f *writerImageFixture) { f.boundary.Hosts = f.boundary.Hosts[:3] }},
		{"different completion time", func(f *writerImageFixture) { f.boundary.CompletedAt = f.boundary.CompletedAt.Add(time.Second) }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newWriterImageFixture(t, "amd64")
			scenario.change(&f)
			wire, delegation := f.wires(t)
			f.retain(backend)
			input := release.HostImageQualification{Receipt: wire, Delegation: delegation, Expected: f.expected(), Role: "manager"}
			proof, err := release.VerifyFoundationWriterImageCurrent(t.Context(), input, f.roots, func(ctx context.Context, digest string) (io.ReadCloser, error) {
				return OpenImageProductionEvidence(ctx, location, digest)
			}, f.now)
			if err == nil || proof.ValidFor(f.expected(), f.now) == nil {
				t.Fatalf("unqualified writer admitted: %v", err)
			}
			expected := CurrentImageExpectation{Cell: "GRU", Environment: "production", Architecture: "amd64", Role: release.FoundationWriterRole}
			if err := PublishCurrentImage(t.Context(), location, wire, delegation, f.roots, expected, f.now); err == nil {
				t.Fatal("publisher admitted unqualified writer image")
			}
		})
	}
}

func TestFoundationWriterImageLegacyRemainsHistorical(t *testing.T) {
	f := newWriterImageFixture(t, "amd64")
	wire, delegation := f.wires(t)
	// Removing only the new purpose leaves the ordinary v1 image proof intact.
	f.receipt.HostProduction = nil
	envelope := f.sign(t, f.receipt, release.ImageScope(f.receipt, "production"), f.imageSigner, f.now, f.now.Add(time.Hour))
	wire = f.encode(t, envelope)
	if _, err := release.VerifyImageCurrent(wire, delegation, f.roots, f.expected(), f.now); err != nil {
		t.Fatalf("original v1 use changed: %v", err)
	}
	if _, err := release.VerifyImageHistorical(wire, delegation, f.roots, f.expected()); err != nil {
		t.Fatalf("historical verification changed: %v", err)
	}
	if _, err := release.VerifyFoundationWriterImageCurrent(t.Context(), release.HostImageQualification{
		Receipt: wire, Delegation: delegation, Expected: f.expected(), Role: "manager",
	}, f.roots, func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("test-only baseline")), nil
	}, f.now); err == nil {
		t.Fatal("v1 generic image authorized privileged writer")
	}
}

type writerImageFixture struct {
	root, imageSigner, qualifier, delegatedQualifier                                      ed25519.PrivateKey
	roots                                                                                 trust.Keyring
	receipt                                                                               release.ImageReceipt
	qualification                                                                         release.ProductionQualification
	boundary                                                                              release.RootCredentialBoundaryEvidence
	qualificationCapability                                                               trust.Scope
	objects                                                                               map[string][]byte
	now, qualificationIssued, qualificationExpiry, qualifierExpiry, imageDelegationExpiry time.Time
}

func newWriterImageFixture(t *testing.T, architecture string) writerImageFixture {
	t.Helper()
	key := func() ed25519.PrivateKey {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return private
	}
	f := writerImageFixture{root: key(), imageSigner: key(), qualifier: key(), objects: make(map[string][]byte)}
	f.delegatedQualifier = f.qualifier
	f.roots, _ = trust.ParseKeyring(f.root.Public().(ed25519.PublicKey))
	f.now = time.Now().UTC().Truncate(time.Second)
	f.qualificationIssued, f.qualificationExpiry = f.now.Add(-time.Second), f.now.Add(10*time.Minute)
	f.qualifierExpiry, f.imageDelegationExpiry = f.now.Add(30*time.Minute), f.now.Add(time.Hour)
	digest := strings.Repeat("a", 64)
	f.receipt = release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("b", 40), GoVersion: release.DefaultGoVersion,
		Architecture: architecture, BinaryBytes: 20, BinarySHA256: digest, QualificationSHA256: digest,
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.BASE", BaseImageRegion: "GRU", BaseImageSHA256: digest,
		KernelRelease: "6.1.0-test", KernelSHA256: digest, ImageFormat: "qcow2", ImageBytes: 1024, ImageSHA256: digest,
		OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.FINAL", OCIRegion: "GRU"}
	candidate := release.ProductionExpectation{SourceRevision: f.receipt.SourceRevision, ArtifactSHA256: digest, QualificationSHA256: digest,
		Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: architecture, Role: release.FoundationWriterRole}
	f.qualification = release.ProductionQualification{Schema: release.FoundationWriterQualificationSchema, Candidate: candidate}
	for _, gate := range []string{"runtime-ha", "workload-safety", release.RootCredentialBoundaryGate} {
		data := []byte("test-only baseline")
		hash := writerDigest(data)
		f.objects[hash] = data
		f.qualification.Evidence = append(f.qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: hash, Bytes: int64(len(data)), CompletedAt: f.now.Add(-time.Second)})
	}
	f.qualificationCapability = release.ProductionQualificationScope(candidate)
	f.boundary = release.RootCredentialBoundaryEvidence{Schema: release.RootCredentialBoundarySchema, Candidate: candidate, CompletedAt: f.now.Add(-time.Second)}
	for index, role := range []string{"manager", "manager", "manager", "container"} {
		transcript := []byte(fmt.Sprintf("test-only native boundary transcript %d", index))
		f.boundary.Hosts = append(f.boundary.Hosts, release.RootCredentialBoundaryHost{Role: role,
			InstanceID: fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.HOST%d", index), ImageOCID: "ocid1.image.oc1.sa-saopaulo-1.TESTED",
			SourceRevision: candidate.SourceRevision, NamespaceSHA256: digest, RootUID: 0, OrdinaryUID: 1001,
			RootOCIRead: "authenticated", OrdinaryUIDIMDS: "refused", OrdinaryUIDSigning: "refused", UnauthorizedIPC: "refused",
			TranscriptSHA256: writerDigest(transcript), Transcript: transcript})
	}
	return f
}

func (f *writerImageFixture) wires(t *testing.T) ([]byte, []byte) {
	t.Helper()
	body, err := json.Marshal(f.boundary, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	for index, evidence := range f.qualification.Evidence {
		if evidence.Gate == release.RootCredentialBoundaryGate {
			evidence.SHA256, evidence.Bytes = writerDigest(body), int64(len(body))
			f.qualification.Evidence[index] = evidence
			f.objects[evidence.SHA256] = body
		}
	}
	baseline := f.qualification
	baseline.Schema = release.ProductionQualificationSchema
	baseline.Evidence = []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: writerDigest([]byte("test-only baseline")), Bytes: int64(len("test-only baseline")), CompletedAt: f.now.Add(-time.Second)}, {Gate: "workload-safety", SHA256: writerDigest([]byte("test-only baseline")), Bytes: int64(len("test-only baseline")), CompletedAt: f.now.Add(-time.Second)}}
	baseline.Candidate = release.ProductionExpectation{SourceRevision: f.receipt.SourceRevision, ArtifactSHA256: f.receipt.ImageSHA256, QualificationSHA256: f.receipt.QualificationSHA256, Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: f.receipt.Architecture, Role: "orchestrator"}
	f.receipt.Production = &release.ProductionProof{Qualification: f.encode(t, f.sign(t, baseline, release.ProductionQualificationScope(baseline.Candidate), f.root, f.now, f.now.Add(time.Hour)))}
	qualification := f.sign(t, f.qualification, release.ProductionQualificationScope(f.qualification.Candidate), f.qualifier, f.qualificationIssued, f.qualificationExpiry)
	f.receipt.HostProduction = map[string]release.ProductionProof{release.FoundationWriterRole: {
		Qualification: f.encode(t, qualification), Delegation: f.delegation(t, f.delegatedQualifier, f.qualificationCapability, f.qualifierExpiry)}}
	return f.encode(t, f.sign(t, f.receipt, release.ImageScope(f.receipt, "production"), f.imageSigner, f.now, f.now.Add(time.Hour))), f.delegation(t, f.imageSigner, release.ImageScope(f.receipt, "production"), f.imageDelegationExpiry)
}

func (f writerImageFixture) sign(t *testing.T, value any, scope trust.Scope, key ed25519.PrivateKey, issued, expires time.Time) trust.Envelope {
	t.Helper()
	payload, err := trust.EncodePayload(value)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Sign(payload, scope, issued, expires, key)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (f writerImageFixture) encode(t *testing.T, envelope trust.Envelope) []byte {
	t.Helper()
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f writerImageFixture) delegation(t *testing.T, key ed25519.PrivateKey, scope trust.Scope, expires time.Time) []byte {
	t.Helper()
	public := key.Public().(ed25519.PublicKey)
	id, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: id, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, f.now.Add(-time.Minute), expires, f.root)
	if err != nil {
		t.Fatal(err)
	}
	return f.encode(t, envelope)
}

func (f writerImageFixture) expected() release.ImageExpectation {
	return release.ImageExpectation{Environment: "production", LogicalRegion: "GRU", OCIImageOCID: f.receipt.OCIImageOCID, Architecture: f.receipt.Architecture}
}

func (f writerImageFixture) retain(backend *functionBucketBackend) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.objects = make(map[string]functionObject)
	for digest, data := range f.objects {
		backend.objects[ImageProductionEvidenceObject(digest)] = functionObject{data: bytes.Clone(data), version: 1}
	}
}

func writerDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
