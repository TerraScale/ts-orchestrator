package imagequalification

import (
	"context"
	"crypto/ed25519"
	"crypto/md5" // OCI API-key fingerprints use MD5 over public SPKI DER.
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/confinement"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/principal"
)

func TestImageOwnershipRequiresExactAuthenticatedPublication(t *testing.T) {
	f := fixture(t)
	f.now = f.now.Add(-90 * time.Minute)
	a := f.prepared.Approval()
	a.Candidate.Role, a.Purpose = release.FoundationWriterRole, qualification.RootCredentialBoundaryPurpose
	a.ArtifactDisposition, a.ReaderIAMAuthority = qualification.RetainTestedImage, qualification.ExactHostReaders
	a.ImageRetainUntil, a.ImageTransferUntil = f.now.Add(30*time.Minute), f.now.Add(20*time.Minute)
	a.ImagePublicationBucket, _ = releasechannel.BucketName(a.Candidate.Cell)
	a.MaterialFixtures = nil
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := md5.Sum(issuerPublic)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var p principal.Preparation
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Schema, p.ExpiresAt = principal.PreparationSchema, f.now.Add(40*time.Minute)
	p.IssuerPrincipal, p.IssuerFingerprint = "ocid1.user.oc1..issuer", strings.Join(parts, ":")
	p.PrincipalName, p.GroupName, p.PolicyName = "ts-qualification-"+a.RunID+"-user", "ts-qualification-"+a.RunID+"-group", "ts-qualification-"+a.RunID+"-policy"
	p.Object = "qualification/" + a.RunID + "/" + a.Candidate.ArtifactSHA256 + ".qcow2"
	p.PublicKeyPEM, p.PublicKeyFingerprint, err = principal.GenerateKey(filepath.Join(t.TempDir(), "escrow"))
	if err != nil {
		t.Fatal(err)
	}
	p.PolicyTemplate = principal.RequiredTemplate(p)
	a.PolicyStatements = confinement.RequiredStatements(confinement.Scope{RunID: p.RunID, Group: a.Group, Compartment: p.Compartment, Bucket: p.Bucket, Object: p.Object, ExpiresAt: p.ExpiresAt, CleanupUntil: p.CleanupUntil})
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey, expires time.Time) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		e, err := trust.Sign(payload, scope, f.now.Add(-time.Minute), expires, key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	approvalWire := sign(a, ApprovalScope(a.RunID, a.Candidate), f.private, f.now.Add(40*time.Minute))
	prepared, err := Prepare(approvalWire, nil, f.roots, a.Candidate, a.RunID, f.disk, f.qualification, f.now)
	if err != nil {
		t.Fatal(err)
	}
	prepared.principalWire = sign(p, qualification.Scope(a.RunID, a.Candidate, "disposable-principal"), f.private, p.CleanupUntil)
	if _, err := principal.VerifyPreparation(prepared.principalWire, nil, f.roots, p.RunID, f.now); err != nil {
		t.Fatal(err)
	}
	imageID := "ocid1.image.oc1.sa-saopaulo-1.tested"
	j := journal{RunID: a.RunID, ApprovalSHA256: prepared.approvalSHA256, ImageID: imageID, Hosts: map[string]string{}, RetainedAt: f.now}
	binding := hostadmission.Binding{Schema: hostadmission.BindingSchema, Purpose: a.Purpose, RunID: a.RunID,
		ApprovalSHA256: prepared.approvalSHA256, PreparationSHA256: hashBytes(prepared.principalWire), HostName: a.Hosts[0].Name}
	candidate := a.Candidate
	candidate.ImageOCID = imageID
	boundary := release.RootCredentialBoundaryEvidence{Schema: release.RootCredentialBoundarySchema, Candidate: candidate, CompletedAt: f.now.Add(-time.Minute)}
	for i, h := range a.Hosts {
		id := fmt.Sprintf("ocid1.instance.oc1.sa-saopaulo-1.host%d", i)
		j.Hosts[h.Name] = id
		binding.Hosts = append(binding.Hosts, hostadmission.BoundHost{Name: h.Name, InstanceID: id, ImageID: imageID, PrivateIP: fmt.Sprintf("10.8.0.%d", i+2)})
		role := "manager"
		if i == 3 {
			role = "container"
		}
		transcript := []byte(fmt.Sprintf("test-only native boundary transcript %d", i))
		boundary.Hosts = append(boundary.Hosts, release.RootCredentialBoundaryHost{Role: role, InstanceID: id, ImageOCID: imageID, SourceRevision: candidate.SourceRevision,
			NamespaceSHA256: hashBytes([]byte(a.Namespace)), RootUID: 0, OrdinaryUID: 1001, RootOCIRead: "authenticated", OrdinaryUIDIMDS: "refused", OrdinaryUIDSigning: "refused", UnauthorizedIPC: "refused", Transcript: transcript, TranscriptSHA256: hashBytes(transcript)})
	}
	proof := hostadmission.Proof{Schema: hostadmission.ProofSchema, Approval: approvalWire, Preparation: prepared.principalWire}
	proof.Binding = sign(binding, ApprovalScope(a.RunID, a.Candidate), f.private, a.ImageRetainUntil)
	proofWire, err := json.Marshal(proof, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := hostadmission.VerifyReaderPlan(proofWire, f.roots, f.now)
	if err != nil {
		t.Fatal(err)
	}
	binding.ReaderIAM = hostadmission.ReaderIAM{DynamicGroupID: "ocid1.dynamicgroup.oc1..reader", PolicyID: "ocid1.policy.oc1..reader", PlanSHA256: plan.SHA256()}
	statements, err := json.Marshal(qualification.ReaderStatements(binding.ReaderIAM.DynamicGroupID, a.Compartment, plan.ExpiresAt()), json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	binding.ReaderIAM.PolicySHA256 = hashBytes(statements)
	proof.Binding = sign(binding, ApprovalScope(a.RunID, a.Candidate), f.private, a.ImageRetainUntil)
	j.RetainedReaderProof, err = json.Marshal(proof, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hostadmission.VerifyReaderBinding(j.RetainedReaderProof, f.roots, f.now); err != nil {
		t.Fatal(err)
	}
	rootBody, err := json.Marshal(boundary, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	j.RootGateSHA256 = hashBytes(rootBody)
	baselineBody := []byte("test-only runtime and workload evidence")
	baseline := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: a.Candidate}
	baseline.Candidate.Role = "orchestrator"
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		baseline.Evidence = append(baseline.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: hashBytes(baselineBody), Bytes: int64(len(baselineBody)), CompletedAt: boundary.CompletedAt})
	}
	writer := baseline
	writer.Schema, writer.Candidate = release.FoundationWriterQualificationSchema, candidate
	writer.Evidence = append(append([]release.ProductionGateEvidence{}, baseline.Evidence...), release.ProductionGateEvidence{Gate: release.RootCredentialBoundaryGate, SHA256: j.RootGateSHA256, Bytes: int64(len(rootBody)), CompletedAt: boundary.CompletedAt})
	receipt := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: a.Candidate.SourceRevision, GoVersion: release.DefaultGoVersion, Architecture: a.Candidate.Architecture,
		BinaryBytes: 100, BinarySHA256: a.BinarySHA256, QualificationSHA256: a.Candidate.QualificationSHA256, BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: a.Candidate.Cell, BaseImageSHA256: hashBytes([]byte("base")),
		KernelRelease: a.KernelRelease, KernelSHA256: a.KernelSHA256, ImageFormat: "qcow2", ImageBytes: a.ImageBytes, ImageSHA256: a.Candidate.ArtifactSHA256, OCIImageOCID: imageID, OCIRegion: a.Candidate.Cell,
		Production:     &release.ProductionProof{Qualification: sign(baseline, release.ProductionQualificationScope(baseline.Candidate), f.private, f.now.Add(time.Hour))},
		HostProduction: map[string]release.ProductionProof{release.FoundationWriterRole: {Qualification: sign(writer, release.ProductionQualificationScope(candidate), f.private, f.now.Add(time.Hour))}}}
	public, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	scope := release.ImageScope(receipt, a.Candidate.Environment)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: 1, SubjectKeyID: leafID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.private)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	receiptWire := sign(receipt, scope, leaf, f.now.Add(time.Hour))
	objects := map[string][]byte{releasechannel.ImageProductionEvidenceObject(j.RootGateSHA256): rootBody, releasechannel.ImageProductionEvidenceObject(hashBytes(baselineBody)): baselineBody}
	var mu sync.Mutex
	mode := ""
	now := f.now.Add(2 * time.Second)
	reads, writes := 0, 0
	c := &cloud{prepared: prepared, now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !authenticatedFixtureRequest(r, &key.PublicKey, a.Tenancy) {
			http.Error(w, "invalid SDK signature", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			var issuerResource any
			switch r.URL.Path {
			case "/20160918/tenancies/" + p.Tenancy:
				issuerResource = identity.Tenancy{Id: new(p.Tenancy), HomeRegionKey: new("GRU")}
			case "/20160918/users/" + p.IssuerPrincipal:
				issuerResource = identity.User{Id: new(p.IssuerPrincipal), CompartmentId: new(p.Tenancy), LifecycleState: identity.UserLifecycleStateActive}
			case "/20160918/users/" + p.IssuerPrincipal + "/apiKeys":
				issuerResource = []identity.ApiKey{{UserId: new(p.IssuerPrincipal), Fingerprint: new(p.IssuerFingerprint), LifecycleState: identity.ApiKeyLifecycleStateActive}}
			}
			if issuerResource != nil {
				reads++
				_ = json.MarshalWrite(w, issuerResource)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/20160918/instances/") && r.Method == http.MethodGet {
			reads++
			if mode == "remaining-host" {
				id := strings.TrimPrefix(r.URL.Path, "/20160918/instances/")
				_ = json.MarshalWrite(w, core.Instance{Id: new(id), CompartmentId: new(a.Compartment), ImageId: new(imageID), LifecycleState: core.InstanceLifecycleStateRunning})
				return
			}
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/20160918/instanceConsoleHistories/") && r.Method == http.MethodGet {
			reads++
			if mode == "remaining-console" {
				id := strings.TrimPrefix(r.URL.Path, "/20160918/instanceConsoleHistories/")
				_ = json.MarshalWrite(w, core.ConsoleHistory{Id: new(id), CompartmentId: new(a.Compartment), InstanceId: new(j.Hosts[a.Hosts[0].Name]), LifecycleState: core.ConsoleHistoryLifecycleStateSucceeded})
				return
			}
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/20160918/computeImageCapabilitySchemas/") && r.Method == http.MethodGet {
			reads++
			if mode == "remaining-capability" {
				id := strings.TrimPrefix(r.URL.Path, "/20160918/computeImageCapabilitySchemas/")
				_ = json.MarshalWrite(w, core.ComputeImageCapabilitySchema{Id: new(id), ImageId: new(imageID), CompartmentId: new(a.Compartment), LifecycleState: core.ComputeImageCapabilitySchemaLifecycleStateActive})
				return
			}
			w.WriteHeader(404)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/n/"+a.Namespace+"/b/"+a.Bucket+"/o/") && r.Method == http.MethodHead {
			reads++
			if mode == "remaining-source" {
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(404)
			return
		}
		prefix := "/n/" + a.Namespace + "/b/" + a.ImagePublicationBucket + "/o/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			name := strings.TrimPrefix(r.URL.Path, prefix)
			if r.Method == http.MethodPut {
				writes++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				objects[name] = body
				w.Header().Set("etag", "fixture-etag")
				w.WriteHeader(200)
				return
			}
			if r.Method != http.MethodGet {
				t.Error("unexpected object effect", r.Method)
				w.WriteHeader(400)
				return
			}
			reads++
			body, found := objects[name]
			if mode == "missing-publication" && strings.Contains(name, "/current/") {
				found = false
			}
			if mode == "missing-recorded-manifest" && strings.Contains(name, "/manifests/") {
				found = false
			}
			if !found {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"code":"ObjectNotFound","message":"local fixture"}`))
				return
			}
			w.Header().Set("ETag", "fixture-etag")
			if mode == "changed-manifest" && strings.Contains(name, "/manifests/") {
				body = []byte("changed manifest")
			}
			if mode == "changed-evidence" && name == releasechannel.ImageProductionEvidenceObject(j.RootGateSHA256) {
				body = []byte("changed root gate")
			}
			modified := f.now
			if mode == "late-publication" {
				modified = a.ImageTransferUntil
			}
			if mode == "publication-at-deadline-second" {
				modified = a.ImageTransferUntil.Add(-time.Second)
			}
			if mode == "future-publication" {
				modified = now.Add(time.Minute)
			}
			if mode != "missing-timestamp" {
				w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
			}
			_, _ = w.Write(body)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/20160918/images/"+imageID {
			reads++
			if mode == "deleted-image" || mode == "checkpoint-deleted-image" || mode == "remaining-capability" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"code":"NotAuthorizedOrNotFound","message":"local fixture"}`))
				return
			}
			compartment := a.Compartment
			if mode == "other-compartment" {
				compartment += "other"
			}
			tags := map[string]string{runTag: a.RunID, approvalTag: prepared.approvalSHA256, imageimport.SHA256Tag: a.Candidate.ArtifactSHA256}
			if mode == "other-image-bytes" {
				tags[imageimport.SHA256Tag] = strings.Repeat("e", 64)
			}
			_ = json.MarshalWrite(w, core.Image{Id: new(imageID), CompartmentId: new(compartment), DisplayName: new(c.name("image")), FreeformTags: tags, LifecycleState: core.ImageLifecycleStateAvailable})
			return
		}
		t.Errorf("unexpected SDK request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(400)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "objectstorage.sa-saopaulo-1.oraclecloud.com:443" && address != "iaas.sa-saopaulo-1.oraclecloud.com:443" && address != "identity.sa-saopaulo-1.oci.oraclecloud.com:443" {
			return nil, fmt.Errorf("unapproved fixture origin %s", address)
		}
		return (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS13}}).DialContext(ctx, network, u.Host)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	provider := common.NewRawConfigurationProvider(a.Tenancy, p.IssuerPrincipal, a.OCIRegion, p.IssuerFingerprint, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	observer, err := ociclient.New(provider, ociclient.Options{Region: a.OCIRegion, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceCompute: {PerSecond: 10000, Burst: 1000}, ociclient.ServiceObjectStorage: {PerSecond: 10000, Burst: 1000}}, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := observer.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	location := releasechannel.Location{Client: client, Namespace: a.Namespace, Bucket: a.ImagePublicationBucket}
	if err := releasechannel.PublishCurrentImage(t.Context(), location, receiptWire, delegationWire, f.roots, releasechannel.CurrentImageExpectation{Cell: a.Candidate.Cell, Environment: a.Candidate.Environment, Architecture: a.Candidate.Architecture, Role: release.FoundationWriterRole}, f.now); err != nil {
		t.Fatal(err)
	}
	t.Run("authenticated-other-current-image", func(t *testing.T) {
		otherBoundary := boundary
		otherBoundary.Candidate.ImageOCID = "ocid1.image.oc1.sa-saopaulo-1.other-tested"
		otherBoundary.Hosts = append([]release.RootCredentialBoundaryHost{}, boundary.Hosts...)
		for i := range otherBoundary.Hosts {
			otherBoundary.Hosts[i].ImageOCID = otherBoundary.Candidate.ImageOCID
		}
		otherBody, err := json.Marshal(otherBoundary, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		otherWriter := writer
		otherWriter.Candidate = otherBoundary.Candidate
		otherWriter.Evidence = append([]release.ProductionGateEvidence{}, writer.Evidence...)
		otherWriter.Evidence[len(otherWriter.Evidence)-1].SHA256 = hashBytes(otherBody)
		otherWriter.Evidence[len(otherWriter.Evidence)-1].Bytes = int64(len(otherBody))
		otherReceipt := receipt
		otherReceipt.OCIImageOCID = otherBoundary.Candidate.ImageOCID
		otherReceipt.HostProduction = map[string]release.ProductionProof{release.FoundationWriterRole: {
			Qualification: sign(otherWriter, release.ProductionQualificationScope(otherWriter.Candidate), f.private, f.now.Add(time.Hour)),
		}}
		mu.Lock()
		objects[releasechannel.ImageProductionEvidenceObject(hashBytes(otherBody))] = otherBody
		mu.Unlock()
		otherScope := release.ImageScope(otherReceipt, a.Candidate.Environment)
		otherWire := sign(otherReceipt, otherScope, leaf, f.now.Add(time.Hour))
		otherDelegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: 1, SubjectKeyID: leafID, SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: otherScope.Domain, DeploymentID: otherScope.DeploymentID, Cell: otherScope.Cell, Environment: otherScope.Environment, Role: otherScope.Role, Slots: []string{otherScope.Slot}, Actions: []string{"sign"}}}}, f.now.Add(-time.Minute), f.now.Add(time.Hour), f.private)
		if err != nil {
			t.Fatal(err)
		}
		otherDelegationWire, err := trust.EncodeEnvelope(otherDelegation)
		if err != nil {
			t.Fatal(err)
		}
		expected := releasechannel.CurrentImageExpectation{Cell: a.Candidate.Cell, Environment: a.Candidate.Environment, Architecture: a.Candidate.Architecture, Role: release.FoundationWriterRole}
		if err := releasechannel.PublishCurrentImage(t.Context(), location, otherWire, otherDelegationWire, f.roots, expected, f.now); err != nil {
			t.Fatal(err)
		}
		otherCurrent, found, err := releasechannel.ReadPublishedImageSDK(t.Context(), observer, a.Namespace, f.roots, expected, "", now)
		if err != nil || !found {
			t.Fatalf("other publication fixture failed authentication: %v", err)
		}
		if transfer, err := c.observeImageTransfer(t.Context(), observer, j); err != nil || transfer != (imageTransfer{}) {
			t.Fatalf("unrelated authenticated current image stalled cleanup: %+v %v", transfer, err)
		}
		wrongRecorded := j
		wrongRecorded.ImageManifestSHA256 = otherCurrent.ManifestSHA256
		if transfer, err := c.observeImageTransfer(t.Context(), observer, wrongRecorded); err == nil || transfer != (imageTransfer{}) {
			t.Fatalf("recorded image mismatch lost cleanup duty: %+v %v", transfer, err)
		}
		if err := releasechannel.PublishCurrentImage(t.Context(), location, receiptWire, delegationWire, f.roots, expected, f.now); err != nil {
			t.Fatal(err)
		}
	})
	mu.Lock()
	publicationWrites := writes
	mu.Unlock()
	transfer, err := c.observeImageTransfer(t.Context(), observer, j)
	if err != nil || !validHash(transfer.manifestSHA256) {
		t.Fatalf("exact authenticated immutable publication rejected: digest=%s err=%v", transfer.manifestSHA256, err)
	}
	// The existing protected journal keeps only the immutable reference. A
	// later locator, expired original binding or expired production proof cannot
	// erase the independently authenticated earlier ownership transition.
	recovered := j
	recovered.ImageManifestSHA256 = transfer.manifestSHA256
	mu.Lock()
	mode = "missing-publication"
	now = f.now.Add(90 * time.Minute)
	mu.Unlock()
	if recoveredTransfer, err := c.observeImageTransfer(t.Context(), observer, recovered); err != nil || recoveredTransfer.manifestSHA256 != transfer.manifestSHA256 {
		t.Fatalf("restart lost exact earlier publication after locator/proof expiry: %+v %v", recoveredTransfer, err)
	}
	t.Run("supervisor-persists-and-reopens-exact-transfer", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "resources.json")
		saved, err := c.load(path)
		if err != nil {
			t.Fatal(err)
		}
		saved.ImageID, saved.Hosts = j.ImageID, j.Hosts
		saved.RetainedAt, saved.RetainedReaderProof, saved.RootGateSHA256 = j.RetainedAt, j.RetainedReaderProof, j.RootGateSHA256
		saved.CapabilityID, saved.CapabilityVersion = "ocid1.computeimagecapabilityschema.oc1.sa-saopaulo-1.original", "original"
		saved.ObjectDeleted = true
		for name := range saved.Hosts {
			saved.Terminated[name] = true
		}
		if err := checkpoint(path, saved); err != nil {
			t.Fatal(err)
		}
		for _, stage := range []string{"initial-publication", "recorded-restart"} {
			mu.Lock()
			mode = ""
			if stage == "recorded-restart" {
				mode = "missing-publication"
			}
			mu.Unlock()
			supervisor := *c
			if err := supervisor.superviseRetainedImage(t.Context(), path, observer); err != nil {
				t.Fatalf("%s rejected historical transfer: %v", stage, err)
			}
			checkpointed, err := supervisor.load(path)
			if err != nil {
				t.Fatal(err)
			}
			if checkpointed.ImageManifestSHA256 != transfer.manifestSHA256 || checkpointed.ImageDeleted || checkpointed.CapabilityDeleted || supervisor.imageTransfer != transfer {
				t.Fatalf("%s lost exact authenticated image ownership: %+v", stage, checkpointed)
			}
		}
		settled, err := c.load(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("outer-restart-after-principal-removal", func(t *testing.T) {
			directory := t.TempDir()
			paths := rootCredentialPaths{Journal: path, Approval: filepath.Join(directory, "approval.json"), PrincipalDirectory: filepath.Join(directory, "principal")}
			if err := os.Mkdir(paths.PrincipalDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.Approval, approvalWire, 0600); err != nil {
				t.Fatal(err)
			}
			preparationDigest := hashBytes(prepared.principalWire)
			description := "Disposable image qualification " + preparationDigest
			var hostIDs []string
			for _, spec := range a.Hosts {
				hostIDs = append(hostIDs, j.Hosts[spec.Name])
			}
			requests := []struct {
				name, id, path string
				request        common.OCIRequest
			}{
				{"user", a.Principal, "/users", identity.CreateUserRequest{CreateUserDetails: identity.CreateUserDetails{CompartmentId: new(p.Tenancy), Name: new(p.PrincipalName), Description: new(description)}}},
				{"group", a.Group, "/groups", identity.CreateGroupRequest{CreateGroupDetails: identity.CreateGroupDetails{CompartmentId: new(p.Tenancy), Name: new(p.GroupName), Description: new(description)}}},
				{"policy", a.PolicyID, "/policies", identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{CompartmentId: new(p.Tenancy), Name: new(p.PolicyName), Description: new(description), Statements: a.PolicyStatements}}},
				{"key", p.PublicKeyFingerprint, "/users/{userId}/apiKeys", identity.UploadApiKeyRequest{UserId: new(a.Principal), CreateApiKeyDetails: identity.CreateApiKeyDetails{Key: new(p.PublicKeyPEM)}}},
				{"membership", "ocid1.groupmembership.oc1..original", "/userGroupMemberships", identity.AddUserToGroupRequest{AddUserToGroupDetails: identity.AddUserToGroupDetails{UserId: new(a.Principal), GroupId: new(a.Group)}}},
				{"reader-group", binding.ReaderIAM.DynamicGroupID, "/dynamicGroups", identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: identity.CreateDynamicGroupDetails{CompartmentId: new(p.Tenancy), Name: new(p.GroupName + "-readers"), Description: new(description), MatchingRule: new(qualification.ReaderMatchingRule(hostIDs))}}},
				{"reader-policy", binding.ReaderIAM.PolicyID, "/policies", identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{CompartmentId: new(p.Tenancy), Name: new(p.PolicyName + "-readers"), Description: new(description), Statements: qualification.ReaderStatements(binding.ReaderIAM.DynamicGroupID, a.Compartment, plan.ExpiresAt())}}},
			}
			operations := map[string]any{}
			for _, original := range requests {
				raw, err := original.request.HTTPRequest(http.MethodPost, original.path, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(raw.Body)
				raw.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				request, err := json.Marshal(struct {
					Method string `json:"method"`
					Path   string `json:"path"`
					Body   string `json:"body"`
				}{raw.Method, raw.URL.EscapedPath(), string(body)}, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				deleteUser := ""
				if original.name == "key" {
					deleteUser = a.Principal
				}
				deletion, err := json.Marshal(struct{ Operation, ID, User, ETag string }{original.name, original.id, deleteUser, "fixture-etag"}, json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				operations[original.name] = map[string]any{"request": jsontext.Value(request), "request_sha256": hashBytes(request), "retry_token": hashBytes([]byte(preparationDigest + "/" + original.name + "/" + hashBytes(request)))[:32], "first_attempt": f.now, "id": original.id,
					"delete_intent": true, "delete_request": jsontext.Value(deletion), "delete_sha256": hashBytes(deletion), "delete_request_id": hashBytes([]byte(preparationDigest + "/delete/" + original.name + "/" + hashBytes(deletion)))[:32], "delete_first_attempt": f.now.Add(35 * time.Minute), "deleted": true}
			}
			if err := checkpoint(filepath.Join(paths.PrincipalDirectory, "journal.json"), map[string]any{"preparation_sha256": preparationDigest, "preparation_wire": jsontext.Value(prepared.principalWire), "operations": operations, "reader_proof": j.RetainedReaderProof, "reader_verified_at": j.RetainedAt, "cleaning": true, "cleaned": true}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			mode = "missing-publication"
			beforeReads := reads
			mu.Unlock()
			if _, err := runRootCredentialBoundary(t.Context(), prepared.principalWire, nil, f.roots, observer, nil, paths); err != nil {
				t.Fatalf("outer restart required renewed creation, signing or local artifacts: %v", err)
			}
			mu.Lock()
			afterReads, afterWrites := reads, writes
			mu.Unlock()
			if afterReads <= beforeReads || afterWrites != publicationWrites {
				t.Fatal("outer restart failed to reobserve cleanup without cloud writes")
			}
		})
		consoleOperation := "console/" + a.Hosts[0].Name + "/root"
		settled.ConsoleHistories[consoleOperation] = "ocid1.consolehistory.oc1.sa-saopaulo-1.original"
		settled.ConsoleDeleted[consoleOperation] = true
		for _, scenario := range []string{"recorded-transfer", "remaining-host", "remaining-console", "remaining-source", "missing-recorded-manifest", "missing-recorded-reference", "deleted-image", "checkpoint-deleted-image", "remaining-capability", "omitted-bound-host", "invalid-manifest-reference", "unresolved-create", "cleanup-expired"} {
			t.Run("completed-cleanup-"+scenario, func(t *testing.T) {
				mu.Lock()
				mode = scenario
				beforeReads := reads
				mu.Unlock()
				original, copyJournal := c.prepared, settled
				switch scenario {
				case "missing-recorded-reference":
					copyJournal.ImageManifestSHA256 = ""
				case "checkpoint-deleted-image":
					copyJournal.ImageDeleted = true
				case "omitted-bound-host":
					copyJournal.ImageDeleted = true
					copyJournal.Hosts = map[string]string{}
				case "invalid-manifest-reference":
					copyJournal.ImageManifestSHA256 = "invalid"
				case "unresolved-create":
					copyJournal.Intents = map[string]time.Time{"unknown-create": f.now}
				case "cleanup-expired":
					original.approval.CleanupUntil = time.Now().UTC()
				}
				if err := checkpoint(path, copyJournal); err != nil {
					t.Fatal(err)
				}
				err := verifyCompletedCleanup(t.Context(), original, observer, path)
				wantSuccess := scenario == "recorded-transfer" || scenario == "deleted-image" || scenario == "checkpoint-deleted-image"
				if (err == nil) != wantSuccess {
					t.Fatalf("settled cleanup=%v, expected success=%v", err, wantSuccess)
				}
				mu.Lock()
				afterReads, afterWrites := reads, writes
				mu.Unlock()
				if afterWrites != publicationWrites {
					t.Fatal("completed cleanup observer dispatched a write")
				}
				if (scenario == "unresolved-create" || scenario == "cleanup-expired" || scenario == "omitted-bound-host" || scenario == "invalid-manifest-reference") && afterReads != beforeReads {
					t.Fatal("invalid settled cleanup authority reached SDK")
				}
			})
		}
	})
	mu.Lock()
	mode = ""
	mu.Unlock()
	if _, _, err := releasechannel.ReadCurrentImageSDK(t.Context(), observer, a.Namespace, f.roots, releasechannel.CurrentImageExpectation{Cell: a.Candidate.Cell, Environment: a.Candidate.Environment, Architecture: a.Candidate.Architecture, Role: release.FoundationWriterRole}, f.now.Add(90*time.Minute)); err == nil {
		t.Fatal("historical ownership transition renewed current writer authority")
	}
	for _, scenario := range []string{"missing-publication", "missing-recorded-manifest", "changed-manifest", "changed-evidence", "other-compartment", "other-image-bytes", "late-publication", "publication-at-deadline-second", "future-publication", "missing-timestamp", "deleted-image", "reimported-image", "other-root-gate", "other-approved-destination", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			mu.Lock()
			mode = scenario
			now = f.now.Add(2 * time.Second)
			beforeReads := reads
			mu.Unlock()
			copyCloud, copyJournal := *c, j
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch scenario {
			case "missing-recorded-manifest":
				copyJournal.ImageManifestSHA256 = transfer.manifestSHA256
			case "other-root-gate":
				copyJournal.RootGateSHA256 = strings.Repeat("e", 64)
			case "other-approved-destination":
				copyCloud.prepared.approval.ImagePublicationBucket = "qualification"
			case "reimported-image":
				copyJournal.ImageID = "ocid1.image.oc1.sa-saopaulo-1.reimported"
			case "late-publication", "publication-at-deadline-second":
				mu.Lock()
				now = a.ImageTransferUntil.Add(5 * time.Minute)
				mu.Unlock()
			case "canceled":
				cancel()
			}
			transferred, err := copyCloud.observeImageTransfer(ctx, observer, copyJournal)
			if transferred.manifestSHA256 != "" {
				t.Fatalf("incomplete transfer relinquished cleanup: %v", err)
			}
			mu.Lock()
			afterReads, afterWrites := reads, writes
			mu.Unlock()
			if afterWrites != publicationWrites {
				t.Fatal("ownership observer dispatched a write")
			}
			if (scenario == "other-approved-destination" || scenario == "reimported-image" || scenario == "canceled") && afterReads != beforeReads {
				t.Fatal("invalid original authority reached SDK")
			}
		})
	}
}
