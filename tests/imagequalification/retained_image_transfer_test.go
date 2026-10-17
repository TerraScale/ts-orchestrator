package imagequalification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/qualification"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestImageOwnershipRequiresExactAuthenticatedPublication(t *testing.T) {
	f := fixture(t)
	a := f.prepared.Approval()
	a.Candidate.Role, a.Purpose = release.FoundationWriterRole, qualification.RootCredentialBoundaryPurpose
	a.ArtifactDisposition, a.ReaderIAMAuthority = qualification.RetainTestedImage, qualification.ExactHostReaders
	a.ImageRetainUntil, a.ImageTransferUntil = f.now.Add(30*time.Minute), f.now.Add(20*time.Minute)
	a.ImagePublicationBucket, _ = releasechannel.BucketName(a.Candidate.Cell)
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
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var p qualification.Preparation
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Schema, p.ExpiresAt = "terrascale.test.image-qualification.principal.v1", f.now.Add(40*time.Minute)
	prepared.principalWire = sign(p, qualification.Scope(a.RunID, a.Candidate, "disposable-principal"), f.private, p.CleanupUntil)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
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
			if mode == "deleted-image" {
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
		if address != "objectstorage.sa-saopaulo-1.oraclecloud.com:443" && address != "iaas.sa-saopaulo-1.oraclecloud.com:443" {
			return nil, fmt.Errorf("unapproved fixture origin %s", address)
		}
		return (&tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS13}}).DialContext(ctx, network, u.Host)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	provider := common.NewRawConfigurationProvider(a.Tenancy, "ocid1.user.oc1..observer", a.OCIRegion, "observer-fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
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
