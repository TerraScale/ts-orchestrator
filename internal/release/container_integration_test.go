package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func TestContainerAdmissionHTTPIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerPublic, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := trust.KeyID(rootPublic)
	signerID, _ := trust.KeyID(signerPublic)
	roots := trust.Keyring{rootID: rootPublic}
	now := time.Now().UTC().Truncate(time.Second)
	target := ContainerTarget{Cell: "GRU", Environment: "production", Role: "ts-auth", Architecture: "arm64"}
	evidence := []byte("actual retained runtime boundary integration evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/evidence/"+evidenceSHA {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(evidence)
	}))
	defer server.Close()
	reader := func(ctx context.Context, digest string) (io.ReadCloser, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/evidence/"+digest, nil)
		if err != nil {
			return nil, err
		}
		response, err := server.Client().Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("evidence HTTP %d", response.StatusCode)
		}
		return response.Body, nil
	}
	migration := SequenceMigration{Schema: SequenceMigrationSchema, Namespace: "fixture", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: signerID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(signerPublic), Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, err := SignSequenceMigration(migration, now, root)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, err := trust.EncodeEnvelope(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	migrationSHA, err := trust.Fingerprint(migrationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	claim := ContainerClaim{Schema: ContainerClaimSchema, Image: "registry.example/platform/auth@sha256:" + strings.Repeat("a", 64), SourceRevision: strings.Repeat("c", 40), Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: 101, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: strings.Repeat("b", 64)}
	qualifier := ProductionQualification{Schema: ProductionQualificationSchema, Candidate: ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: claim.QualificationSHA256, Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, Runtime: ProductionRuntime}, Evidence: []ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
	qualificationPayload, _ := trust.EncodePayload(qualifier)
	qualificationEnvelope, err := trust.Sign(qualificationPayload, ProductionQualificationScope(qualifier.Candidate), now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	claim.Production.Qualification, err = trust.EncodeEnvelope(qualificationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(signerPublic), Capabilities: []trust.Capability{{Domain: ContainerClaimDomain, DeploymentID: ContainerScope(target).DeploymentID, Cell: target.Cell, Environment: target.Environment, Role: target.Role, Slots: []string{"linux-arm64"}, Actions: []string{"sign"}}}}, now, now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	makeBundle := func(c ContainerClaim, key ed25519.PrivateKey) ContainerBundle {
		t.Helper()
		payload, err := trust.EncodePayload(c)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := trust.Sign(payload, ContainerScope(target), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(signed)
		if err != nil {
			t.Fatal(err)
		}
		return ContainerBundle{Claim: wire, Delegation: grantWire, Migration: migrationWire}
	}
	bundle := makeBundle(claim, signer)
	verified, err := VerifyContainerCurrent(ctx, bundle, roots, target, now, now.Add(time.Minute), reader)
	if err != nil || verified.Claim().Image != claim.Image || verified.Fingerprint() == "" {
		t.Fatalf("qualified child image admission: %+v %v", verified, err)
	}
	renewed := claim
	qualificationEnvelope, err = trust.Sign(qualificationPayload, ProductionQualificationScope(qualifier.Candidate), now.Add(-time.Second), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	renewed.Production.Qualification, err = trust.EncodeEnvelope(qualificationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	renewedVerified, err := VerifyContainerCurrent(ctx, makeBundle(renewed, signer), roots, target, now, now.Add(time.Minute), reader)
	if err != nil || renewedVerified.ReleaseIdentity() != verified.ReleaseIdentity() || renewedVerified.Fingerprint() == verified.Fingerprint() {
		t.Fatalf("qualification renewal changed immutable release identity: %+v %v", renewedVerified, err)
	}
	changed := claim
	changed.Image = "registry.example/platform/auth@sha256:" + strings.Repeat("d", 64)
	before, err := claim.ContentManifestDigest()
	if err != nil {
		t.Fatal(err)
	}
	after, err := changed.ContentManifestDigest()
	if err != nil || before == after {
		t.Fatalf("OCI child identity change was lost: %s %s %v", before, after, err)
	}
	tests := []struct {
		name   string
		bundle ContainerBundle
		target ContainerTarget
		until  time.Time
	}{
		{"wrong-target", bundle, ContainerTarget{Cell: "FRA", Environment: target.Environment, Role: target.Role, Architecture: target.Architecture}, now.Add(time.Minute)},
		{"deadline-expiry", bundle, target, now.Add(2 * time.Hour)},
	}
	missing := claim
	missing.Production = ProductionProof{}
	tests = append(tests, struct {
		name   string
		bundle ContainerBundle
		target ContainerTarget
		until  time.Time
	}{"missing-independent-proof", makeBundle(missing, signer), target, now.Add(time.Minute)})
	wrongImage := claim
	wrongImage.Image = "registry.example/platform/auth@sha256:" + strings.Repeat("d", 64)
	tests = append(tests, struct {
		name   string
		bundle ContainerBundle
		target ContainerTarget
		until  time.Time
	}{"wrong-image-proof", makeBundle(wrongImage, signer), target, now.Add(time.Minute)})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyContainerCurrent(ctx, test.bundle, roots, test.target, now, test.until, reader); err == nil {
				t.Fatal("invalid container release admitted")
			}
		})
	}
	if _, err := VerifyContainerCurrent(ctx, bundle, roots, target, now, now.Add(time.Minute), func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("tampered evidence")), nil
	}); err == nil {
		t.Fatal("tampered retained evidence admitted")
	}
	if _, err := VerifyContainerCurrent(ctx, bundle, roots, target, now, now.Add(time.Minute), func(context.Context, string) (io.ReadCloser, error) { return nil, nil }); err == nil {
		t.Fatal("missing evidence reader admitted")
	}
	otherRootPublic, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
	otherRootID, _ := trust.KeyID(otherRootPublic)
	roots[otherRootID] = otherRootPublic
	wrongSigner := makeBundle(claim, otherRoot)
	wrongSigner.Delegation = nil
	if _, err := VerifyContainerCurrent(ctx, wrongSigner, roots, target, now, now.Add(time.Minute), reader); err == nil {
		t.Fatal("root-trusted release signer bypassed root-authorized sequence signer")
	}
}
