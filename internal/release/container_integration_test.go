package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
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
	claim := ContainerClaim{Schema: ContainerClaimSchema, Image: "registry.example/platform/auth@sha256:" + strings.Repeat("a", 64), SourceRepository: "https://github.com/TerraScale/ts-auth", SourceRevision: strings.Repeat("c", 40), SourceTreeSHA256: strings.Repeat("e", 64), Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: 101, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: strings.Repeat("a", 64)}
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
	if !verified.Valid(now) || !verified.ExpiresAt().Equal(now.Add(time.Minute)) || verified.Valid(now.Add(time.Minute)) || (VerifiedContainer{}).Valid(now) {
		t.Fatal("cached container proof escaped its admitted operation deadline")
	}
	renewed := claim
	qualificationEnvelope, err = trust.Sign(qualificationPayload, ProductionQualificationScope(qualifier.Candidate), now, now.Add(59*time.Minute), root)
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
	claimPayload, err := trust.EncodePayload(claim)
	if err != nil {
		t.Fatal(err)
	}
	expiredClaim, err := trust.Sign(claimPayload, ContainerScope(target), now.Add(-2*time.Hour), now.Add(-time.Hour), signer)
	if err != nil {
		t.Fatal(err)
	}
	expiredGrant, err := trust.Sign(grant.Payload, grant.Scope, now.Add(-2*time.Hour), now.Add(-time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	expiredBundle := bundle
	expiredBundle.Claim, err = trust.EncodeEnvelope(expiredClaim)
	if err != nil {
		t.Fatal(err)
	}
	expiredBundle.Delegation, err = trust.EncodeEnvelope(expiredGrant)
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyContainerHistorical(expiredBundle, roots, target)
	if err != nil || history.ReleaseIdentity() != verified.ReleaseIdentity() || history.Claim().SourceRepository != claim.SourceRepository || history.Claim().SourceTreeSHA256 != claim.SourceTreeSHA256 {
		t.Fatalf("retained expired source floor lost authenticated identity: %+v %v", history, err)
	}
	if _, err := VerifyContainerCurrent(ctx, expiredBundle, roots, target, now, now.Add(time.Minute), reader); err == nil {
		t.Fatal("historical source floor authorized a new runtime operation")
	}
	changedSource := claim
	changedSource.SourceTreeSHA256 = strings.Repeat("f", 64)
	changedSourceVerified, err := VerifyContainerCurrent(ctx, makeBundle(changedSource, signer), roots, target, now, now.Add(time.Minute), reader)
	if err != nil || changedSourceVerified.ReleaseIdentity() == verified.ReleaseIdentity() {
		t.Fatalf("signed tree change did not change immutable content identity: %+v %v", changedSourceVerified, err)
	}
	indexed := func(index []byte) ContainerBundle {
		t.Helper()
		c := claim
		c.QualificationSHA256 = fmt.Sprintf("%x", sha256.Sum256(index))
		qualification := qualifier
		qualification.Candidate.QualificationSHA256 = c.QualificationSHA256
		payload, err := trust.EncodePayload(qualification)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := trust.Sign(payload, ProductionQualificationScope(qualification.Candidate), now, now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		c.Production.Qualification, err = trust.EncodeEnvelope(proof)
		if err != nil {
			t.Fatal(err)
		}
		result := makeBundle(c, signer)
		result.Index = index
		return result
	}
	index := []byte(fmt.Sprintf(" {\n\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:%s\",\"size\":42,\"platform\":{\"os\":\"linux\",\"architecture\":\"arm64\"}}]}\n", strings.Repeat("a", 64)))
	withIndex := indexed(index)
	transport, err := json.Marshal(withIndex)
	if err != nil {
		t.Fatal(err)
	}
	var transported ContainerBundle
	if err := json.Unmarshal(transport, &transported); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyContainerCurrent(ctx, transported, roots, target, now, now.Add(time.Minute), reader); err != nil {
		t.Fatal("exact retained OCI index did not survive transport: ", err)
	}
	if _, err := VerifyContainerHistorical(transported, roots, target); err != nil {
		t.Fatal("historical index membership: ", err)
	}
	missingIndex := withIndex
	missingIndex.Index = nil
	if _, err := VerifyContainerHistorical(missingIndex, roots, target); err == nil {
		t.Fatal("signed index digest accepted without retained membership bytes")
	}
	wrongIndex := withIndex
	wrongIndex.Index = []byte(strings.ReplaceAll(string(index), "arm64", "amd64"))
	if _, err := VerifyContainerHistorical(wrongIndex, roots, target); err == nil {
		t.Fatal("modified index bytes accepted")
	}
	if _, err := VerifyContainerCurrent(ctx, indexed(wrongIndex.Index), roots, target, now, now.Add(time.Minute), reader); err == nil {
		t.Fatal("signed index without target architecture accepted")
	}
	wrongChild := []byte(strings.ReplaceAll(string(index), strings.Repeat("a", 64), strings.Repeat("d", 64)))
	if _, err := VerifyContainerCurrent(ctx, indexed(wrongChild), roots, target, now, now.Add(time.Minute), reader); err == nil {
		t.Fatal("signed index with wrong child accepted")
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
	for _, source := range []string{"http://github.com/TerraScale/ts-auth", "https://user:password@github.com/TerraScale/ts-auth", "https://github.com/TerraScale/ts-auth?ref=main"} {
		invalid := claim
		invalid.SourceRepository = source
		if _, err := VerifyContainerHistorical(makeBundle(invalid, signer), roots, target); err == nil {
			t.Fatalf("invalid signed source repository accepted: %s", source)
		}
	}
	invalidTree := claim
	invalidTree.SourceTreeSHA256 = strings.Repeat("z", 64)
	if _, err := VerifyContainerHistorical(makeBundle(invalidTree, signer), roots, target); err == nil {
		t.Fatal("invalid source tree accepted")
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
	if _, err := VerifyContainerHistorical(wrongSigner, roots, target); err == nil {
		t.Fatal("historical floor bypassed root-authorized sequence signer")
	}
}
