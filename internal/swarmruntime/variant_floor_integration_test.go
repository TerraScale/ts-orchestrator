package swarmruntime

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

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

func TestFunctionWorkerVariantFloorIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	node := serviceStart(t, ctx, serviceConfig(t, "ts-gru-1", "manager"))
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := trust.KeyID(public)
	roots := trust.Keyring{keyID: public}
	now := time.Now().UTC().Truncate(time.Second)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "worker-variants", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: keyID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: "function-worker", Environment: "production", SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	signedMigration, err := release.SignSequenceMigration(migration, now, key)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(signedMigration)
	migrationSHA, _ := trust.Fingerprint(signedMigration)
	evidence := []byte("retained qualified mixed architecture runtime evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(evidence) }))
	defer server.Close()
	reader := func(ctx context.Context, _ string) (io.ReadCloser, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			return nil, err
		}
		response, err := server.Client().Do(request)
		if err != nil {
			return nil, err
		}
		return response.Body, nil
	}
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":42,"platform":{"os":"linux","architecture":"arm64"}},{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":42,"platform":{"os":"linux","architecture":"amd64"}}]}`, strings.Repeat("a", 64), strings.Repeat("d", 64)))
	indexSHA := fmt.Sprintf("%x", sha256.Sum256(index))
	build := func(arch string, sequence uint64, region, source string) (ServiceIntent, release.VerifiedContainer) {
		t.Helper()
		entry, _ := catalog.CellForOCIRegion(region)
		intent := ServiceIntent{ID: entityid.Derive("function-worker-release", "production", region), Role: "function-worker", Region: region, Environment: "production", Architecture: arch}
		digest := strings.Repeat("a", 64)
		if arch == "amd64" {
			digest = strings.Repeat("d", 64)
		}
		candidate := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: digest, QualificationSHA256: indexSHA, Cell: entry.Cell, Environment: intent.Environment, Runtime: release.ProductionRuntime, Architecture: arch, Role: intent.Role}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		proof, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(proof)
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/platform/function-worker@sha256:" + digest, SourceRepository: "https://github.com/TerraScale/ts-orchestrator", SourceRevision: source, SourceTreeSHA256: strings.Repeat("e", 64), Cell: entry.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: arch, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: indexSHA, Production: release.ProductionProof{Qualification: proofWire}}
		target := release.ContainerTarget{Cell: entry.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: arch}
		payload, _ = trust.EncodePayload(claim)
		signed, err := trust.Sign(payload, release.ContainerScope(target), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		verified, err := release.VerifyContainerCurrent(ctx, release.ContainerBundle{Claim: wire, Migration: migrationWire, Index: index}, roots, target, now, now.Add(45*time.Second), reader)
		if err != nil {
			t.Fatal(err)
		}
		return intent, verified
	}
	retained := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	arm, armProof := build("arm64", 101, "sa-saopaulo-1", strings.Repeat("c", 40))
	amd, amdProof := build("amd64", 101, "sa-saopaulo-1", strings.Repeat("c", 40))
	armFloor, err := reserveReleaseFloor(ctx, client, arm, armProof, roots, retained, 0)
	if err != nil {
		t.Fatal(err)
	}
	amdFloor, err := reserveReleaseFloor(ctx, client, amd, amdProof, roots, retained, 0)
	if err != nil {
		t.Fatal("same-sequence sibling rejected: ", err)
	}
	if armFloor.ID == amdFloor.ID || armFloor.Spec.Annotations.Labels[labelReleaseArchitecture] != "arm64" || amdFloor.Spec.Annotations.Labels[labelReleaseArchitecture] != "amd64" {
		t.Fatal("qualified variants share durable floor")
	}
	_, nextAMD := build("amd64", 102, "sa-saopaulo-1", strings.Repeat("f", 40))
	if _, err := reserveReleaseFloor(ctx, client, amd, nextAMD, roots, retained, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveReleaseFloor(ctx, client, arm, armProof, roots, retained, 0); err != nil {
		t.Fatal("advancing sibling revoked ARM floor: ", err)
	}
	if _, err := reserveReleaseFloor(ctx, client, amd, amdProof, roots, retained, 0); err == nil {
		t.Fatal("variant highwater regressed")
	}
	legacyIntent, legacyProof := build("arm64", 500, "us-sanjose-1", strings.Repeat("c", 40))
	retained.Cell = "SFO"
	original, err := reserveReleaseFloor(ctx, client, legacyIntent, legacyProof, roots, retained, 0)
	if err != nil {
		t.Fatal(err)
	}
	legacySpec := original.Spec.Copy()
	oldIdentity := sha256.Sum256([]byte(legacyIntent.Environment + "/" + legacyIntent.Region + "/" + legacyIntent.Role))
	legacySpec.Annotations.Name = fmt.Sprintf("ts-release-%x", oldIdentity[:16])
	delete(legacySpec.Annotations.Labels, labelReleaseArchitecture)
	if _, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: legacySpec}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: original.ID}); err != nil {
		t.Fatal(err)
	}
	legacyIntent, olderProof := build("arm64", 101, "us-sanjose-1", strings.Repeat("c", 40))
	if _, err := reserveReleaseFloor(ctx, client, legacyIntent, olderProof, roots, retained, 0); err == nil {
		t.Fatal("missing variant floor erased retained unpartitioned highwater")
	}
}
