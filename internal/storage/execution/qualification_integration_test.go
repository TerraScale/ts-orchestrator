package execution

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
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// This fixture signs synthetic evidence only in a test binary. It tests the
// consumer; it never qualifies a TerraBase build or supplies production proof.
func TestStatefulQualificationHTTPIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	qualifierPublic, qualifier, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := trust.KeyID(rootPublic)
	qualifierID, _ := trust.KeyID(qualifierPublic)
	roots := trust.Keyring{rootID: rootPublic, qualifierID: qualifierPublic}
	now := time.Now().UTC().Truncate(time.Second)
	target := release.ContainerTarget{Cell: "GRU", Environment: "production", Role: "terrabase", Architecture: "amd64"}
	data := RetainedData{DatabaseID: entityid.Derive("database", "fixture"), PartitionID: entityid.Derive("partition", "fixture"), VolumeID: "ocid1.volume.fixture", FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4", DiskFormatSHA256: strings.Repeat("d", 64), SourceArtifactSHA256: strings.Repeat("e", 64), SourceTreeSHA256: strings.Repeat("f", 64), SourceArchitecture: "amd64"}
	cpu := CPUProfile{Architecture: "amd64", FeaturesSHA256: strings.Repeat("c", 64)}
	var lock sync.RWMutex
	blobs := make(map[string][]byte)
	put := func(wire []byte) string {
		digest := fmt.Sprintf("%x", sha256.Sum256(wire))
		lock.Lock()
		blobs[digest] = wire
		lock.Unlock()
		return digest
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.RLock()
		wire, ok := blobs[strings.TrimPrefix(r.URL.Path, "/evidence/")]
		lock.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	open := func(ctx context.Context, digest string) (io.ReadCloser, error) {
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
	sign := func(value any, scope trust.Scope, key ed25519.PrivateKey) []byte {
		t.Helper()
		payload, err := trust.EncodePayload(value)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, scope, now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "fixture", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: rootID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(rootPublic), Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, root)
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
	proof := StatefulQualification{Schema: StatefulQualificationSchema, CandidateSourceTreeSHA256: strings.Repeat("b", 64), Data: data, SourceCPU: cpu, TargetCPU: cpu, DiskFormatSHA256: data.DiskFormatSHA256}
	proof.ResultData = data
	configWire := []byte(`{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/usr/local/bin/terrabase"],"User":"65532:65532"},"rootfs":{"type":"layers","diff_ids":[]}}`)
	configSHA := put(configWire)
	manifestWire := []byte(fmt.Sprintf(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%d},"layers":[]}`, configSHA, len(configWire)))
	imageDigest := put(manifestWire)
	proof.ImageManifest = release.ProductionGateEvidence{Gate: "image-manifest", SHA256: imageDigest, Bytes: int64(len(manifestWire)), CompletedAt: now}
	proof.ImageConfig = release.ProductionGateEvidence{Gate: "image-config", SHA256: configSHA, Bytes: int64(len(configWire)), CompletedAt: now}
	proof.ResultData.SourceArtifactSHA256 = imageDigest
	proof.ResultData.SourceTreeSHA256 = proof.CandidateSourceTreeSHA256
	for _, gate := range []string{"retained-restart", "restore", "replication-catchup", "durable-drain", "sigterm", "cpu-format-transition"} {
		wire := []byte("controlled test-only " + gate + " evidence")
		proof.Scenarios = append(proof.Scenarios, release.ProductionGateEvidence{Gate: gate, SHA256: put(wire), Bytes: int64(len(wire)), CompletedAt: now})
	}
	makeBundle := func(p StatefulQualification) release.ContainerBundle {
		t.Helper()
		wire, err := trust.EncodePayload(p)
		if err != nil {
			t.Fatal(err)
		}
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/platform/terrabase@sha256:" + imageDigest, SourceRepository: "https://github.com/TerraScale/terrascale", SourceRevision: strings.Repeat("a", 40), SourceTreeSHA256: proof.CandidateSourceTreeSHA256, Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: 101, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: strings.Repeat("2", 64)}
		ha := []byte("controlled runtime fixture evidence")
		expected := release.ProductionExpectation{SourceRevision: claim.SourceRevision, ArtifactSHA256: imageDigest, QualificationSHA256: claim.QualificationSHA256, Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, Runtime: release.ProductionRuntime}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: expected, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: put(ha), Bytes: int64(len(ha)), CompletedAt: now}, {Gate: "workload-safety", SHA256: put(wire), Bytes: int64(len(wire)), CompletedAt: now}}}
		claim.Production.Qualification = sign(qualification, release.ProductionQualificationScope(expected), qualifier)
		return release.ContainerBundle{Claim: sign(claim, release.ContainerScope(target), root), Migration: migrationWire}
	}
	bundle := makeBundle(proof)
	verified, err := VerifyStatefulCurrent(ctx, bundle, roots, target, data, cpu, now, now.Add(time.Minute), open)
	if err != nil || verified.Data() != data || verified.CPU() != cpu || verified.SHA256() == "" {
		t.Fatalf("signed typed consumer: %+v %v", verified, err)
	}

	retained, err := VerifyRetainedProvenance(ctx, bundle, roots, target, proof.ResultData, open)
	if err != nil || retained != proof.ResultData {
		t.Fatalf("signed prior writer provenance: %+v %v", retained, err)
	}
	unknownFormat := proof.ResultData
	unknownFormat.DiskFormatSHA256 = ""
	retained, err = VerifyRetainedProvenance(ctx, bundle, roots, target, unknownFormat, open)
	if err != nil || retained.DiskFormatSHA256 != proof.ResultData.DiskFormatSHA256 {
		t.Fatalf("format derived only from signed retained result: %+v %v", retained, err)
	}
	wrongVolume := proof.ResultData
	wrongVolume.VolumeID = "ocid1.volume.foreign"
	if _, err := VerifyRetainedProvenance(ctx, bundle, roots, target, wrongVolume, open); err == nil {
		t.Fatal("retained proof transplanted to another volume")
	}
	for _, test := range []struct {
		name   string
		mutate func(*StatefulQualification)
	}{
		{"source-tree", func(p *StatefulQualification) { p.CandidateSourceTreeSHA256 = strings.Repeat("9", 64) }},
		{"retained-volume", func(p *StatefulQualification) { p.Data.VolumeID = "ocid1.volume.other" }},
		{"disk-format", func(p *StatefulQualification) { p.DiskFormatSHA256 = strings.Repeat("8", 64) }},
		{"cpu-features", func(p *StatefulQualification) { p.TargetCPU.FeaturesSHA256 = strings.Repeat("7", 64) }},
		{"missing-restore", func(p *StatefulQualification) { p.Scenarios = append(p.Scenarios[:1], p.Scenarios[2:]...) }},
		{"future-scenario", func(p *StatefulQualification) { p.Scenarios[0].CompletedAt = now.Add(time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proof
			candidate.Scenarios = append([]release.ProductionGateEvidence(nil), proof.Scenarios...)
			test.mutate(&candidate)
			if _, err := VerifyStatefulCurrent(ctx, makeBundle(candidate), roots, target, data, cpu, now, now.Add(time.Minute), open); err == nil {
				t.Fatal("invalid signed stateful proof admitted")
			}
		})
	}
	if _, err := VerifyStatefulCurrent(ctx, bundle, roots, target, data, cpu, now, now.Add(2*time.Hour), open); err == nil {
		t.Fatal("expired proof admitted")
	}
	lock.Lock()
	blobs[proof.Scenarios[0].SHA256] = []byte("changed retained scenario")
	lock.Unlock()
	if _, err := VerifyStatefulCurrent(ctx, bundle, roots, target, data, cpu, now, now.Add(time.Minute), open); err == nil {
		t.Fatal("tampered nested retained scenario admitted")
	}
	lock.Lock()
	delete(blobs, proof.Scenarios[0].SHA256)
	lock.Unlock()
	if _, err := VerifyStatefulCurrent(ctx, bundle, roots, target, data, cpu, now, now.Add(time.Minute), open); err == nil {
		t.Fatal("missing nested retained scenario admitted")
	}
}
