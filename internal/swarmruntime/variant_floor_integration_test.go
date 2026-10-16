package swarmruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func serviceAllocationStore(t *testing.T, namespace, bucket string) release.SequenceLocation {
	t.Helper()
	directory := t.TempDir()
	var lock sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned OCI request", http.StatusUnauthorized)
			return
		}
		nameSHA := sha256.Sum256([]byte(r.URL.Path))
		name := filepath.Join(directory, hex.EncodeToString(nameSHA[:]))
		lock.Lock()
		defer lock.Unlock()
		current, err := os.ReadFile(name)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		found := err == nil
		etag := fmt.Sprintf(`"%x"`, sha256.Sum256(current))
		switch r.Method {
		case http.MethodGet:
			if !found {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("ETag", etag)
			_, _ = w.Write(current)
		case http.MethodPut:
			if r.Header.Get("If-None-Match") == "*" && found || r.Header.Get("If-Match") != "" && (!found || r.Header.Get("If-Match") != etag) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			if r.Header.Get("If-Match") == "" && r.Header.Get("If-None-Match") == "" {
				http.Error(w, "missing CAS", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := os.WriteFile(name, body, 0600); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil))
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	client.HTTPClient = serviceAllocationHTTPClient{server}
	policy := common.NoRetryPolicy()
	client.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &policy})
	return release.SequenceLocation{Client: client, Namespace: namespace, Bucket: bucket}
}

type serviceAllocationHTTPClient struct{ server *httptest.Server }

func (client serviceAllocationHTTPClient) Do(request *http.Request) (*http.Response, error) {
	cloned := request.Clone(request.Context())
	address := *request.URL
	cloned.URL = &address
	cloned.URL.Scheme = "http"
	cloned.URL.Host = strings.TrimPrefix(client.server.URL, "http://")
	return client.server.Client().Do(cloned)
}

func serviceSequenceEvidence(t *testing.T, ctx context.Context, location release.SequenceLocation, migration trust.Envelope, claim release.ContainerClaim, roots trust.Keyring, signer ed25519.PrivateKey) []byte {
	t.Helper()
	if err := location.ImportMigration(ctx, migration, roots, claim.Role, claim.Environment, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	sequence, wire, err := location.AllocateWithEvidence(ctx, release.SequenceIdentity{Role: claim.Role, Environment: claim.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family}, roots, signer)
	if err != nil || sequence != claim.ReleaseSequence {
		t.Fatalf("allocate signed container sequence: got %d, want %d: %v", sequence, claim.ReleaseSequence, err)
	}
	return wire
}

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
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := trust.KeyID(rootPublic)
	roots := trust.Keyring{rootID: rootPublic}
	now := time.Now().UTC().Truncate(time.Second)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "worker-variants", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: keyID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: "function-worker", Environment: "production", SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	signedMigration, err := release.SignSequenceMigration(migration, now, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(signedMigration)
	migrationSHA, _ := trust.Fingerprint(signedMigration)
	allocations := serviceAllocationStore(t, migration.Namespace, migration.Bucket)
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
	build := func(arch string, sequence uint64, region, source string, root []byte) (ServiceIntent, release.ContainerBundle) {
		t.Helper()
		if root == nil {
			root = index
		}
		rootSHA := fmt.Sprintf("%x", sha256.Sum256(root))
		entry, _ := catalog.CellForOCIRegion(region)
		intent := ServiceIntent{ID: entityid.Derive("function-worker-release", "production", region), Role: "function-worker", Region: region, Environment: "production", Architecture: arch}
		digest := strings.Repeat("a", 64)
		if arch == "amd64" {
			digest = strings.Repeat("d", 64)
		}
		candidate := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: digest, QualificationSHA256: rootSHA, Cell: entry.Cell, Environment: intent.Environment, Runtime: release.ProductionRuntime, Architecture: arch, Role: intent.Role}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		proof, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(proof)
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/platform/function-worker@sha256:" + digest, SourceRepository: "https://github.com/TerraScale/ts-orchestrator", SourceRevision: source, SourceTreeSHA256: strings.Repeat("e", 64), Cell: entry.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: arch, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: rootSHA, Production: release.ProductionProof{Qualification: proofWire}}
		family, err := claim.WorkerFamilyDigest()
		if err != nil {
			t.Fatal(err)
		}
		identity := struct {
			Role           string `json:"role"`
			Environment    string `json:"environment"`
			SourceRevision string `json:"source_revision"`
			ManifestSHA256 string `json:"manifest_sha256"`
		}{claim.Role, claim.Environment, source, family}
		reservationPayload, _ := trust.EncodePayload(struct {
			Sequence uint64 `json:"sequence"`
			Identity any    `json:"identity"`
		}{sequence, identity})
		reservationScope := release.SequenceMigrationScope(claim.Role, claim.Environment)
		reservationScope.Domain = "terrascale.release.sequence-reservation"
		reservationScope.Slot = "reservation"
		reservation, err := trust.Sign(reservationPayload, reservationScope, now, now.Add(release.MaxReceiptLifetime), key)
		if err != nil {
			t.Fatal(err)
		}
		sequenceWire, _ := trust.EncodePayload(struct {
			Schema      string         `json:"schema"`
			Sequence    uint64         `json:"sequence"`
			Identity    any            `json:"identity"`
			Migration   trust.Envelope `json:"migration"`
			Reservation trust.Envelope `json:"reservation"`
		}{"terrascale.release.sequence.v1", sequence, identity, signedMigration, reservation})
		target := release.ContainerTarget{Cell: entry.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: arch}
		grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(public), Capabilities: []trust.Capability{{Domain: release.ContainerClaimDomain, DeploymentID: release.ContainerScope(target).DeploymentID, Cell: target.Cell, Environment: target.Environment, Role: target.Role, Slots: []string{"linux-" + arch}, Actions: []string{"sign"}}}}, now, now.Add(time.Hour), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		grantWire, _ := trust.EncodeEnvelope(grant)
		payload, _ = trust.EncodePayload(claim)
		signed, err := trust.Sign(payload, release.ContainerScope(target), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		return intent, release.ContainerBundle{Claim: wire, Delegation: grantWire, Migration: migrationWire, Index: root, Sequence: sequenceWire}
	}
	verify := func(intent ServiceIntent, bundle release.ContainerBundle) (release.VerifiedContainer, error) {
		entry, _ := catalog.CellForOCIRegion(intent.Region)
		return release.VerifyContainerCurrent(ctx, bundle, roots, release.ContainerTarget{Cell: entry.Cell, Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}, now, now.Add(45*time.Second), reader, allocations)
	}
	retainedReservations := map[uint64][]byte{}
	admit := func(arch string, sequence uint64, region, source string) (ServiceIntent, release.VerifiedContainer) {
		t.Helper()
		intent, bundle := build(arch, sequence, region, source, nil)
		if retainedReservations[sequence] == nil {
			envelope, err := trust.DecodeEnvelope(bundle.Claim)
			if err != nil {
				t.Fatal(err)
			}
			var claim release.ContainerClaim
			if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
				t.Fatal(err)
			}
			retainedReservations[sequence] = serviceSequenceEvidence(t, ctx, allocations, signedMigration, claim, roots, key)
		}
		bundle.Sequence = retainedReservations[sequence]
		verified, err := verify(intent, bundle)
		if err != nil {
			t.Fatal(err)
		}
		return intent, verified
	}
	retained := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	arm, armProof := admit("arm64", 101, "sa-saopaulo-1", strings.Repeat("c", 40))
	amd, amdProof := admit("amd64", 101, "sa-saopaulo-1", strings.Repeat("c", 40))
	armFloor, err := reserveReleaseFloor(ctx, client, arm, armProof, roots, retained, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, divergence := range []struct {
		name   string
		source string
		root   []byte
	}{
		{"source", strings.Repeat("f", 40), nil},
		{"index", strings.Repeat("c", 40), []byte(strings.Replace(string(index), `"schemaVersion":2`, `"annotations":{"release":"divergent"},"schemaVersion":2`, 1))},
	} {
		t.Run(divergence.name, func(t *testing.T) {
			intent, conflicting := build("amd64", 101, "sa-saopaulo-1", divergence.source, divergence.root)
			if _, err := verify(intent, conflicting); err == nil {
				t.Fatal("independently signed divergent sibling replaced the allocated family")
			}
			name, err := releaseFloorName(amd, amdProof)
			if err != nil {
				t.Fatal(err)
			}
			floors, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
			if err != nil || len(floors.Configs) != 0 {
				t.Fatalf("refused family changed the variant floor: %v", err)
			}
		})
	}
	amdFloor, err := reserveReleaseFloor(ctx, client, amd, amdProof, roots, retained, 0)
	if err != nil {
		t.Fatal("same-sequence sibling rejected: ", err)
	}
	if armFloor.ID == amdFloor.ID || armFloor.Spec.Annotations.Labels[labelReleaseArchitecture] != "arm64" || amdFloor.Spec.Annotations.Labels[labelReleaseArchitecture] != "amd64" {
		t.Fatal("qualified variants share durable floor")
	}
	_, nextAMD := admit("amd64", 102, "sa-saopaulo-1", strings.Repeat("f", 40))
	if _, err := reserveReleaseFloor(ctx, client, amd, nextAMD, roots, retained, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := reserveReleaseFloor(ctx, client, arm, armProof, roots, retained, 0); err != nil {
		t.Fatal("advancing sibling revoked ARM floor: ", err)
	}
	if _, currentARM := admit("arm64", 101, "sa-saopaulo-1", strings.Repeat("c", 40)); currentARM.ReleaseIdentity() != armProof.ReleaseIdentity() {
		t.Fatal("latest global allocation revoked the retained ARM generation")
	}
	if _, err := reserveReleaseFloor(ctx, client, amd, amdProof, roots, retained, 0); err == nil {
		t.Fatal("variant highwater regressed")
	}
	legacyIntent, legacyProof := admit("arm64", 103, "us-sanjose-1", strings.Repeat("d", 40))
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
	legacyIntent, olderProof := admit("arm64", 101, "us-sanjose-1", strings.Repeat("c", 40))
	if _, err := reserveReleaseFloor(ctx, client, legacyIntent, olderProof, roots, retained, 0); err == nil {
		t.Fatal("missing variant floor erased retained unpartitioned highwater")
	}
}
