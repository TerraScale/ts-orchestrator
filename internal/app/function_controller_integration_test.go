package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestFunctionControllerIngestsSignedChannelIntoDurableIntent(t *testing.T) {
	js := testRolloutJetStream(t)
	runtime, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: entityid.Derive("deployment", "function-controller-test"),
		Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	artifacts, err := js.CreateObjectStore(t.Context(), jetstream.ObjectStoreConfig{Bucket: delivery.ArtifactBucket})
	if err != nil {
		t.Fatal(err)
	}
	signer := newFunctionPublicationSigner(t)
	roots, err := newRootRegistry(signer.roots, trust.ChainIdentity{DeploymentID: entityid.Derive("deployment", "function-controller-test"),
		Cell: "gru", Environment: "canary"}, trust.RootChain{Version: 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	publishFunctionRootHistory(t, js, roots)
	bucket := newChannelBucket()
	location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	controller := functionController{config: functionControllerConfig{Authority: runtime, JS: js, Roots: roots,
		Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Authority: runtime, Artifacts: artifacts, Roots: roots.current}},
		Channel:  &channelSource{location: &location}, Cell: "gru", Environment: "canary"}}
	epoch := runtime.Current().Epoch
	first := signer.proof(t, 42, "first")
	if err := releasechannel.PublishFunction(t.Context(), location, first); err != nil {
		t.Fatal(err)
	}
	if err := controller.ingest(t.Context(), epoch); err != nil {
		t.Fatal(err)
	}
	entry, err := runtime.ReadFunctionIntent(t.Context(), signer.claim.TenantID, signer.claim.FunctionID)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := authority.DecodeFunctionIntent(entry)
	if err != nil || intent.EnvelopeSHA256 != first.EnvelopeSHA256() || bytes.Contains(entry.Payload, signer.module) {
		t.Fatalf("durable signed metadata: %+v, %v", intent, err)
	}
	object, err := artifacts.Get(t.Context(), "sha256-"+signer.claim.Digest)
	if err != nil {
		t.Fatal(err)
	}
	module, readErr := io.ReadAll(object)
	if err := errors.Join(readErr, object.Close()); err != nil || !bytes.Equal(module, signer.module) {
		t.Fatalf("verified artifact bytes: %x, %v", module, err)
	}
	if err := controller.ingest(t.Context(), epoch); err != nil {
		t.Fatal(err)
	}
	replayed, err := runtime.ReadFunctionIntent(t.Context(), signer.claim.TenantID, signer.claim.FunctionID)
	if err != nil || replayed.Sequence != entry.Sequence {
		t.Fatalf("identical channel republished intent: %d, %v", replayed.Sequence, err)
	}
	next := signer.proof(t, 43, "second")
	if err := releasechannel.PublishFunction(t.Context(), location, next); err != nil {
		t.Fatal(err)
	}
	if err := controller.ingest(t.Context(), epoch); err != nil {
		t.Fatal(err)
	}
	for name, proof := range map[string]release.VerifiedFunction{"rollback": first, "equivocation": signer.proof(t, 43, "other")} {
		t.Run(name, func(t *testing.T) {
			if err := controller.ingestRelease(t.Context(), epoch, location, releasechannel.FunctionRelease{Envelope: proof.Envelope(), Delegation: proof.Delegation()}); err == nil {
				t.Fatal("stale or equivocated release admitted")
			}
		})
	}
	if err := controller.ingestRelease(t.Context(), epoch+1, location, releasechannel.FunctionRelease{Envelope: signer.proof(t, 44, "third").Envelope(), Delegation: first.Delegation()}); !errors.Is(err, authority.ErrFenced) {
		t.Fatalf("stale leader epoch: %v", err)
	}
	bucket.mu.Lock()
	bucket.objects[releasechannel.FunctionModuleObject(signer.claim.Digest)] = []byte("tampered module")
	bucket.mu.Unlock()
	if err := controller.ingest(t.Context(), epoch); err == nil {
		t.Fatal("tampered source bytes admitted")
	}
	current, err := controller.config.Material.Reader.CurrentFunction(t.Context(), signer.claim.TenantID, signer.claim.FunctionID)
	if err != nil || current.EnvelopeSHA256() != next.EnvelopeSHA256() {
		t.Fatalf("rejected publication changed retained function: %v", err)
	}
	entries, err := runtime.ListFunctionIntents(t.Context())
	if err != nil || len(entries) != 1 {
		t.Fatalf("reconciliation inventory: %d, %v", len(entries), err)
	}
	t.Run("worker qualification covers full material lifetime", func(t *testing.T) {
		controller.config.Client = newFunctionControlClient(t)
		target := release.ContainerTarget{Cell: "GRU", Environment: "canary", Role: swarmruntime.FunctionWorkerRole, Architecture: "arm64"}
		bundle, evidence := signer.worker(t, target)
		controller.config.Factory = signer.factory
		controller.config.Worker = func(context.Context, release.VerifiedFunction) (functionWorkerRelease, error) {
			return functionWorkerRelease{Architecture: target.Architecture, Bundle: bundle}, nil
		}
		controller.config.Evidence = evidence
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		allocations, err := currentContainerAllocations(ctx, signer.factory, bundle, signer.roots, target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := release.VerifyContainerCurrent(ctx, bundle, signer.roots, target, time.Now(), deadline, evidence, allocations); err != nil {
			t.Fatalf("independent worker qualification through request deadline: %v", err)
		}
		if demand, err := functionDemandSource(controller.config)(ctx); !errors.Is(err, trust.ErrExpired) || demand != nil {
			t.Fatalf("worker expiring before potential grant must fail its signed lifetime: %v", err)
		}
	})
}

type functionPublicationSigner struct {
	claim       release.FunctionClaim
	module      []byte
	roots       trust.Keyring
	root        ed25519.PrivateKey
	leaf        ed25519.PrivateKey
	delegation  trust.Envelope
	factory     *ociclient.Factory
	allocations release.SequenceLocation
}

func newFunctionPublicationSigner(t *testing.T) functionPublicationSigner {
	t.Helper()
	module, err := hex.DecodeString("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI,
		TenantID: entityid.Derive("tenant", "function-controller"), FunctionID: "echo", Revision: "first",
		Digest: hex.EncodeToString(digest[:]), Bytes: int64(len(module)), Environment: "canary", Cell: "GRU", Sequence: 42}
	root, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leaf, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	scope := release.FunctionScope(claim)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: keyID, SubjectPublicKey: publicKey,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell,
			Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}},
	}, now.Add(-time.Minute), now.Add(2*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		t.Fatal(err)
	}
	factory, allocations := functionAllocationStore(t)
	return functionPublicationSigner{claim: claim, module: module, roots: roots, root: rootPrivate, leaf: leaf, delegation: delegation,
		factory: factory, allocations: allocations}
}

func (signer functionPublicationSigner) proof(t *testing.T, sequence uint64, revision string) release.VerifiedFunction {
	t.Helper()
	claim := signer.claim
	claim.Sequence, claim.Revision = sequence, revision
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := release.SignFunctionClaim(claim, signer.module, signer.delegation, signer.roots, signer.leaf, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.EncodeEnvelope(signer.delegation)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := release.VerifyFunctionCurrent(wire, delegation, signer.module, signer.roots,
		release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID,
			FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: sequence}, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (signer functionPublicationSigner) worker(t *testing.T, target release.ContainerTarget) (release.ContainerBundle, func(context.Context, string) (io.ReadCloser, error)) {
	t.Helper()
	return signer.workerUntil(t, target, time.Now().UTC().Truncate(time.Second).Add(time.Minute))
}

func (signer functionPublicationSigner) workerUntil(t *testing.T, target release.ContainerTarget, expires time.Time) (release.ContainerBundle, func(context.Context, string) (io.ReadCloser, error)) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	signerPublic := signer.leaf.Public().(ed25519.PublicKey)
	signerID, err := trust.KeyID(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := trust.EncodeDelegatedPublicKey(signerPublic)
	if err != nil {
		t.Fatal(err)
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "function-controller-test", Bucket: "gru-1-head", Region: "GRU",
		SignerKeyID: signerID, SignerPublicKey: encoded, Role: target.Role, Environment: target.Environment, SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("a", 64)})
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, signer.root)
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
	evidence := []byte("test worker qualification evidence")
	digest := sha256.Sum256(evidence)
	nativeDigest := strings.Repeat("c", 64)
	index := fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":42,"platform":{"os":"linux","architecture":%q}}]}`, "sha256:"+nativeDigest, target.Architecture)
	indexDigest := sha256.Sum256(index)
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: strings.Repeat("b", 40), ArtifactSHA256: nativeDigest, QualificationSHA256: hex.EncodeToString(indexDigest[:]),
			Cell: target.Cell, Environment: target.Environment, Runtime: release.ProductionRuntime, Architecture: target.Architecture, Role: target.Role}}
	for _, gate := range []string{"runtime-ha", "workload-safety"} {
		qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(evidence)), CompletedAt: now})
	}
	sign := func(payload any, scope trust.Scope, key ed25519.PrivateKey, expiry time.Time) []byte {
		t.Helper()
		body, err := trust.EncodePayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(body, scope, now, expiry, key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	scope := release.ContainerScope(target)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID, SubjectPublicKey: encoded,
		Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now, now.Add(2*time.Hour), signer.root)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		t.Fatal(err)
	}
	claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "example.invalid/worker@sha256:" + qualification.Candidate.ArtifactSHA256,
		SourceRepository: "https://example.invalid/function-worker", SourceRevision: qualification.Candidate.SourceRevision, SourceTreeSHA256: strings.Repeat("e", 64),
		Cell: target.Cell, Environment: target.Environment, Role: target.Role, Architecture: target.Architecture, ReleaseSequence: 101,
		SequenceMigrationSHA256: migrationSHA, QualificationSHA256: qualification.Candidate.QualificationSHA256,
		Production: release.ProductionProof{Qualification: sign(qualification, release.ProductionQualificationScope(qualification.Candidate), signer.root, now.Add(2*time.Hour))}}
	if err := signer.allocations.ImportMigration(t.Context(), migrationEnvelope, signer.roots, claim.Role, claim.Environment, now); err != nil {
		t.Fatal(err)
	}
	family, err := claim.WorkerFamilyDigest()
	if err != nil {
		t.Fatal(err)
	}
	sequence, sequenceWire, err := signer.allocations.AllocateWithEvidence(t.Context(), release.SequenceIdentity{
		Role: claim.Role, Environment: claim.Environment, SourceRevision: claim.SourceRevision, ManifestSHA256: family,
	}, signer.roots, signer.leaf)
	if err != nil || sequence != claim.ReleaseSequence {
		t.Fatalf("allocate signed worker sequence: got %d, want %d: %v", sequence, claim.ReleaseSequence, err)
	}
	return release.ContainerBundle{Claim: sign(claim, scope, signer.leaf, expires), Delegation: delegationWire, Migration: migrationWire, Sequence: sequenceWire, Index: index},
		func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(evidence)), nil
		}
}

func functionAllocationStore(t *testing.T) (*ociclient.Factory, release.SequenceLocation) {
	t.Helper()
	directory := t.TempDir()
	var lock sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			http.Error(w, "unsigned OCI request", http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/n/function-controller-test/b/gru-1-head/o/") {
			http.NotFound(w, r)
			return
		}
		nameSHA := sha256.Sum256([]byte(r.URL.Path))
		name := filepath.Join(directory, hex.EncodeToString(nameSHA[:]))
		lock.Lock()
		defer lock.Unlock()
		current, err := os.ReadFile(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
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
			if r.Header.Get("If-Match") == "" && r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "missing CAS", http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
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
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	tlsDialer := tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "objectstorage.sa-saopaulo-1.oraclecloud.com:443" {
			return nil, fmt.Errorf("unexpected OCI endpoint %q", address)
		}
		return tlsDialer.DialContext(ctx, network, server.Listener.Addr().String())
	}
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("allocation fixture requires its TLS OCI endpoint")
	}
	// The SDK must retain the local transport when production creates fresh clients.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
	})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	factory, err := ociclient.New(common.NewRawConfigurationProvider("tenancy", "user", "sa-saopaulo-1", "fingerprint", string(keyPEM), nil),
		ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	return factory, release.SequenceLocation{Client: client, Namespace: "function-controller-test", Bucket: "gru-1-head"}
}
