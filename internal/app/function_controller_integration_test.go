package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/grpc"
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
	bucket := newChannelBucket()
	location := releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	controller := functionController{config: functionControllerConfig{Authority: runtime,
		Material: functionmaterial.Controller{Reader: functionmaterial.Reader{Authority: runtime, Artifacts: artifacts, Roots: func() trust.Keyring { return signer.roots }}},
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
	object, err := artifacts.Get(t.Context(), signer.claim.Digest)
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
		registration := host.Registration{ID: entityid.New(), Cell: "gru", Environment: "canary"}
		binding := functionmaterial.Binding{HostID: registration.ID, TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25),
			NodeID: strings.Repeat("c", 25), InstanceID: "ocid1.instance.oc1.sa-saopaulo-1.function", Region: "sa-saopaulo-1"}
		controller.config.Client = functionRecipientManager{
			task: &api.Task{ID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID, DesiredState: api.TaskStateRunning},
			service: &api.Service{ID: binding.ServiceID, Spec: api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{
				swarmruntime.LabelFunctionTenant: signer.claim.TenantID, swarmruntime.LabelFunctionID: signer.claim.FunctionID}}}},
			node: &api.Node{ID: binding.NodeID, Spec: api.NodeSpec{Membership: api.NodeMembershipAccepted, Availability: api.NodeAvailabilityActive,
				Annotations: api.Annotations{Name: registration.ID, Labels: map[string]string{swarmruntime.LabelRegion: binding.Region,
					swarmruntime.LabelHostRole: "wasm", swarmruntime.LabelExecutionScope: "tenant", swarmruntime.LabelInstanceID: binding.InstanceID}}},
				Status: api.NodeStatus{State: api.NodeStatus_READY}},
		}
		target := release.ContainerTarget{Cell: "GRU", Environment: "canary", Role: swarmruntime.FunctionWorkerRole, Architecture: "arm64"}
		bundle, evidence := signer.worker(t, target)
		controller.config.Worker = func(context.Context, release.VerifiedFunction) (functionWorkerRelease, error) {
			return functionWorkerRelease{Architecture: target.Architecture, Bundle: bundle}, nil
		}
		controller.config.Evidence = evidence
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		deadline, _ := ctx.Deadline()
		if _, err := release.VerifyContainerCurrent(ctx, bundle, signer.roots, target, time.Now(), deadline, evidence); err != nil {
			t.Fatalf("independent worker qualification through request deadline: %v", err)
		}
		if _, err := controller.recipient(ctx, registration, binding); !errors.Is(err, trust.ErrExpired) {
			t.Fatalf("worker expiring before potential grant must fail its signed lifetime: %v", err)
		}
	})
}

type functionRecipientManager struct {
	api.ControlClient
	task    *api.Task
	service *api.Service
	node    *api.Node
}

func (manager functionRecipientManager) GetTask(context.Context, *api.GetTaskRequest, ...grpc.CallOption) (*api.GetTaskResponse, error) {
	return &api.GetTaskResponse{Task: manager.task}, nil
}

func (manager functionRecipientManager) GetService(context.Context, *api.GetServiceRequest, ...grpc.CallOption) (*api.GetServiceResponse, error) {
	return &api.GetServiceResponse{Service: manager.service}, nil
}

func (manager functionRecipientManager) GetNode(context.Context, *api.GetNodeRequest, ...grpc.CallOption) (*api.GetNodeResponse, error) {
	return &api.GetNodeResponse{Node: manager.node}, nil
}

type functionPublicationSigner struct {
	claim      release.FunctionClaim
	module     []byte
	roots      trust.Keyring
	root       ed25519.PrivateKey
	leaf       ed25519.PrivateKey
	delegation trust.Envelope
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
	return functionPublicationSigner{claim: claim, module: module, roots: roots, root: rootPrivate, leaf: leaf, delegation: delegation}
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
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
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
	qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
		Candidate: release.ProductionExpectation{SourceRevision: strings.Repeat("b", 40), ArtifactSHA256: strings.Repeat("c", 64), QualificationSHA256: strings.Repeat("d", 64),
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
	return release.ContainerBundle{Claim: sign(claim, scope, signer.leaf, now.Add(time.Minute)), Delegation: delegationWire, Migration: migrationWire},
		func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(evidence)), nil
		}
}
