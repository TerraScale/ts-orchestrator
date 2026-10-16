package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
)

type functionIntentFixture struct {
	proof   release.VerifiedFunction
	revoked bool
}

type functionSlotExecutor struct{ serviceExecutor }

func (e functionSlotExecutor) Describe(ctx context.Context) (*api.NodeDescription, error) {
	description, err := e.serviceExecutor.Describe(ctx)
	if err == nil {
		description.Resources.Generic = []*api.GenericResource{genericresource.NewDiscrete(FunctionWorkerSlot, 1)}
	}
	return description, err
}

func (f *functionIntentFixture) CurrentFunction(_ context.Context, tenant, function string) (release.VerifiedFunction, error) {
	if f.revoked || f.proof.Claim().TenantID != tenant || f.proof.Claim().FunctionID != function {
		return release.VerifiedFunction{}, errors.New("function intent is not current")
	}
	return f.proof, nil
}

// Exercise actual CA admission, manager RPC, scheduler, Raft service CAS and
// release floors. The lifecycle fixture does not qualify container isolation.
func TestFunctionServiceManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	client, workerCfg, platform := serviceCluster(t, ctx)
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	wasmCfg := serviceConfig(t, "ts-gru-wasm", "wasm")
	wasmCfg.Admission.Region = "sa-saopaulo-1"
	wasmCfg.Admission.ManagerAddress = workerCfg.Admission.ManagerAddress
	wasmCfg.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	wasm, err := StartNode(ctx, wasmCfg, functionSlotExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := wasm.Stop(stop); err != nil {
			t.Error(err)
		}
	})
	if _, err := AdmitNode(ctx, client, wasm.ID(), wasmCfg.Admission); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := trust.KeyID(public)
	roots := trust.Keyring{keyID: public}
	now := time.Now().UTC().Truncate(time.Second)
	intent := FunctionServiceIntent{TenantID: entityid.Derive("tenant", t.Name()), FunctionID: "echo", Region: "sa-saopaulo-1", Environment: "production", Architecture: runtime.GOARCH}
	module := []byte("\x00asm\x01\x00\x00\x00")
	functionClaim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: intent.TenantID, FunctionID: intent.FunctionID, Revision: "first", Digest: fmt.Sprintf("%x", sha256.Sum256(module)), Bytes: int64(len(module)), Environment: intent.Environment, Cell: "GRU", Sequence: 1}
	scope := release.FunctionScope(functionClaim)
	encodedPublic, _ := trust.EncodeDelegatedPublicKey(public)
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: encodedPublic, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, _ := trust.EncodeEnvelope(delegation)
	functionProof := func(sequence uint64) release.VerifiedFunction {
		t.Helper()
		claim := functionClaim
		claim.Sequence = sequence
		signed, err := release.SignFunctionClaim(claim, module, delegation, roots, key, now, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		proof, err := release.VerifyFunctionCurrent(wire, delegationWire, module, roots, release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: sequence}, now)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	current := &functionIntentFixture{proof: functionProof(1)}
	evidence := []byte("test-only worker candidate isolation evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	readEvidence := func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "function-test", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: keyID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: FunctionWorkerRole, Environment: intent.Environment, SequenceFloor: 100}
	legacy := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		floor := legacy
		floor.Cell = cell
		migration.Regions = append(migration.Regions, floor)
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, key)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(migrationEnvelope)
	migrationSHA, _ := trust.Fingerprint(migrationEnvelope)
	bundle := func(role string) release.ContainerBundle {
		t.Helper()
		candidate := release.ProductionExpectation{SourceRevision: strings.Repeat("c", 40), ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: strings.Repeat("b", 64), Cell: "GRU", Environment: intent.Environment, Runtime: release.ProductionRuntime, Architecture: runtime.GOARCH, Role: role}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		proof, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(proof)
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "example.invalid/worker@sha256:" + strings.Repeat("a", 64), SourceRevision: candidate.SourceRevision, Cell: "GRU", Environment: intent.Environment, Role: role, Architecture: runtime.GOARCH, ReleaseSequence: 101, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: candidate.QualificationSHA256, Production: release.ProductionProof{Qualification: proofWire}}
		payload, _ = trust.EncodePayload(claim)
		signed, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: role, Architecture: runtime.GOARCH}), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		return release.ContainerBundle{Claim: wire, Migration: migrationWire}
	}
	probe := func(_ context.Context, task *api.Task) error {
		if task.NodeID != wasm.ID() || task.NodeID == platform.ID() {
			return errors.New("function scheduled outside admitted WASM host")
		}
		return nil
	}
	qualified := bundle(FunctionWorkerRole)
	created, err := ApplyFunctionService(ctx, client, intent, current, qualified, roots, legacy, readEvidence, probe)
	if err != nil {
		t.Fatal(err)
	}
	if created.Spec.Annotations.Labels[LabelFunctionProof] != current.proof.EnvelopeSHA256() || created.Spec.Annotations.Labels[LabelRole] != FunctionWorkerRole {
		t.Fatal("signed function identity missing")
	}
	workerProof, err := release.VerifyContainerCurrent(ctx, qualified, roots, release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: FunctionWorkerRole, Architecture: runtime.GOARCH}, now, now.Add(time.Minute), readEvidence)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil || len(tasks.Tasks) != 1 {
		t.Fatalf("current function task: %+v %v", tasks, err)
	}
	if err := intent.VerifyTask(tasks.Tasks[0], created, current.proof, workerProof); err != nil {
		t.Fatal(err)
	}
	forged := tasks.Tasks[0].Copy()
	forged.Spec.ForceUpdate++
	if err := intent.VerifyTask(forged, created, current.proof, workerProof); err == nil {
		t.Fatal("altered task accepted for material grant")
	}
	version := created.Meta.Version.Index
	replayed, err := ApplyFunctionService(ctx, client, intent, current, qualified, roots, legacy, readEvidence, probe)
	if err != nil || replayed.ID != created.ID || replayed.Meta.Version.Index != version {
		t.Fatalf("function replay not idempotent: %+v %v", replayed, err)
	}
	if _, err := ApplyFunctionService(ctx, client, intent, current, bundle("ts-auth"), roots, legacy, readEvidence, probe); err == nil {
		t.Fatal("platform worker qualification admitted for tenant functions")
	}
	current.revoked = true
	if _, err := ApplyFunctionService(ctx, client, intent, current, qualified, roots, legacy, readEvidence, probe); err == nil {
		t.Fatal("revoked current function intent admitted")
	}
	current.revoked = false
	current.proof = functionProof(2)
	updated, err := ApplyFunctionService(ctx, client, intent, current, qualified, roots, legacy, readEvidence, probe)
	if err != nil || updated.ID != created.ID || updated.Spec.Task.ForceUpdate == created.Spec.Task.ForceUpdate {
		t.Fatalf("renewed function proof did not replace stable worker task: %+v %v", updated, err)
	}
	// The upstream scheduler must leave a second worker pending rather than
	// assigning a fixed-port collision for the local executor to reject forever.
	second := updated.Spec.Copy()
	second.Annotations.Name += "-slot"
	blocked, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: second})
	if err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{blocked.Service.ID}}})
		return err == nil && len(tasks.Tasks) == 1 && tasks.Tasks[0].Status.State == api.TaskStatePending && tasks.Tasks[0].NodeID == ""
	})
}
