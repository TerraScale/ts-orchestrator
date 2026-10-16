package swarmruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

type functionRegistryRollbackExecutor struct{ functionSlotExecutor }

func (functionRegistryRollbackExecutor) Controller(task *api.Task) (exec.Controller, error) {
	if _, err := DecodeContainer(task); err != nil {
		return nil, err
	}
	return &serviceController{fail: task.ServiceAnnotations.Labels[labelReleaseSequence] == "102", done: make(chan struct{})}, nil
}

func TestFunctionRegistryManagerIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	client, workerConfig, platform := serviceCluster(t, ctx)
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	config := serviceConfig(t, "ts-gru-function-registry", "wasm")
	config.Admission.HostID = entityid.Derive("function-registry-host", t.Name())
	config.Admission.ManagerAddress = workerConfig.Admission.ManagerAddress
	config.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	node, err := StartNode(ctx, config, functionRegistryRollbackExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := node.Stop(stop); err != nil {
			t.Error(err)
		}
	})
	if _, err := AdmitNode(ctx, client, node.ID(), config.Admission); err != nil {
		t.Fatal(err)
	}
	rootPublic, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := trust.KeyID(rootPublic)
	signerID, _ := trust.KeyID(public)
	roots := trust.Keyring{rootID: rootPublic}
	now := time.Now().UTC().Truncate(time.Second)
	intent := FunctionServiceIntent{TenantID: entityid.Derive("registry-tenant", t.Name()), FunctionID: "echo", Region: "sa-saopaulo-1", Environment: "production", Architecture: runtime.GOARCH}
	module := []byte("\x00asm\x01\x00\x00\x00")
	claim := release.FunctionClaim{Schema: release.FunctionSchema, ABI: release.FunctionABI, TenantID: intent.TenantID, FunctionID: intent.FunctionID, Revision: "first", Digest: fmt.Sprintf("%x", sha256.Sum256(module)), Bytes: int64(len(module)), Environment: intent.Environment, Cell: "GRU", Sequence: 1}
	encodedPublic, _ := trust.EncodeDelegatedPublicKey(public)
	delegate := func(scope trust.Scope) (trust.Envelope, []byte) {
		t.Helper()
		envelope, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID, SubjectPublicKey: encodedPublic, Capabilities: []trust.Capability{{Domain: scope.Domain, DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, now.Add(-time.Minute), now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(envelope)
		return envelope, wire
	}
	functionDelegation, functionDelegationWire := delegate(release.FunctionScope(claim))
	functionProof := func(sequence uint64) release.VerifiedFunction {
		t.Helper()
		selected := claim
		selected.Sequence = sequence
		signed, err := release.SignFunctionClaim(selected, module, functionDelegation, roots, signer, now, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		proof, err := release.VerifyFunctionCurrent(wire, functionDelegationWire, module, roots, release.FunctionExpectation{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: sequence}, now)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	current := &functionIntentFixture{proof: functionProof(1)}
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "function-registry", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: signerID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: FunctionWorkerRole, Environment: intent.Environment, SequenceFloor: 100}
	legacy := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		floor := legacy
		floor.Cell = cell
		migration.Regions = append(migration.Regions, floor)
	}
	signedMigration, err := release.SignSequenceMigration(migration, now, root)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(signedMigration)
	migrationSHA, _ := trust.Fingerprint(signedMigration)
	allocations := serviceAllocationStore(t, migration.Namespace, migration.Bucket)
	evidence := []byte("test-only qualified registry worker runtime evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	readEvidence := func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}
	target := release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: FunctionWorkerRole, Architecture: runtime.GOARCH}
	_, workerDelegation := delegate(release.ContainerScope(target))
	bundle := func(sequence uint64) release.ContainerBundle {
		t.Helper()
		digest := strings.Repeat("a", 64)
		candidate := release.ProductionExpectation{SourceRevision: strings.Repeat(string(rune('c'+sequence-101)), 40), ArtifactSHA256: digest, QualificationSHA256: digest, Cell: "GRU", Environment: intent.Environment, Runtime: release.ProductionRuntime, Architecture: runtime.GOARCH, Role: FunctionWorkerRole}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		signed, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), root)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(signed)
		workerClaim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: "registry.example/function-worker@sha256:" + digest, SourceRepository: "https://example.invalid/function-worker", SourceRevision: candidate.SourceRevision, SourceTreeSHA256: strings.Repeat("d", 64), Cell: "GRU", Environment: intent.Environment, Role: FunctionWorkerRole, Architecture: runtime.GOARCH, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: digest, Production: release.ProductionProof{Qualification: proofWire}}
		sequenceWire := serviceSequenceEvidence(t, ctx, allocations, signedMigration, workerClaim, roots, signer)
		payload, _ = trust.EncodePayload(workerClaim)
		signed, err = trust.Sign(payload, release.ContainerScope(target), now, now.Add(time.Hour), signer)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		return release.ContainerBundle{Claim: wire, Migration: migrationWire, Delegation: workerDelegation, Sequence: sequenceWire}
	}
	service, err := ApplyFunctionService(ctx, client, intent, current, bundle(101), roots, legacy, readEvidence, func(context.Context, *api.Task) error { return nil }, allocations)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	worker, err := release.VerifyContainerCurrent(ctx, bundle(101), roots, target, now, deadline, readEvidence, allocations)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
	if err != nil || len(tasks.Tasks) != 1 {
		t.Fatalf("assigned function registry task: %+v %v", tasks, err)
	}
	task := tasks.Tasks[0]
	retained, err := intent.WorkerBundleForTask(ctx, client, task)
	if err != nil {
		t.Fatal(err)
	}
	retainedWorker, err := release.VerifyContainerCurrent(ctx, retained, roots, target, now, deadline, readEvidence, allocations)
	if err != nil || retainedWorker.BundleSHA256() != worker.BundleSHA256() {
		t.Fatalf("task did not retain its exact independently qualified bundle: %v", err)
	}
	// Renewing only delegation keeps the signed claim but creates a distinct proof.
	renewed := retained
	workerScope := release.ContainerScope(target)
	renewedGrant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: signerID, SubjectPublicKey: encodedPublic, Capabilities: []trust.Capability{{Domain: workerScope.Domain, DeploymentID: workerScope.DeploymentID, Cell: workerScope.Cell, Environment: workerScope.Environment, Role: workerScope.Role, Slots: []string{workerScope.Slot}, Actions: []string{"sign"}}}}, now.Add(-30*time.Second), now.Add(time.Hour), root)
	if err != nil {
		t.Fatal(err)
	}
	renewed.Delegation, _ = trust.EncodeEnvelope(renewedGrant)
	renewedWorker, err := release.VerifyContainerCurrent(ctx, renewed, roots, target, now, deadline, readEvidence, allocations)
	if err != nil {
		t.Fatal(err)
	}
	if renewedWorker.Fingerprint() != worker.Fingerprint() || renewedWorker.BundleSHA256() == worker.BundleSHA256() {
		t.Fatal("whole-bundle identity did not distinguish renewed delegation under the same claim")
	}
	if err := intent.retainWorkerBundle(ctx, client, renewed, renewedWorker); err != nil {
		t.Fatal(err)
	}
	renewedSpec, err := intent.serviceSpec(current.proof, renewedWorker)
	if err != nil || renewedSpec.Task.ForceUpdate == service.Spec.Task.ForceUpdate {
		t.Fatalf("renewed worker proof did not change the task recipe: %v", err)
	}
	if err := intent.VerifyTask(task, service, current.proof, renewedWorker); err == nil {
		t.Fatal("an old task accepted independently renewed worker proof bytes")
	}
	retainedAgain, err := intent.WorkerBundleForTask(ctx, client, task)
	if err != nil || !bytes.Equal(retainedAgain.Delegation, retained.Delegation) {
		t.Fatalf("renewed delegation overwrote the original task bundle: %v", err)
	}
	missing := task.Copy()
	missing.ServiceAnnotations.Labels[LabelFunctionWorkerBundle] = strings.Repeat("0", 64)
	if _, err := intent.WorkerBundleForTask(ctx, client, missing); err == nil {
		t.Fatal("missing task-pinned proof selected a different worker bundle")
	}
	if err := VerifyFunctionRegistryTask(ctx, client, task, intent, current, worker); err != nil {
		t.Fatal(err)
	}
	admission, err := AdmitFunctionRegistryTask(ctx, client, task, intent, current, worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyCurrent(ctx); err != nil {
		t.Fatal("unchanged actual manager state rejected a fresh registry receipt: ", err)
	}
	actualService, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		t.Fatal(err)
	}
	changed := actualService.Service.Spec.Copy()
	changed.Update.Delay += time.Second
	updated, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &actualService.Service.Meta.Version, Spec: changed})
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.VerifyCurrent(ctx); err == nil {
		t.Fatal("registry receipt survived an actual manager service change after its authority reads")
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &updated.Service.Meta.Version, Spec: service.Spec.Copy()}); err != nil {
		t.Fatal(err)
	}
	forged := task.Copy()
	forged.NodeID = platform.ID()
	if err := VerifyFunctionRegistryTask(ctx, client, forged, intent, current, worker); err == nil {
		t.Fatal("another host was authorized for the function worker pull")
	}
	current.revoked = true
	if err := VerifyFunctionRegistryTask(ctx, client, task, intent, current, worker); err == nil {
		t.Fatal("revoked function intent authorized a worker pull")
	}
	current.revoked = false
	newBundle := bundle(102)
	newWorker, err := release.VerifyContainerCurrent(ctx, newBundle, roots, target, now, deadline, readEvidence, allocations)
	if err != nil {
		t.Fatal(err)
	}
	if err := intent.retainWorkerBundle(ctx, client, newBundle, newWorker); err != nil {
		t.Fatal(err)
	}
	workerIntent := ServiceIntent{ID: entityid.Derive("function-worker-release", intent.Environment, intent.Region), Role: FunctionWorkerRole, Region: intent.Region, Environment: intent.Environment, Architecture: intent.Architecture}
	if _, err := reserveReleaseFloor(ctx, client, workerIntent, newWorker, roots, legacy, 0); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFunctionRegistryTask(ctx, client, task, intent, current, worker); err == nil {
		t.Fatal("superseded current worker authorized outside a previous service recipe")
	}
	latest, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		t.Fatal(err)
	}
	next := latest.Service.Spec.Copy()
	// Change only update policy so the actual assigned task retains PreviousSpec.
	next.Update.Delay += time.Second
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &latest.Service.Meta.Version, Spec: next}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFunctionRegistryTask(ctx, client, task, intent, current, worker); err != nil {
		t.Fatal("current function's qualified previous worker pull was denied: ", err)
	}
	previousBundle, err := intent.WorkerBundleForTask(ctx, client, task)
	if err != nil {
		t.Fatal(err)
	}
	previousWorker, err := release.VerifyContainerCurrent(ctx, previousBundle, roots, target, now, deadline, readEvidence, allocations)
	if err != nil || previousWorker.BundleSHA256() != worker.BundleSHA256() {
		t.Fatalf("previous task did not select its own qualified retained bundle: %v", err)
	}
	if err := VerifyFunctionRegistryTask(ctx, client, task, intent, current, previousWorker); err != nil {
		t.Fatal("retained previous worker was not authorized through actual manager state: ", err)
	}
	if err := intent.VerifyWorkerFloor(ctx, client, worker); err == nil {
		t.Fatal("previous worker pull authorization also authorized stale function material")
	}
	// Restore the fixed recipe before the genuine updater rolls back a rejected worker.
	latest, err = client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &latest.Service.Meta.Version, Spec: service.Spec.Copy()})
	if err != nil {
		t.Fatal(err)
	}
	nextWorkerSpec, err := intent.serviceSpec(current.proof, newWorker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: service.ID, ServiceVersion: &canonical.Service.Meta.Version, Spec: nextWorkerSpec}); err != nil {
		t.Fatal(err)
	}
	var rollbackTask *api.Task
	serviceEventually(t, ctx, func() bool {
		actual, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: service.ID})
		if err != nil || actual.Service == nil || actual.Service.UpdateStatus == nil || !proto.Equal(&actual.Service.Spec, &service.Spec) {
			return false
		}
		switch actual.Service.UpdateStatus.State {
		case api.UpdateStatus_ROLLBACK_STARTED, api.UpdateStatus_ROLLBACK_COMPLETED, api.UpdateStatus_ROLLBACK_PAUSED:
		default:
			return false
		}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		if err != nil {
			return false
		}
		for _, candidate := range tasks.Tasks {
			if candidate.ID != task.ID && candidate.Status.State == api.TaskStateRunning && intent.VerifyTask(candidate, actual.Service, current.proof, worker) == nil {
				rollbackTask = candidate
				return true
			}
		}
		return false
	})
	rollbackBundle, err := intent.WorkerBundleForTask(ctx, client, rollbackTask)
	if err != nil {
		t.Fatal(err)
	}
	rollbackWorker, err := release.VerifyContainerCurrent(ctx, rollbackBundle, roots, target, time.Now().UTC(), deadline, readEvidence, allocations)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFunctionRegistryTask(ctx, client, rollbackTask, intent, current, rollbackWorker); err != nil {
		t.Fatal("actual current rollback task could not pull its qualified retained worker: ", err)
	}
	if err := VerifyFunctionRegistryTask(ctx, client, rollbackTask, intent, current, newWorker); err == nil {
		t.Fatal("rollback status authorized a different worker bundle")
	}
	if err := intent.VerifyWorkerFloor(ctx, client, rollbackWorker); err == nil {
		t.Fatal("rollback image pull also authorized superseded worker material")
	}
	current.proof = functionProof(2)
	if err := VerifyFunctionRegistryTask(ctx, client, rollbackTask, intent, current, rollbackWorker); err == nil {
		t.Fatal("rollback status authorized a superseded function proof")
	}
}
