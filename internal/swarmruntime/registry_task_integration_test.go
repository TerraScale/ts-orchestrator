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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
)

// The new revision remains in Prepare while the real upstream manager retains
// its old assignment during the start-first update.
type registryAssignmentExecutor struct {
	serviceExecutor
	shutdown <-chan struct{}
}

func (e registryAssignmentExecutor) Controller(task *api.Task) (exec.Controller, error) {
	spec, err := DecodeContainer(task)
	if err != nil {
		return nil, err
	}
	if len(spec.Args) > 0 && spec.Args[0] == "pending" {
		return &registryPendingController{serviceController: serviceController{done: make(chan struct{})}}, nil
	}
	controller, err := e.serviceExecutor.Controller(task)
	if err != nil || e.shutdown == nil {
		return controller, err
	}
	return &registryStoppingController{serviceController: controller.(*serviceController), shutdown: e.shutdown}, nil
}

type registryStoppingController struct {
	*serviceController
	shutdown <-chan struct{}
}

func (c *registryStoppingController) Shutdown(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.shutdown:
		return c.serviceController.Shutdown(ctx)
	}
}

func (c *registryStoppingController) Terminate(ctx context.Context) error { return c.Shutdown(ctx) }

type registryPendingController struct{ serviceController }

func (*registryPendingController) Prepare(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func TestRegistryTaskAssignmentIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	shutdown := make(chan struct{})
	node, err := StartNode(ctx, cfg, registryAssignmentExecutor{shutdown: shutdown})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := node.Stop(stopCtx); err != nil {
			t.Error(err)
		}
	})
	var releaseShutdown sync.Once
	release := func() { releaseShutdown.Do(func() { close(shutdown) }) }
	t.Cleanup(release)
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitNode(ctx, client, node.ID(), cfg.Admission); err != nil {
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
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "test", Bucket: "gru-1-head", Region: "GRU", SignerKeyID: keyID, SignerPublicKey: base64.RawURLEncoding.EncodeToString(public), Role: "api", Environment: "production", SequenceFloor: 100}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)})
	}
	migrationEnvelope, err := release.SignSequenceMigration(migration, now, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	migrationWire, _ := trust.EncodeEnvelope(migrationEnvelope)
	migrationSHA, _ := trust.Fingerprint(migrationEnvelope)
	allocations := serviceAllocationStore(t, migration.Namespace, migration.Bucket)
	reservations := map[uint64][]byte{}
	intent := serviceIntent()
	intent.Generation = 1
	intent.OperationID = entityid.Derive("registry-operation", "first")
	evidence := []byte("retained exact candidate integration evidence")
	evidenceSHA := fmt.Sprintf("%x", sha256.Sum256(evidence))
	readEvidence := func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(evidence)), nil
	}
	bundle := func(sequence uint64, source string) release.ContainerBundle {
		t.Helper()
		candidate := release.ProductionExpectation{SourceRevision: source, ArtifactSHA256: strings.Repeat("a", 64), QualificationSHA256: strings.Repeat("a", 64), Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: intent.Architecture, Role: intent.Role}
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema, Candidate: candidate, Evidence: []release.ProductionGateEvidence{{Gate: "runtime-ha", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}, {Gate: "workload-safety", SHA256: evidenceSHA, Bytes: int64(len(evidence)), CompletedAt: now}}}
		payload, _ := trust.EncodePayload(qualification)
		proof, err := trust.Sign(payload, release.ProductionQualificationScope(candidate), now, now.Add(time.Hour), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		proofWire, _ := trust.EncodeEnvelope(proof)
		claim := release.ContainerClaim{Schema: release.ContainerClaimSchema, Image: intent.Container.Image, SourceRepository: "https://github.com/TerraScale/ts-auth", SourceRevision: source, SourceTreeSHA256: strings.Repeat("e", 64), Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture, ReleaseSequence: sequence, SequenceMigrationSHA256: migrationSHA, QualificationSHA256: candidate.QualificationSHA256, Production: release.ProductionProof{Qualification: proofWire}}
		if reservations[sequence] == nil {
			reservations[sequence] = serviceSequenceEvidence(t, ctx, allocations, migrationEnvelope, claim, roots, key)
		}
		payload, _ = trust.EncodePayload(claim)
		signed, err := trust.Sign(payload, release.ContainerScope(release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}), now, now.Add(time.Hour), key)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := trust.EncodeEnvelope(signed)
		target := release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}
		grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID, SubjectPublicKey: base64.RawURLEncoding.EncodeToString(public),
			Capabilities: []trust.Capability{{Domain: release.ContainerClaimDomain, DeploymentID: release.ContainerScope(target).DeploymentID,
				Cell: target.Cell, Environment: target.Environment, Role: target.Role, Slots: []string{"linux-" + target.Architecture}, Actions: []string{"sign"}}}}, now, now.Add(time.Hour), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		delegationWire, _ := trust.EncodeEnvelope(grant)
		return release.ContainerBundle{Claim: wire, Migration: migrationWire, Delegation: delegationWire, Sequence: reservations[sequence]}
	}

	target := release.ContainerTarget{Cell: "GRU", Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}
	verify := func(b release.ContainerBundle) release.VerifiedContainer {
		t.Helper()
		proof, err := release.VerifyContainerCurrent(ctx, b, roots, target, time.Now().UTC(), time.Now().UTC().Add(45*time.Second), readEvidence, allocations)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	first := bundle(101, strings.Repeat("c", 40))
	proof := verify(first)
	legacy := release.SequenceFloor{Cell: "GRU", RunNumber: 100, EvidenceSHA256: strings.Repeat("1", 64)}
	created, err := applySignedService(ctx, client, intent, first, roots, legacy, readEvidence, allocations)
	if err != nil {
		t.Fatal(err)
	}
	var task *api.Task
	serviceEventually(t, ctx, func() bool {
		response, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.ID}}})
		if err != nil {
			return false
		}
		for _, candidate := range response.Tasks {
			if candidate.Status.State == api.TaskStateRunning {
				task = candidate
				return true
			}
		}
		return false
	})
	if err := VerifyRegistryTask(ctx, client, task, intent, proof, roots); err != nil {
		t.Fatal("current authenticated assignment: ", err)
	}
	forged := task.Copy()
	forged.Spec.GetGeneric().Payload.Value = append(forged.Spec.GetGeneric().Payload.Value, ' ')
	if err := VerifyRegistryTask(ctx, client, forged, intent, proof, roots); err == nil {
		t.Fatal("forged executor task accepted")
	}
	forged = task.Copy()
	forged.ID = "missing-task"
	if err := VerifyRegistryTask(ctx, client, forged, intent, proof, roots); err == nil {
		t.Fatal("unassigned task accepted")
	}
	wrong := intent
	wrong.OperationID = entityid.Derive("registry-operation", "other")
	if err := VerifyRegistryTask(ctx, client, task, wrong, proof, roots); err == nil {
		t.Fatal("unrelated durable operation accepted")
	}
	// Renewing qualification changes the full proof but keeps the release identity.
	now = now.Add(-time.Second)
	renewed := verify(bundle(101, strings.Repeat("c", 40)))
	if err := VerifyRegistryTask(ctx, client, task, intent, renewed, roots); err != nil {
		t.Fatal("renewed qualification: ", err)
	}
	next := bundle(102, strings.Repeat("d", 40))
	nextProof := verify(next)
	changed := intent
	changed.Generation++
	changed.Container = intent.Container.Copy()
	changed.Container.Args = []string{"pending"}
	changed.OperationID = entityid.Derive("registry-operation", "next")
	prepared, err := changed.withVerifiedRelease(nextProof)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := reserveReleaseFloor(ctx, client, prepared, nextProof, roots, legacy, created.Meta.Version.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegistryTask(ctx, client, task, intent, proof, roots); err != nil {
		t.Fatal("highwater revoked current task: ", err)
	}
	if _, err := applySignedService(ctx, client, changed, next, roots, legacy, readEvidence, allocations); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegistryTask(ctx, client, task, intent, proof, roots); err != nil {
		t.Fatal("authorized previous assignment: ", err)
	}
	floorSpec := floor.Spec.Copy()
	floorSpec.Annotations.Labels[LabelIntentID] = entityid.Derive("foreign-service")
	foreignFloor, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: floor.ID, ConfigVersion: &floor.Meta.Version, Spec: floorSpec})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRegistryTask(ctx, client, task, intent, proof, roots); err == nil {
		t.Fatal("foreign release floor accepted")
	}
	if err := VerifyTaskAllocation(ctx, client, task, intent, proof, roots); err == nil {
		t.Fatal("allocation accepted foreign release floor")
	}
	if _, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: floor.ID, ConfigVersion: &foreignFloor.Config.Meta.Version, Spec: &floor.Spec}); err != nil {
		t.Fatal(err)
	}
	assignedNode, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	drained := assignedNode.Node.Spec.Copy()
	drained.Availability = api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: task.NodeID, NodeVersion: &assignedNode.Node.Meta.Version, Spec: drained}); err != nil {
		t.Fatal(err)
	}
	serviceEventually(t, ctx, func() bool {
		current, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
		if err != nil || current == nil || current.Task == nil || current.Task.DesiredState <= api.TaskStateRunning || current.Task.Status.State >= api.TaskStateCompleted {
			return false
		}
		task = current.Task
		return true
	})
	if err := VerifyTaskAllocation(ctx, client, task, intent, proof, roots); err != nil {
		t.Fatal("blocked shutdown lost signed previous reservation: ", err)
	}
	if err := VerifyRegistryTask(ctx, client, task, intent, proof, roots); err == nil {
		t.Fatal("read-only reservation widened registry authority")
	}
	changedTask := task.Copy()
	changedTask.Spec.Resources.Reservations.MemoryBytes++
	if err := VerifyTaskAllocation(ctx, client, changedTask, intent, proof, roots); err == nil {
		t.Fatal("forged allocation resources accepted")
	}
	release()
	serviceEventually(t, ctx, func() bool {
		current, err := client.GetTask(ctx, &api.GetTaskRequest{TaskID: task.ID})
		if err != nil || current == nil || current.Task == nil || current.Task.Status.State < api.TaskStateCompleted {
			return false
		}
		task = current.Task
		return true
	})
	if err := VerifyTaskAllocation(ctx, client, task, intent, proof, roots); err == nil {
		t.Fatal("terminal task retained a live allocation")
	}
}
