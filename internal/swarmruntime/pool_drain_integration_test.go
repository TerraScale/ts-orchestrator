//go:build linux

package swarmruntime

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/moby/swarmkit/v2/api"
)

// This proves the actual manager/R3 append ordering only. Protected source/CAS,
// provider fences and kernel process-stop observations require their own fixture.
func TestPoolDrainPauseBarrierOrdersInflightAcquire(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	js, _ := effectSessionR3(t)
	config := authority.Config{Scope: "gru", DeploymentID: entityid.New(), CandidateID: entityid.New(), Replicas: 3,
		LeaseDuration: 3 * time.Minute, RenewInterval: time.Minute}
	journal, err := authority.Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	leases, err := authority.OpenReader(ctx, js, config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	founderConfig := serviceConfig(t, "ts-gru-1", "manager")
	founder := serviceStart(t, ctx, founderConfig)
	control, err := founder.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clusters, err := control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || clusters == nil || len(clusters.Clusters) != 1 {
		t.Fatal("actual manager cluster unavailable", err)
	}
	workerConfig := serviceConfig(t, entityid.Derive("host", "gru", "drain-worker"), "container")
	workerConfig.Admission.ManagerAddress, err = founder.RemoteAddress()
	if err != nil {
		t.Fatal(err)
	}
	workerConfig.Admission.JoinToken = clusters.Clusters[0].RootCA.JoinTokens.Worker
	worker := serviceStart(t, ctx, workerConfig)
	if _, err := AdmitNode(ctx, control, worker.ID(), workerConfig.Admission); err != nil {
		t.Fatal(err)
	}
	intent := serviceIntent()
	intent.ID, intent.OperationID, intent.Replicas = entityid.New(), entityid.New(), 2
	service, err := applyService(ctx, control, intent)
	if err != nil {
		t.Fatal(err)
	}
	var task, laterTask *api.Task
	serviceEventually(t, ctx, func() bool {
		listed, err := control.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}}})
		if err != nil || listed == nil || len(listed.Tasks) != 2 {
			return false
		}
		for _, actual := range listed.Tasks {
			if actual.NodeID != worker.ID() || actual.Status.State != api.TaskStateRunning {
				return false
			}
		}
		task, laterTask = listed.Tasks[0].Copy(), listed.Tasks[1].Copy()
		return true
	})
	original, err := leases.CurrentLease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	taskHash, err := executionwire.TaskSHA256(task)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := ContainerTaskFingerprint(task)
	if err != nil {
		t.Fatal(err)
	}
	hold := drainwire.ExecutionHold{HostSession: drainwire.HostSession{Cell: config.Scope, HostNode: "drain-worker", RegistrationID: workerConfig.Admission.HostID,
		InstanceID: workerConfig.Admission.InstanceID, HostSessionID: entityid.New(), RegistrationGeneration: 1, HostEpoch: 41, ExpiresAt: original.ExpiresAt},
		OriginalEpoch: original.Epoch, NodeID: worker.ID(), TaskID: task.ID, ServiceID: service.ID, TaskSHA256: taskHash,
		ExecutionSHA256: fingerprint, ExecutionSessionID: entityid.New(), IssuedAt: time.Now().UTC()}
	key, chain, err := founder.nodeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	signing, err := drainwire.HoldSigningBytes(hold)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signing)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signed := drainwire.SignedHold{Hold: hold, CertificateChain: chain, Signature: signature}
	managerRecord, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: founder.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := drainwire.VerifySignedHold(signed, managerRecord.Node.Certificate.Certificate, clusters.Clusters[0].RootCA.CACert, clusters.Clusters[0].ID, time.Now().UTC()); err != nil {
		t.Fatal("actual manager key did not authenticate retained hold", err)
	}
	checkActive := func(check context.Context) error {
		actual, err := control.GetNode(check, &api.GetNodeRequest{NodeID: worker.ID()})
		if err != nil || actual == nil || actual.Node == nil {
			return errors.Join(ErrPoolDrainPending, err)
		}
		if actual.Node.Spec.Availability != api.NodeAvailabilityActive {
			return ErrPoolDrainPending
		}
		return nil
	}
	verified, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	acquireDone := make(chan error, 1)
	go func() {
		acquireDone <- journal.BeginGenericExecution(ctx, original.Epoch, signed, func(check context.Context) error {
			if err := checkActive(check); err != nil {
				return err
			}
			close(verified)
			select {
			case <-release:
				return nil
			case <-check.Done():
				return check.Err()
			}
		})
	}()
	select {
	case <-verified:
	case err := <-acquireDone:
		t.Fatal("acquisition failed before final actual ACTIVE check", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	node, err := control.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil {
		t.Fatal(err)
	}
	spec := node.Node.Spec.Copy()
	spec.Availability = api.NodeAvailabilityPause
	if _, err := control.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: worker.ID(), NodeVersion: &node.Node.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	barrierDone := make(chan struct {
		revision uint64
		err      error
	}, 1)
	go func() {
		revision, err := poolDrainPauseBarrier(ctx, leases, original)
		barrierDone <- struct {
			revision uint64
			err      error
		}{revision, err}
	}()
	renewCtx, stopRenew := context.WithCancel(ctx)
	defer stopRenew()
	renewDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			if err := journal.Guard(renewCtx, original.Epoch); err != nil {
				renewDone <- err
				return
			}
			select {
			case <-renewCtx.Done():
				renewDone <- renewCtx.Err()
				return
			case <-ticker.C:
			}
		}
	}()
	shortCtx, stopShort := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stopShort()
	pinned, err := leases.AdmitCurrentLease(shortCtx, original.DeploymentID, original.CandidateID, original.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	deadline := pinned.Deadline()
	if _, err := poolDrainPauseBarrier(shortCtx, leases, pinned.Original()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending barrier ignored its original authority deadline", err)
	}
	select {
	case result := <-barrierDone:
		t.Fatalf("renewal crossed the blocked original acquire: %+v", result)
	case err := <-renewDone:
		t.Fatal("renewal escaped the original acquisition mutex", err)
	case <-time.After(150 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	unblock()
	select {
	case err := <-acquireDone:
		if err != nil {
			t.Fatal("original in-flight acquire did not commit before renewal", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case result := <-barrierDone:
		if result.err != nil || result.revision <= original.Revision {
			t.Fatal("post-PAUSE same-owner barrier unavailable", result)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stopRenew()
	select {
	case <-renewDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	history, err := leases.ListGenericExecutions(ctx)
	if err != nil || len(history) != 1 || !sameGenericHold(history[0], signed) {
		t.Fatal("post-barrier capture lost original in-flight execution", err)
	}
	if err := pinned.Guard(ctx); !errors.Is(err, authority.ErrFenced) || !pinned.Deadline().Equal(deadline) {
		t.Fatal("later same-owner renewal extended expired original authority", err)
	}
	later := hold
	later.TaskID, later.ServiceID, later.ExecutionSessionID = laterTask.ID, laterTask.ServiceID, entityid.New()
	later.TaskSHA256, err = executionwire.TaskSHA256(laterTask)
	if err != nil {
		t.Fatal(err)
	}
	later.ExecutionSHA256, err = ContainerTaskFingerprint(laterTask)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := drainwire.HoldSigningBytes(later)
	if err != nil {
		t.Fatal(err)
	}
	laterDigest := sha256.Sum256(wire)
	laterSignature, err := key.Sign(rand.Reader, laterDigest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.BeginGenericExecution(ctx, original.Epoch, drainwire.SignedHold{Hold: later, CertificateChain: chain, Signature: laterSignature}, checkActive); !errors.Is(err, ErrPoolDrainPending) {
		t.Fatal("actual PAUSE allowed a subsequent acquisition append", err)
	}
	history, err = leases.ListGenericExecutions(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("denied later acquisition changed immutable execution history", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	config.CandidateID = entityid.New()
	successor, err := authority.Start(ctx, js, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = successor.Close() })
	if _, err := poolDrainPauseBarrier(ctx, leases, original); !errors.Is(err, authority.ErrFenced) {
		t.Fatal("original capture followed a successor owner", err)
	}
}
