package drainwire

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func poolReceiptFixture() PoolReceipt {
	now := time.Now().UTC()
	digest := strings.Repeat("a", 64)
	specWire, rootWire := []byte("signed spec"), []byte("signed root chain")
	child := PoolChild{Cell: "GRU", BirthOperationID: entityid.New(), RemovalOperationID: entityid.New(),
		InstanceID: "ocid1.instance.original", PoolID: "ocid1.instancepool.original", ConfigurationID: "ocid1.instanceconfiguration.original",
		RecipeSHA256: digest, GrantSHA256: digest, Generation: 1}
	host := HostSession{Cell: "gru", HostNode: "worker-a", RegistrationID: entityid.New(), InstanceID: child.InstanceID,
		HostSessionID: entityid.New(), RegistrationGeneration: 1, HostEpoch: 41, ExpiresAt: now.Add(time.Minute)}
	hold := ExecutionHold{HostSession: host, OriginalEpoch: 2, NodeID: "worker", TaskID: "task", ServiceID: "service",
		TaskSHA256: digest, ExecutionSHA256: digest, ExecutionSessionID: entityid.New(), IssuedAt: now.Add(-time.Second)}
	return PoolReceipt{Child: child, CellSpecWire: specWire, RootChainWire: rootWire,
		Source: PoolSource{ControllerConfigSHA256: digest, CellSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(specWire)), CellSpecGeneration: 1,
			RootSHA256: fmt.Sprintf("%x", sha256.Sum256(rootWire)), ManagerInstanceID: "ocid1.instance.manager", ManagerNodeID: "manager", DeploymentID: entityid.New(),
			CandidateID: entityid.New(), OwnerID: entityid.New(), Epoch: 3, LeaseRevision: 1, ExpiresAt: host.ExpiresAt},
		Host: host, NodeID: "worker", ClusterID: "cluster", ClusterCAPEM: []byte("ca"), ManagerCertificates: [][]byte{[]byte("manager")},
		WorkerCertificate: []byte("worker"), CapturedAt: now, ExpiresAt: host.ExpiresAt, Phase: PoolCaptured,
		Tasks: []PoolTask{{TaskID: hold.TaskID, ServiceID: hold.ServiceID, TaskSHA256: digest, ExecutionSHA256: digest}},
		Holds: []SignedHold{{Hold: hold}}, Challenges: []DrainStopChallenge{{Cell: host.Cell, HostNode: host.HostNode,
			RemovalOperationID: child.RemovalOperationID, BirthOperationID: child.BirthOperationID, InstanceID: child.InstanceID,
			NodeID: hold.NodeID, RegistrationID: host.RegistrationID, HostSessionID: host.HostSessionID,
			RegistrationGeneration: host.RegistrationGeneration, Epoch: 3, HostEpoch: host.HostEpoch, OriginalEpoch: 2,
			ExecutionSessionID: hold.ExecutionSessionID, TaskID: hold.TaskID, ServiceID: hold.ServiceID, TaskSHA256: digest,
			ExecutionSHA256: digest, Nonce: digest, IssuedAt: now, Deadline: host.ExpiresAt}}}
}

func TestPoolReceiptRetainsOriginalCapture(t *testing.T) {
	original := poolReceiptFixture()
	if err := original.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*PoolReceipt){
		"new host session":  func(r *PoolReceipt) { r.Host.HostSessionID = entityid.New() },
		"extended deadline": func(r *PoolReceipt) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
		"lost task":         func(r *PoolReceipt) { r.Tasks = nil },
		"lost hold":         func(r *PoolReceipt) { r.Holds = nil },
		"rewritten source":  func(r *PoolReceipt) { r.Source.OwnerID = entityid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			if err := changed.Retains(original); err == nil {
				t.Fatal("original capture could be replaced")
			}
		})
	}
	if err := VerifyPoolReceiptStops(original, original.CapturedAt); err == nil {
		t.Fatal("capture without an actual stop authorized stopped evidence")
	}
}
