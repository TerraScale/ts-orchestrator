package nodescale

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"github.com/moby/swarmkit/v2/manager/state/raft"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// swarmHosts drives admitted node/task observations through the real upstream control API.
type swarmHosts struct {
	instanceIDs         map[string]string
	live                map[string]bool
	desired             []desiredTask
	cordoned, unretired []string
	store               *store.MemoryStore
	control             api.ControlClient
}

type desiredTask struct {
	Cell, Node, Role string
	Withdrawn        bool
}

// scalerKeys supplies disposable encryption material to the real single-member Raft log.
type scalerKeys struct{ key []byte }

func makeKey() []byte                              { key := make([]byte, 32); _, _ = rand.Read(key); return key }
func (k *scalerKeys) GetKeys() raft.EncryptionKeys { return raft.EncryptionKeys{CurrentDEK: k.key} }
func (*scalerKeys) NeedsRotation() bool            { return false }
func (k *scalerKeys) UpdateKeys(keys raft.EncryptionKeys) error {
	if keys.CurrentDEK != nil {
		k.key = keys.CurrentDEK
	}
	return nil
}
func (*scalerKeys) RotationNotify() chan struct{} { return nil }

func newSwarmHosts(t *testing.T) *swarmHosts {
	t.Helper()
	raftNode := raft.NewNode(raft.NodeOptions{ID: "scaler-manager", Addr: "127.0.0.1:1", StateDir: t.TempDir(),
		TickInterval: 10 * time.Millisecond, TLSCredentials: insecure.NewCredentials(), KeyRotator: &scalerKeys{key: makeKey()}})
	if err := raftNode.JoinAndStart(t.Context()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- raftNode.Run(t.Context()) }()
	t.Cleanup(func() { raftNode.Cancel(); <-done })
	deadline := time.Now().Add(10 * time.Second)
	for !raftNode.ReadyForProposals() {
		if time.Now().After(deadline) {
			t.Fatal("embedded manager did not elect a leader")
		}
		time.Sleep(10 * time.Millisecond)
	}
	memory := raftNode.MemoryStore()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterControlServer(server, controlapi.NewServer(memory, raftNode, nil, nil, nil))
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); server.Stop() })
	return &swarmHosts{live: map[string]bool{}, instanceIDs: map[string]string{}, store: memory, control: api.NewControlClient(conn)}
}

func (h *swarmHosts) sync(t *testing.T) {
	t.Helper()
	if err := h.store.Update(func(tx store.Tx) error {
		for name, live := range h.live {
			node := store.GetNode(tx, name)
			create := node == nil
			if create {
				node = &api.Node{ID: name, Role: api.NodeRoleWorker, Spec: api.NodeSpec{DesiredRole: api.NodeRoleWorker, Membership: api.NodeMembershipAccepted,
					Annotations: api.Annotations{Name: name, Labels: map[string]string{"terrascale.instance-id": "ocid-" + name, "terrascale.region": "sa-saopaulo-1"}}}}
				if nodeNumber(name) < FirstPoolNode {
					node.Role = api.NodeRoleManager
					node.Certificate.Role = api.NodeRoleManager
					node.Spec.DesiredRole = api.NodeRoleManager
				}
			}
			if id := h.instanceIDs[name]; id != "" {
				node.Spec.Annotations.Labels["terrascale.instance-id"] = id
			}
			node.Status.State = api.NodeStatus_DOWN
			if live {
				node.Status.State = api.NodeStatus_READY
			}
			if create {
				if err := store.CreateNode(tx, node); err != nil {
					return err
				}
			} else if err := store.UpdateNode(tx, node); err != nil {
				return err
			}
		}
		for i, desired := range h.desired {
			id := fmt.Sprintf("task-%d", i)
			serviceID := "service-" + desired.Role
			if store.GetService(tx, serviceID) == nil {
				if err := store.CreateService(tx, &api.Service{ID: serviceID, Spec: api.ServiceSpec{Annotations: api.Annotations{Name: serviceID, Labels: map[string]string{"terrascale.role": desired.Role}}}}); err != nil {
					return err
				}
			}
			task := store.GetTask(tx, id)
			create := task == nil
			if create {
				task = &api.Task{ID: id, NodeID: desired.Node, ServiceID: serviceID, DesiredState: api.TaskStateRunning, Status: api.TaskStatus{State: api.TaskStateRunning}}
			}
			if desired.Withdrawn {
				task.DesiredState = api.TaskStateShutdown
				task.Status.State = api.TaskStateShutdown
			}
			if create {
				if err := store.CreateTask(tx, task); err != nil {
					return err
				}
			} else if err := store.UpdateTask(tx, task); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (h *swarmHosts) observe(t *testing.T) {
	t.Helper()
	nodes, err := h.control.ListNodes(t.Context(), &api.ListNodesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes.Nodes {
		name := node.Spec.Annotations.Name
		if node.Spec.Availability == api.NodeAvailabilityDrain && !slices.Contains(h.cordoned, name) {
			h.cordoned = append(h.cordoned, name)
		}
		if node.Spec.Availability == api.NodeAvailabilityActive && slices.Contains(h.cordoned, name) && !slices.Contains(h.unretired, name) {
			h.unretired = append(h.unretired, name)
		}
	}
}

type swarmLeader struct {
	snapshot authority.Snapshot
	guardErr error
}

func (f *swarmLeader) Current() authority.Snapshot         { return f.snapshot }
func (f *swarmLeader) Guard(context.Context, uint64) error { return f.guardErr }

func swarmScaler(t *testing.T) (*Scaler, *swarmHosts, *tick) {
	t.Helper()
	hosts := newSwarmHosts(t)
	hosts.live["ts-gru-4"] = true
	hosts.sync(t)
	now := time.Now()
	scaler := &Scaler{Cell: "gru", Control: hosts.control, CanRetire: func(context.Context, string, string) error { return nil },
		Leader:   &swarmLeader{snapshot: authority.Snapshot{DeploymentID: entityid.New(), Ready: true, Leader: true, Epoch: 7, Revision: 3, ExpiresAt: now.Add(time.Hour)}},
		Backends: func(context.Context, string, string) (int, error) { return 0, nil }}
	observation := scaler.observe(PoolState{Instances: []PoolInstance{{ID: "ocid-ts-gru-4", Name: "ts-gru-4", State: "RUNNING"}}}, []*api.Node{})
	observation.counted["ts-gru-4"] = true
	pass := &tick{epoch: 7, now: now, pool: PoolState{Instances: []PoolInstance{{ID: "ocid-ts-gru-4", Name: "ts-gru-4", State: "RUNNING"}}}, obs: observation,
		loads: []NodeLoad{{Node: "ts-gru-4", CPU: .1}}, record: Record{Action: &InFlight{ID: entityid.New(), Kind: Down, Step: stepCordon, Node: "ts-gru-4", InstanceID: "ocid-ts-gru-4", Started: now}}}
	return scaler, hosts, pass
}

func TestSwarmDrainWaitsForObservedStopAndBackends(t *testing.T) {
	scaler, hosts, pass := swarmScaler(t)
	hosts.desired = []desiredTask{{Node: "ts-gru-4", Role: "app"}}
	hosts.sync(t)
	if err := scaler.cordon(t.Context(), pass); err != nil {
		t.Fatal(err)
	}
	if pass.record.Action.Step != stepDrain {
		t.Fatal("did not ask SwarmKit to drain worker")
	}
	if err := hosts.store.Update(func(tx store.Tx) error {
		task := store.GetTask(tx, "task-0")
		task.DesiredState = api.TaskStateShutdown
		return store.UpdateTask(tx, task)
	}); err != nil {
		t.Fatal(err)
	}
	if drained, err := scaler.drained(t.Context(), pass); err != nil || drained {
		t.Fatalf("shutdown requested but process remains: drained=%v err=%v", drained, err)
	}
	if err := hosts.store.Update(func(tx store.Tx) error {
		task := store.GetTask(tx, "task-0")
		task.Status.State = api.TaskStateOrphaned
		return store.UpdateTask(tx, task)
	}); err != nil {
		t.Fatal(err)
	}
	if drained, err := scaler.drained(t.Context(), pass); err != nil || drained {
		t.Fatalf("manager orphaned task without observed stop: drained=%v err=%v", drained, err)
	}
	hosts.desired[0].Withdrawn = true
	hosts.sync(t)
	scaler.Backends = func(context.Context, string, string) (int, error) { return 1, nil }
	if drained, err := scaler.drained(t.Context(), pass); err != nil || drained {
		t.Fatalf("backend still registered: drained=%v err=%v", drained, err)
	}
	scaler.Backends = func(context.Context, string, string) (int, error) { return 0, nil }
	if drained, err := scaler.drained(t.Context(), pass); err != nil || !drained {
		t.Fatalf("terminal tasks and no backends: drained=%v err=%v", drained, err)
	}
}

func TestSwarmRetainsProtectedAndUnprovenWorkers(t *testing.T) {
	for _, kind := range []string{"no-proof", "failed-proof", "stateful-history", "terrabase", "orphan", "unlabelled-service"} {
		t.Run(kind, func(t *testing.T) {
			scaler, hosts, pass := swarmScaler(t)
			switch kind {
			case "no-proof":
				scaler.CanRetire = nil
			case "failed-proof":
				scaler.CanRetire = func(context.Context, string, string) error { return errors.New("retained volume attachment") }
			default:
				if err := hosts.store.Update(func(tx store.Tx) error {
					task := &api.Task{ID: "protected", NodeID: "ts-gru-4", ServiceID: "missing", Status: api.TaskStatus{State: api.TaskStateCompleted}}
					if kind != "orphan" {
						labels := map[string]string{}
						if kind == "stateful-history" {
							labels["terrascale.stateful"] = "true"
							labels["terrascale.role"] = "database"
						}
						if kind == "terrabase" {
							labels["terrascale.role"] = "terrabase"
						}
						service := &api.Service{ID: "service", Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "service", Labels: labels}}}
						if err := store.CreateService(tx, service); err != nil {
							return err
						}
						task.ServiceID = service.ID
					}
					return store.CreateTask(tx, task)
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, found, err := scaler.pickDrain(t.Context(), pass); err != nil || found {
				t.Fatalf("protected candidate selected: found=%v err=%v", found, err)
			}
			_ = scaler.cordon(t.Context(), pass)
			nodes, err := hosts.control.ListNodes(t.Context(), &api.ListNodesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if nodes.Nodes[0].Spec.Availability == api.NodeAvailabilityDrain {
				t.Fatal("drained protected worker")
			}
		})
	}
}

func TestSwarmCordonChecksIdentityAndLeadership(t *testing.T) {
	for _, kind := range []string{"wrong-instance", "empty-instance", "duplicate-instance", "lost-leadership", "missing-node", "manager", "wrong-certificate-role", "wrong-region", "pending-membership", "worker-hostname"} {
		t.Run(kind, func(t *testing.T) {
			scaler, hosts, pass := swarmScaler(t)
			if kind == "lost-leadership" {
				scaler.Leader.(*swarmLeader).guardErr = errors.New("leadership lost")
			}
			if err := hosts.store.Update(func(tx store.Tx) error {
				node := store.GetNode(tx, "ts-gru-4")
				switch kind {
				case "wrong-instance":
					node.Spec.Annotations.Labels["terrascale.instance-id"] = "other-instance"
				case "empty-instance":
					pass.record.Action.InstanceID = ""
				case "duplicate-instance":
					duplicate := node.Copy()
					duplicate.ID = "old-certificate-node"
					duplicate.Spec.Annotations.Name = "ts-gru-5"
					return store.CreateNode(tx, duplicate)
				case "missing-node":
					return store.DeleteNode(tx, node.ID)
				case "manager":
					node.Role = api.NodeRoleManager
					node.Certificate.Role = api.NodeRoleManager
					node.Spec.DesiredRole = api.NodeRoleManager
				case "pending-membership":
					node.Spec.Membership = api.NodeMembershipPending
				case "wrong-certificate-role":
					node.Certificate.Role = api.NodeRoleManager
				case "wrong-region":
					node.Spec.Annotations.Labels["terrascale.region"] = "eu-frankfurt-1"
				case "worker-hostname":
					node.Spec.Annotations.Name = ""
					node.Description = &api.NodeDescription{Hostname: "ts-gru-4"}
				}
				return store.UpdateNode(tx, node)
			}); err != nil {
				t.Fatal(err)
			}
			_ = scaler.cordon(t.Context(), pass)
			nodes, err := hosts.control.ListNodes(t.Context(), &api.ListNodesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range nodes.Nodes {
				if node.Spec.Availability == api.NodeAvailabilityDrain {
					t.Fatal("drained without trusted identity/authority")
				}
			}
		})
	}
}

func TestSwarmControlRejectsStaleNodeVersion(t *testing.T) {
	scaler, hosts, _ := swarmScaler(t)
	before, err := hosts.control.GetNode(t.Context(), &api.GetNodeRequest{NodeID: "ts-gru-4"})
	if err != nil {
		t.Fatal(err)
	}
	if err := scaler.setAvailability(t.Context(), "ts-gru-4", "ocid-ts-gru-4", api.NodeAvailabilityDrain, 7); err != nil {
		t.Fatal(err)
	}
	_, err = hosts.control.UpdateNode(t.Context(), &api.UpdateNodeRequest{NodeID: before.Node.ID, NodeVersion: &before.Node.Meta.Version, Spec: &before.Node.Spec})
	if err == nil {
		t.Fatal("accepted stale node version")
	}
	if status.Code(err) != codes.Unknown || !strings.Contains(err.Error(), "update out of sequence") {
		t.Fatalf("unexpected CAS error: %v", err)
	}
	after, err := hosts.control.GetNode(t.Context(), &api.GetNodeRequest{NodeID: "ts-gru-4"})
	if err != nil {
		t.Fatal(err)
	}
	if after.Node.Spec.Availability != api.NodeAvailabilityDrain {
		t.Fatal("stale update undid drain")
	}
}

func TestSwarmRetirementRechecksAfterDrainAndLaunchTimeout(t *testing.T) {
	scaler, hosts, pass := swarmScaler(t)
	if err := scaler.cordon(t.Context(), pass); err != nil {
		t.Fatal(err)
	}
	hosts.desired = []desiredTask{{Node: "ts-gru-4", Role: "terrabase"}}
	hosts.sync(t)
	pass.record.Action.Step = stepRemove
	if err := scaler.remove(t.Context(), pass); err != nil {
		t.Fatal(err)
	}
	if pass.pool.Pending == "" || pass.record.Action.Step != stepRemove {
		t.Fatal("retirement did not retain newly observed database member")
	}
	if err := scaler.expiredSafe(t.Context(), pass, pass.pool.Instances[0]); err == nil {
		t.Fatal("launch timeout bypassed database safety")
	}
	scaler.CanRetire = nil
	if err := scaler.expiredSafe(t.Context(), pass, PoolInstance{Name: "unenrolled", ID: "other"}); err == nil {
		t.Fatal("launch timeout bypassed missing retained-volume proof")
	}
}

func TestSwarmPoolBindingUsesOCIIdentityInsteadOfCanonicalHostID(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprintf("duplicate=%t", duplicate), func(t *testing.T) {
			scaler, hosts, pass := swarmScaler(t)
			canonicalHostID := entityid.New()
			managerSlot := "gru-controller-primary"
			if err := hosts.store.Update(func(tx store.Tx) error {
				node := store.GetNode(tx, "ts-gru-4")
				node.Spec.Annotations.Name = canonicalHostID
				node.Description = &api.NodeDescription{Hostname: canonicalHostID}
				if err := store.UpdateNode(tx, node); err != nil {
					return err
				}
				if duplicate {
					old := node.Copy()
					old.ID = "old-worker-certificate"
					old.Spec.Annotations.Name = entityid.New()
					if err := store.CreateNode(tx, old); err != nil {
						return err
					}
				}
				for _, region := range []string{"sa-saopaulo-1", "eu-frankfurt-1"} {
					manager := &api.Node{ID: region + "-manager", Role: api.NodeRoleManager, Certificate: api.Certificate{Role: api.NodeRoleManager},
						Spec: api.NodeSpec{DesiredRole: api.NodeRoleManager, Membership: api.NodeMembershipAccepted,
							Annotations: api.Annotations{Name: managerSlot, Labels: map[string]string{"terrascale.region": region, "terrascale.instance-id": "ocid-" + region + "-manager"}}},
						Status: api.NodeStatus{State: api.NodeStatus_READY}}
					if err := store.CreateNode(tx, manager); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			listed, err := hosts.control.ListNodes(t.Context(), &api.ListNodesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			pass.obs = scaler.observe(pass.pool, listed.Nodes)
			if pass.obs.quorum != 1 || pass.obs.nodes != 2 || !pass.obs.counted[managerSlot] {
				t.Fatalf("regional manager slot was not counted independently of pool naming: %+v", pass.obs)
			}
			if pass.obs.live["ts-gru-4"] == duplicate || pass.obs.counted[canonicalHostID] {
				t.Fatalf("canonical host ID was interpreted as the pool hostname: %+v", pass.obs)
			}
			loads := countedLoads([]NodeLoad{{Node: canonicalHostID}, {Node: "ts-gru-4"}, {Node: managerSlot}}, pass.obs)
			wantLoads := 2
			if duplicate {
				wantLoads--
			}
			if len(loads) != wantLoads || slices.ContainsFunc(loads, func(load NodeLoad) bool { return load.Node == canonicalHostID }) {
				t.Fatalf("load samples lost their trusted pool/manager names: %+v", loads)
			}
			target, found, err := scaler.pickDrain(t.Context(), pass)
			if err != nil || found == duplicate {
				t.Fatalf("pool binding candidate: found=%v err=%v", found, err)
			}
			if duplicate {
				if _, err := scaler.worker(t.Context(), "ts-gru-4", "ocid-ts-gru-4"); err == nil {
					t.Fatal("duplicate OCI identity resolved to a worker")
				}
				return
			}
			if target.Name != "ts-gru-4" || target.ID != "ocid-ts-gru-4" {
				t.Fatalf("pool identity was not preserved for retirement: %+v", target)
			}
			if err := scaler.cordon(t.Context(), pass); err != nil {
				t.Fatal(err)
			}
			if drained, err := scaler.drained(t.Context(), pass); err != nil || !drained {
				t.Fatalf("canonical worker did not drain through OCI binding: drained=%v err=%v", drained, err)
			}
			observed, err := hosts.control.GetNode(t.Context(), &api.GetNodeRequest{NodeID: "ts-gru-4"})
			if err != nil {
				t.Fatal(err)
			}
			if observed.Node.Spec.Annotations.Name != canonicalHostID || observed.Node.Spec.Availability != api.NodeAvailabilityDrain {
				t.Fatalf("drain changed or lost canonical host identity: node=%+v", observed.Node)
			}
		})
	}
}
