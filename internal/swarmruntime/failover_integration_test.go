package swarmruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/swarmkit/v2/api"
)

// Three managers share one disposable host/runtime; this proves logical Raft
// failover and real execution, not host isolation or regional availability.
func TestRuntimeThreeManagerLeaderLoss(t *testing.T) {
	if *integrationSocket == "" {
		t.Fatal("provide -containerd-socket for a disposable real runtime")
	}
	// Managers must stay alive until service cleanup finishes.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	var nodes []*Node
	var clients []api.ControlClient
	var executors []*Executor
	var joinAddress, joinToken string
	for i, name := range []string{"founder", "manager-two", "manager-three"} {
		cfg := nodeFixtureConfig(t, name, "manager")
		cfg.Admission.Region = "gru"
		cfg.Admission.ManagerAddress, cfg.Admission.JoinToken = joinAddress, joinToken
		e, err := NewExecutor(*integrationSocket, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		node, err := StartNode(ctx, cfg, e)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nodeFixtureStop(t, node) })
		client, err := node.ControlClient(ctx)
		if err != nil {
			t.Fatal(err)
		}
		nodes, clients, executors = append(nodes, node), append(clients, client), append(executors, e)
		if _, err := AdmitNode(ctx, clients[0], node.ID(), cfg.Admission); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			joinAddress, err = node.RemoteAddress()
			if err != nil {
				t.Fatal(err)
			}
			clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
			if err != nil || len(clusters.Clusters) != 1 {
				t.Fatalf("cluster join material: %v %v", clusters, err)
			}
			joinToken = clusters.Clusters[0].RootCA.JoinTokens.Manager
		}
	}
	var leader *api.Node
	waitRuntime(t, ctx, func() (bool, error) {
		listed, err := clients[0].ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil || len(listed.Nodes) != 3 {
			return false, err
		}
		leader = nil
		for _, node := range listed.Nodes {
			if node.ManagerStatus == nil || node.ManagerStatus.Reachability != api.RaftMemberStatus_REACHABLE {
				return false, nil
			}
			if node.ManagerStatus.Leader {
				leader = node
			}
		}
		return leader != nil, nil
	})
	// Keep the serving task on a surviving agent, so the exercise isolates
	// manager quorum loss from worker-loss rescheduling semantics.
	paused := leader.Spec.Copy()
	paused.Availability = api.NodeAvailabilityPause
	if _, err := clients[0].UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: leader.ID, NodeVersion: &leader.Meta.Version, Spec: paused}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	intent := ServiceIntent{
		ID: "leader-loss", Role: "smoke", Region: "gru", Environment: "integration", Architecture: runtime.GOARCH, Replicas: 1,
		Container: &api.ContainerSpec{Image: integrationImage, User: "65532:65532", Command: []string{"/bin/sh", "-c", fmt.Sprintf("exec nc -lk -p %d -e /bin/sh -c \"printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 5\\r\\nConnection: close\\r\\n\\r\\nready'\"", port)}},
		Resources: &api.ResourceRequirements{Limits: &api.Resources{NanoCPUs: 250_000_000, MemoryBytes: 64 << 20}},
		Ports:     []*api.PortConfig{{Name: "ready", Protocol: api.ProtocolTCP, PublishMode: api.PublishModeHost, TargetPort: port, PublishedPort: port}},
	}
	client := clients[0]
	var services []string
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		for _, id := range services {
			tasks, err := client.ListTasks(cleanup, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{id}}})
			_, _ = client.RemoveService(cleanup, &api.RemoveServiceRequest{ServiceID: id})
			if err != nil {
				t.Error(err)
				continue
			}
			for _, task := range tasks.Tasks {
				controller, err := executors[0].Controller(task)
				if err == nil {
					err = controller.Remove(cleanup)
				}
				if err != nil {
					t.Error(err)
				}
			}
		}
	})
	service, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	services = append(services, service.ID)
	httpClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer httpClient.CloseIdleConnections()
	probe := func(ctx context.Context, _ *api.Task) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/readyz", port), nil)
		if err != nil {
			return err
		}
		response, err := httpClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 32))
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "ready" {
			return fmt.Errorf("HTTP readiness: status=%d body=%q err=%v", response.StatusCode, body, err)
		}
		return nil
	}
	var taskID string
	waitRuntime(t, ctx, func() (bool, error) {
		view, err := ObserveService(ctx, client, service.ID, probe)
		if err != nil || view.ReadyReplicas != 1 || len(view.Tasks) != 1 {
			return false, err
		}
		taskID = view.Tasks[0].TaskID
		if view.Tasks[0].NodeID == leader.ID {
			t.Fatal("serving task scheduled on paused leader")
		}
		return true, nil
	})
	container, err := executors[0].client.LoadContainer(runtimeContext(ctx), "ts-"+taskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := container.Task(runtimeContext(ctx), nil)
	if err != nil {
		t.Fatal(err)
	}
	pid := task.Pid()
	oldLeader := leader.ID
	for i, node := range nodes {
		if node.ID() == oldLeader {
			nodeFixtureStop(t, node)
		} else {
			client = clients[i]
		}
	}
	failoverStarted := time.Now()
	var newLeader string
	waitRuntime(t, ctx, func() (bool, error) {
		if err := probe(ctx, nil); err != nil {
			t.Fatalf("serving failed during leader loss: %v", err)
		}
		poll, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		listed, err := client.ListNodes(poll, &api.ListNodesRequest{})
		if err != nil {
			return false, err
		}
		for _, node := range listed.Nodes {
			if node.ID != oldLeader && node.ManagerStatus != nil && node.ManagerStatus.Leader {
				newLeader = node.ID
				for i, n := range nodes {
					if n.ID() == newLeader {
						client = clients[i]
					}
				}
				return true, nil
			}
		}
		return false, nil
	})
	failoverDuration := time.Since(failoverStarted)
	view, err := ObserveService(ctx, client, service.ID, probe)
	if err != nil || view.ReadyReplicas != 1 || len(view.Tasks) != 1 || view.Tasks[0].TaskID != taskID {
		t.Fatalf("serving task changed after election: %+v %v", view, err)
	}
	containers, err := executors[0].client.Containers(runtimeContext(ctx), "labels.terrascale.service=="+service.ID)
	if err != nil || len(containers) != 1 {
		t.Fatalf("duplicate runtime containers after election: count=%d err=%v", len(containers), err)
	}
	task, err = containers[0].Task(runtimeContext(ctx), nil)
	if err != nil || task.Pid() != pid {
		t.Fatalf("serving PID changed after election: %v %v", task, err)
	}
	// A new real workload and a metadata CAS prove writes reach the new leader.
	intent.ID, intent.Ports = "after-leader-loss", nil
	intent.Container.Command = []string{"/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}
	created, err := applyService(ctx, client, intent)
	if err != nil {
		t.Fatal(err)
	}
	services = append(services, created.ID)
	waitRuntime(t, ctx, func() (bool, error) {
		view, err := ObserveService(ctx, client, created.ID, nil)
		return err == nil && view.RunningReplicas == 1 && len(view.Tasks) == 1, err
	})
	spec := created.Spec.Copy()
	spec.Annotations.Labels["terrascale.failover-proof"] = "committed"
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.ID, ServiceVersion: &created.Meta.Version, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	observed, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: created.ID})
	if err != nil || observed.Service.Spec.Annotations.Labels["terrascale.failover-proof"] != "committed" {
		t.Fatalf("new-leader update missing: %v %v", observed, err)
	}
	for _, id := range services {
		if _, err := client.RemoveService(ctx, &api.RemoveServiceRequest{ServiceID: id}); err != nil {
			t.Fatal(err)
		}
		waitRuntime(t, ctx, func() (bool, error) {
			containers, err := executors[0].client.Containers(runtimeContext(ctx), "labels.terrascale.service=="+id)
			return err == nil && len(containers) == 0, err
		})
	}
	services = nil
	if _, err := executors[0].client.LoadContainer(runtimeContext(ctx), "ts-"+taskID); !errdefs.IsNotFound(err) {
		t.Fatalf("serving container survived removal: %v", err)
	}
	t.Logf("logical three-manager failover %s -> %s in %s retained task %s pid %d; new-leader create/update/remove passed", oldLeader, newLeader, failoverDuration, taskID, pid)
}
