package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func nodeScaleJourney(ctx context.Context, state string, manager *swarmruntime.Node) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialControl(filepath.Join(state, "manager"))
	if err != nil {
		return err
	}
	defer conn.Close()
	watcher := api.NewWatchClient(conn)
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		return err
	}
	var workers []*swarmruntime.Node
	defer func() {
		for _, worker := range workers {
			_ = worker.Stop(context.Background())
		}
	}()
	for i := range 3 {
		workerState := filepath.Join(state, fmt.Sprintf("worker-%d", i))
		executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, workerState)
		if err != nil {
			return err
		}
		defer executor.Close()
		address := fmt.Sprintf("127.0.0.1:%d", 4243+i)
		joining, err := swarmruntime.JoiningAdmission(fmt.Sprintf("worker-%d", i), fmt.Sprintf("instance-%d", i), "127.0.0.1:4242", clusters.Clusters[0].RootCA.JoinTokens.Worker)
		if err != nil {
			return err
		}
		worker, err := swarmruntime.StartHost(ctx, workerState, executor, address, address, joining)
		if err != nil {
			return err
		}
		workers = append(workers, worker)
		if err := awaitPromotionReady(ctx, client, watcher, i+2, 1); err != nil {
			return err
		}
		admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: fmt.Sprintf("worker-%d", i), InstanceID: fmt.Sprintf("instance-%d", i), FounderID: joining.FounderID, Role: "container"}
		if _, err := swarmruntime.AdmitNode(ctx, client, worker.ID(), admission); err != nil {
			return err
		}
	}
	for range 2 {
		if _, err := manager.PromoteManager(ctx); err != nil {
			return err
		}
	}
	bounds := fleet.Nodes{Min: 3, Max: 4}
	view, err := quietView(ctx, manager)
	if err != nil {
		return err
	}
	pool := poolOf(view, "instance-0", "instance-1", "instance-2")
	scaler := &fleet.NodeScaler{}
	start := time.Now()
	steps := []struct {
		at                 time.Duration
		pool               compute.Pool
		action, code, node string
	}{
		{0, pool, "hold", "unhealthy", ""},
		{6 * time.Minute, pool, "hold", "steady", ""},
		{22 * time.Minute, poolOf(view, "instance-0", "instance-1"), "hold", "quorum", ""},
		{22 * time.Minute, pool, "cordon", "low-demand", "worker-2"},
	}
	for _, step := range steps {
		if err := expect(scaler.Decide(start.Add(step.at), bounds, view, step.pool, true), step.action, step.code, step.node); err != nil {
			return fmt.Errorf("at +%s: %w", step.at, err)
		}
	}
	if err := manager.Cordon(ctx, workers[2].ID(), start.Add(22*time.Minute)); err != nil {
		return err
	}
	if view, err = quietView(ctx, manager); err != nil {
		return err
	}
	if err := expect(scaler.Decide(start.Add(23*time.Minute), bounds, view, pool, true), "remove", "drained", "worker-2"); err != nil {
		return fmt.Errorf("one change in flight: %w", err)
	}
	stop, done := context.WithTimeout(ctx, 15*time.Second)
	err = manager.Stop(stop)
	done()
	if err != nil {
		return fmt.Errorf("kill the leader: %w", err)
	}
	leader, view, err := nextLeader(ctx, workers[:2])
	if err != nil {
		return err
	}
	successor := &fleet.NodeScaler{}
	took := time.Now()
	if err := expect(successor.Decide(took, bounds, view, pool, true), "hold", "unhealthy", "worker-2"); err != nil {
		return fmt.Errorf("new leader: %w", err)
	}
	if d := successor.Decide(took.Add(6*time.Minute), bounds, view, pool, true); d.Node != "worker-2" || d.Action == "cordon" {
		return fmt.Errorf("new leader after settling: decision %s, want the same drain of worker-2", d)
	}
	if err := leader.Remove(ctx, "worker-2", func(ctx context.Context) error { return ctx.Err() }); err != nil {
		return err
	}
	if view, err = quietView(ctx, leader); err != nil {
		return err
	}
	for _, node := range view.Nodes {
		if node.Hostname == "worker-2" {
			return errors.New("worker-2 is still in the swarm after its removal")
		}
	}
	fmt.Println("ok node-scale: Decide refuses a new leader and a manager; one drained worker at a time; after a leader change Decide picks the same drained worker; RemoveMember removes it on the new leader")
	return nil
}

func quietView(ctx context.Context, node *swarmruntime.Node) (fleet.SwarmView, error) {
	view, err := node.SwarmView(ctx)
	view.Demand = fleet.Demand{Known: true}
	return view, err
}

func poolOf(view fleet.SwarmView, instances ...string) compute.Pool {
	pool := compute.Pool{InstancePool: core.InstancePool{Id: common.String("node-scale-pool"), Size: common.Int(len(instances)),
		LifecycleState: core.InstancePoolLifecycleStateRunning}}
	for _, instance := range instances {
		pool.Members = append(pool.Members, core.InstanceSummary{Id: common.String(instance)})
	}
	return pool
}

func expect(d fleet.NodeDecision, action, code, node string) error {
	if d.Action != action || d.Code != code || d.Node != node {
		return fmt.Errorf("decision %s, want %s %s %s", d, action, code, node)
	}
	return nil
}

func nextLeader(ctx context.Context, managers []*swarmruntime.Node) (*swarmruntime.Node, fleet.SwarmView, error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		for _, manager := range managers {
			if view, err := quietView(ctx, manager); err == nil {
				return manager, view, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, fleet.SwarmView{}, fmt.Errorf("no new Raft leader after the leader stopped: %w", ctx.Err())
		case <-tick.C:
		}
	}
}
