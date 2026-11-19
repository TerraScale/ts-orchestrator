package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func settleManagers(ctx context.Context, keeper *swarmruntime.ManagerKeeper) error {
	for range swarmruntime.VotingManagers {
		change, err := keeper.Reconcile(ctx, time.Now())
		if err != nil {
			return fmt.Errorf("manager keeper: %w", err)
		}
		if change == "" {
			return nil
		}
	}
	return nil
}

func managerQuorumJourney(ctx context.Context, state string, manager *swarmruntime.Node) error {
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
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
	keeping, stopKeeping := context.WithCancel(ctx)
	var keepers sync.WaitGroup
	defer keepers.Wait()
	defer stopKeeping()
	keep := func(state string, node *swarmruntime.Node) {
		keepers.Go(func() { swarmruntime.NewManagerKeeper(state, node).Run(keeping) })
	}
	keep(filepath.Join(state, "manager"), manager)
	var workers []*swarmruntime.Node
	var executors []*swarmruntime.Executor
	defer func() {
		for _, worker := range workers {
			stop, done := context.WithTimeout(context.Background(), 15*time.Second)
			_ = worker.Stop(stop)
			done()
		}
		for _, executor := range executors {
			_ = executor.Close()
		}
	}()
	join := func(i, managers int) error {
		workerState := filepath.Join(state, fmt.Sprintf("worker-%d", i))
		executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, workerState)
		if err != nil {
			return err
		}
		executors = append(executors, executor)
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
		keep(workerState, worker)
		if err := awaitPromotionReady(ctx, client, watcher, len(workers)+1, managers); err != nil {
			return fmt.Errorf("worker-%d joins: %w", i, err)
		}
		admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: fmt.Sprintf("worker-%d", i), InstanceID: fmt.Sprintf("instance-%d", i), FounderID: joining.FounderID, Role: "container"}
		_, err = swarmruntime.AdmitNode(ctx, client, worker.ID(), admission)
		return err
	}
	for i := range 2 {
		if err := join(i, 1); err != nil {
			return err
		}
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 3); err != nil {
		return fmt.Errorf("a three-host pool region did not reach three managers by itself: %w", err)
	}
	stopKeeping()
	keepers.Wait()
	if err := join(2, 3); err != nil {
		return err
	}
	keeper := swarmruntime.NewManagerKeeper(filepath.Join(state, "manager"), manager)
	if change, err := keeper.Reconcile(ctx, time.Now()); change != "" || err != nil {
		return fmt.Errorf("a fourth ready host changed three ready managers: %q: %v", change, err)
	}
	stop, done := context.WithTimeout(ctx, 15*time.Second)
	err = workers[0].Stop(stop)
	done()
	if err != nil {
		return fmt.Errorf("kill manager worker-0: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 2); err != nil {
		return fmt.Errorf("worker-0 stops being a ready manager: %w", err)
	}
	died := time.Now()
	if change, err := keeper.Reconcile(ctx, died); change != "" || err != nil {
		return fmt.Errorf("a just-unreachable manager was replaced before %s: %q: %v", swarmruntime.ManagerReplaceAfter, change, err)
	}
	quorum, err := swarmruntime.ReadManagerQuorum(ctx, client)
	if err != nil {
		return err
	}
	if quorum != (swarmruntime.ManagerQuorum{Voters: 3, Reachable: 2}) {
		return fmt.Errorf("one dead manager: %s, want 2 of 3", quorum)
	}
	change, err := keeper.Reconcile(ctx, died.Add(swarmruntime.ManagerReplaceAfter))
	if err != nil {
		return fmt.Errorf("replace the dead manager with quorum 2 of 3: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 3); err != nil {
		return fmt.Errorf("after %q: %w", change, err)
	}
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	roles := map[string]api.NodeRole{}
	for _, node := range listed.Nodes {
		roles[node.ID] = node.Role
	}
	if roles[workers[0].ID()] != api.NodeRoleWorker || roles[workers[2].ID()] != api.NodeRoleManager || roles[manager.ID()] != api.NodeRoleManager || roles[workers[1].ID()] != api.NodeRoleManager {
		return fmt.Errorf("after %q: roles %v, want worker-0 demoted and worker-2 promoted", change, roles)
	}
	if quorum, err = swarmruntime.ReadManagerQuorum(ctx, client); err != nil || quorum != (swarmruntime.ManagerQuorum{Voters: 3, Reachable: 3}) {
		return fmt.Errorf("after the replacement: %s: %v", quorum, err)
	}
	fmt.Printf("ok manager-quorum: a three-host pool region reaches three managers by itself; a fourth host stays a worker; one dead manager keeps quorum 2 of 3 and after %s the leader %s\n", swarmruntime.ManagerReplaceAfter, change)
	return nil
}
