package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func settleManagers(ctx context.Context, keeper *swarmruntime.ManagerKeeper) error {
	if _, err := keeper.Reconcile(ctx, time.Now()); err != nil {
		return fmt.Errorf("manager keeper: %w", err)
	}
	return nil
}

type quorumHost struct {
	state    string
	node     *swarmruntime.Node
	executor *swarmruntime.Executor
	address  string
}

func managerQuorumJourney(ctx context.Context, state string, manager *swarmruntime.Node) error {
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
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
	var workers []*quorumHost
	defer func() {
		for _, worker := range workers {
			stop, done := context.WithTimeout(context.Background(), 15*time.Second)
			_ = worker.node.Stop(stop)
			done()
			_ = worker.executor.Close()
		}
	}()
	join := func(i, ready, managers int) error {
		worker := &quorumHost{state: filepath.Join(state, fmt.Sprintf("worker-%d", i)), address: fmt.Sprintf("127.0.0.1:%d", 4243+i)}
		if worker.executor, err = swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, worker.state); err != nil {
			return err
		}
		joining, err := swarmruntime.JoiningAdmission(fmt.Sprintf("worker-%d", i), fmt.Sprintf("instance-%d", i), "127.0.0.1:4242", clusters.Clusters[0].RootCA.JoinTokens.Worker)
		if err != nil {
			return err
		}
		if worker.node, err = swarmruntime.StartHost(ctx, worker.state, worker.executor, worker.address, worker.address, joining); err != nil {
			return err
		}
		workers = append(workers, worker)
		keep(worker.state, worker.node)
		if err := awaitPromotionReady(ctx, client, watcher, ready, managers); err != nil {
			return fmt.Errorf("worker-%d joins: %w", i, err)
		}
		admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: fmt.Sprintf("worker-%d", i), InstanceID: fmt.Sprintf("instance-%d", i), FounderID: joining.FounderID, Role: "container"}
		_, err = swarmruntime.AdmitNode(ctx, client, worker.node.ID(), admission)
		return err
	}
	stopHost := func(host *swarmruntime.Node) error {
		stop, done := context.WithTimeout(ctx, 15*time.Second)
		defer done()
		return host.Stop(stop)
	}
	quorum := func(client api.ControlClient, want swarmruntime.ManagerQuorum) error {
		_, got, err := swarmruntime.ListMembers(ctx, client)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("quorum %s, want %s", got, want)
		}
		return nil
	}
	roles := func() (map[string]api.NodeRole, error) {
		listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return nil, err
		}
		roles := map[string]api.NodeRole{}
		for _, node := range listed.Nodes {
			roles[node.ID] = node.Role
		}
		return roles, nil
	}
	for i := range 2 {
		if err := join(i, i+2, 1); err != nil {
			return err
		}
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 3); err != nil {
		return fmt.Errorf("a three-host pool region did not reach three managers by itself: %w", err)
	}
	stopKeeping()
	keepers.Wait()
	if err := join(2, 4, 3); err != nil {
		return err
	}
	keeper := swarmruntime.NewManagerKeeper(filepath.Join(state, "manager"), manager)
	if change, err := keeper.Reconcile(ctx, time.Now()); change != "" || err != nil {
		return fmt.Errorf("a fourth ready host changed three voters: %q: %v", change, err)
	}
	if err := stopHost(workers[0].node); err != nil {
		return fmt.Errorf("stop manager worker-0: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 2); err != nil {
		return fmt.Errorf("worker-0 stops being a ready manager: %w", err)
	}
	died := time.Now()
	if change, err := keeper.Reconcile(ctx, died); change != "" || err != nil {
		return fmt.Errorf("a just-unreachable voter was replaced: %q: %v", change, err)
	}
	if err := quorum(client, swarmruntime.ManagerQuorum{Voters: 3, Reachable: 2}); err != nil {
		return fmt.Errorf("one stopped voter: %w", err)
	}
	stored, _, err := swarmruntime.StoredAdmission(workers[0].state)
	if err != nil {
		return err
	}
	if workers[0].node, err = swarmruntime.StartHost(ctx, workers[0].state, workers[0].executor, workers[0].address, workers[0].address, stored); err != nil {
		return fmt.Errorf("restart worker-0: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 4, 3); err != nil {
		return fmt.Errorf("worker-0 recovers as a voter: %w", err)
	}
	if change, err := keeper.Reconcile(ctx, died.Add(swarmruntime.ManagerReplaceAfter)); change != "" || err != nil {
		return fmt.Errorf("a recovered voter was demoted: %q: %v", change, err)
	}
	if err := stopHost(workers[0].node); err != nil {
		return fmt.Errorf("stop manager worker-0 again: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 2); err != nil {
		return err
	}
	died = time.Now()
	if change, err := keeper.Reconcile(ctx, died); change != "" || err != nil {
		return fmt.Errorf("the recovery did not restart the unreachable clock: %q: %v", change, err)
	}
	replaced, err := keeper.Reconcile(ctx, died.Add(swarmruntime.ManagerReplaceAfter))
	if err != nil {
		return fmt.Errorf("replace a dead voter with quorum 2 of 3: %w", err)
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 3); err != nil {
		return fmt.Errorf("after %q: %w", replaced, err)
	}
	current, err := roles()
	if err != nil {
		return err
	}
	if current[workers[0].node.ID()] != api.NodeRoleWorker || current[workers[2].node.ID()] != api.NodeRoleManager {
		return fmt.Errorf("after %q: roles %v, want worker-0 demoted and worker-2 promoted", replaced, current)
	}
	if err := quorum(client, swarmruntime.ManagerQuorum{Voters: 3, Reachable: 3}); err != nil {
		return fmt.Errorf("after the replacement: %w", err)
	}
	if err := join(3, 4, 3); err != nil {
		return err
	}
	if err := stopHost(workers[3].node); err != nil {
		return fmt.Errorf("stop worker-3: %w", err)
	}
	got, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: workers[3].node.ID()})
	if err != nil {
		return err
	}
	spec := got.Node.Spec.Copy()
	spec.DesiredRole = api.NodeRoleManager
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: got.Node.ID, NodeVersion: &got.Node.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	failed := time.Now()
	if change, err := keeper.Reconcile(ctx, failed); change != "" || err != nil {
		return fmt.Errorf("a candidate inside its join wait was touched: %q: %v", change, err)
	}
	unlock, err := swarmruntime.LockMembership(filepath.Join(state, "manager"))
	if err != nil {
		return err
	}
	change, lockErr := keeper.Reconcile(ctx, failed.Add(swarmruntime.ManagerJoinWait))
	unlock()
	if change != "" || lockErr == nil || !strings.Contains(lockErr.Error(), "another membership change") {
		return fmt.Errorf("the manager keeper ignored a membership change in progress: %q: %v", change, lockErr)
	}
	reverted, err := keeper.Reconcile(ctx, failed.Add(swarmruntime.ManagerJoinWait))
	if err != nil {
		return fmt.Errorf("return a candidate that never joined Raft: %w", err)
	}
	if current, err = roles(); err != nil {
		return err
	}
	if current[workers[3].node.ID()] != api.NodeRoleWorker {
		return fmt.Errorf("after %q: worker-3 is %s, want worker", reverted, current[workers[3].node.ID()])
	}
	if err := quorum(client, swarmruntime.ManagerQuorum{Voters: 3, Reachable: 3}); err != nil {
		return fmt.Errorf("after the failed candidate: %w", err)
	}
	if err := stopHost(manager); err != nil {
		return fmt.Errorf("stop the leader: %w", err)
	}
	leader, _, err := nextLeader(ctx, []*swarmruntime.Node{workers[1].node, workers[2].node})
	if err != nil {
		return err
	}
	leaderState := workers[1].state
	if leader == workers[2].node {
		leaderState = workers[2].state
	}
	successor := swarmruntime.NewManagerKeeper(leaderState, leader)
	handoff := time.Now()
	if change, err := successor.Reconcile(ctx, handoff); change != "" || err != nil {
		return fmt.Errorf("the new leader acted on a just-stopped voter: %q: %v", change, err)
	}
	if change, err := successor.Reconcile(ctx, handoff.Add(swarmruntime.ManagerReplaceAfter)); change != "" || err != nil {
		return fmt.Errorf("the new leader demoted a voter with no replacement: %q: %v", change, err)
	}
	leaderClient, leaderConn, err := swarmruntime.DialControl(leaderState)
	if err != nil {
		return err
	}
	defer leaderConn.Close()
	if err := quorum(leaderClient, swarmruntime.ManagerQuorum{Voters: 3, Reachable: 2}); err != nil {
		return fmt.Errorf("after the leader handoff: %w", err)
	}
	fmt.Printf("ok manager-quorum: a three-host pool region reaches three voters by itself; a fourth host stays a worker; a recovered voter is kept; a dead voter keeps quorum 2 of 3 and the leader %s; %s; a new leader keeps three voters with no replacement\n", replaced, reverted)
	return nil
}
