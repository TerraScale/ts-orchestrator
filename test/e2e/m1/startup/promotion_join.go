package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func promotionJoinJourney(ctx context.Context, state string, manager *swarmruntime.Node) error {
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
	workerState := filepath.Join(state, "worker-0")
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, workerState)
	if err != nil {
		return err
	}
	defer executor.Close()
	joining, err := swarmruntime.JoiningAdmission("worker-0", "instance-0", "127.0.0.1:4242", clusters.Clusters[0].RootCA.JoinTokens.Worker)
	if err != nil {
		return err
	}
	worker, err := swarmruntime.StartHost(ctx, workerState, executor, "127.0.0.1:4243", "127.0.0.1:4253", joining)
	if err != nil {
		return err
	}
	defer func() { _ = worker.Stop(context.Background()) }()
	if err := awaitPromotionReady(ctx, client, watcher, 2, 1); err != nil {
		return err
	}
	admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: "worker-0", InstanceID: "instance-0", FounderID: joining.FounderID, Role: "container"}
	if _, err := swarmruntime.AdmitNode(ctx, client, worker.ID(), admission); err != nil {
		return err
	}
	_, err = manager.PromoteManager(ctx, "unreachable-join")
	if err == nil || !strings.Contains(err.Error(), "never became a Raft voter, so its manager intent was rolled back") {
		return fmt.Errorf("a promotion whose Raft listener is unreachable did not roll back its intent: %v", err)
	}
	if err := awaitWorkerRole(ctx, client, watcher, worker.ID()); err != nil {
		return err
	}
	members, err := manager.MemberView()
	if err != nil {
		return err
	}
	if members.Voters != 1 {
		return fmt.Errorf("the refused join changed the Raft voters to %d", members.Voters)
	}
	fmt.Println("ok promotion-join: SwarmKit refused the unreachable worker's Raft join; the promotion rolled back its own intent and the region kept one voter")
	return nil
}

func awaitWorkerRole(ctx context.Context, client api.ControlClient, watcher api.WatchClient, nodeID string) error {
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := watcher.Watch(watchCtx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{
		Kind: "node", Action: api.WatchActionKindUpdate, Filters: []*api.SelectBy{{By: &api.SelectBy_ID{ID: nodeID}}},
	}}})
	if err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil {
		return err
	}
	for {
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: nodeID})
		if err != nil {
			return err
		}
		node := current.Node
		if node.Spec.DesiredRole == api.NodeRoleWorker && node.Role == api.NodeRoleWorker {
			return nil
		}
		if _, err := stream.Recv(); err != nil {
			return fmt.Errorf("worker-0 did not return to worker after the rollback: role %v desired %v: %w", node.Role, node.Spec.DesiredRole, err)
		}
	}
}
