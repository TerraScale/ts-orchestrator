package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/fsnotify/fsnotify"
	"github.com/moby/swarmkit/v2/api"
	"golang.org/x/sys/unix"
)

func promotionJourney(ctx context.Context, state string, manager *swarmruntime.Node) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, conn, err := swarmruntime.DialControl(filepath.Join(state, "manager"))
	if err != nil {
		return err
	}
	defer conn.Close()
	watcher := api.NewWatchClient(conn)
	if err := os.MkdirAll("/var/lib/ts-orch", 0o700); err != nil {
		return err
	}
	if err := unix.Mount(filepath.Join(state, "manager"), "/var/lib/ts-orch", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer unix.Unmount("/var/lib/ts-orch", 0)
	command := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, os.Args[3], append([]string{"member"}, args...)...).CombinedOutput()
	}
	if output, err := command("leave", "manager"); err == nil || !strings.Contains(string(output), "cannot remove") {
		return fmt.Errorf("last manager removal was not refused: %s: %v", output, err)
	}
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
	for i := range 2 {
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
		if err := awaitPromotionReady(ctx, client, watcher, len(workers)+1, i+1); err != nil {
			return err
		}
		admission := swarmruntime.Admission{Region: "sa-saopaulo-1", HostID: fmt.Sprintf("worker-%d", i), InstanceID: fmt.Sprintf("instance-%d", i), FounderID: joining.FounderID, Role: "container"}
		if _, err := swarmruntime.AdmitNode(ctx, client, worker.ID(), admission); err != nil {
			return err
		}
		if err := awaitPromotionReady(ctx, client, watcher, len(workers)+1, i+1); err != nil {
			return fmt.Errorf("joining workers changed manager roles without an operator command: %w", err)
		}
		promotion, err := manager.PromoteManager(ctx)
		if err != nil {
			return fmt.Errorf("promote worker-%d: %w", i, err)
		}
		if promotion.Hostname != fmt.Sprintf("worker-%d", i) || promotion.Voters != i+2 {
			return fmt.Errorf("promotion %+v, want worker-%d as voter %d", promotion, i, i+2)
		}
		listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		voters := 0
		for _, node := range listed.Nodes {
			if node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
				voters++
			}
		}
		if voters != i+2 {
			return fmt.Errorf("after promoting worker-%d: %d Raft-reachable managers, want %d", i, voters, i+2)
		}
	}
	if _, err := manager.PromoteManager(ctx); err == nil || !strings.Contains(err.Error(), "already has 3 voting managers") {
		return fmt.Errorf("a fourth voting manager was not refused: %v", err)
	}
	if _, err := workers[0].PromoteManager(ctx); !errors.Is(err, swarmruntime.ErrNotRegionLeader) {
		return fmt.Errorf("a follower was allowed to change manager membership: %v", err)
	}
	lock, err := os.OpenFile(filepath.Join(state, "manager", "membership.lock"), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	_, promoteErr := manager.PromoteManager(ctx)
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		return err
	}
	if promoteErr == nil || !strings.Contains(promoteErr.Error(), "another membership change") {
		return fmt.Errorf("concurrent membership change was not refused: %v", promoteErr)
	}
	if err := meshPromotionJourney(ctx, state, append([]*swarmruntime.Node{manager}, workers...)); err != nil {
		return err
	}
	workerState := filepath.Join(state, "worker-0")
	if err := awaitStoredRole(ctx, workerState, "manager"); err != nil {
		return err
	}
	current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: workers[0].ID()})
	if err != nil {
		return err
	}
	node := current.Node
	spec := node.Spec.Copy()
	spec.DesiredRole, spec.Availability = api.NodeRoleWorker, api.NodeAvailabilityDrain
	if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID, NodeVersion: &node.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	if err := awaitStoredRole(ctx, workerState, "container"); err != nil {
		return err
	}
	if output, err := command("leave", "worker-0"); err != nil {
		return fmt.Errorf("demoted member departure: %w: %s", err, output)
	}
	output, commandErr := command("leave", "worker-1")
	if commandErr == nil || !strings.Contains(string(output), "promote replacement managers first") {
		return fmt.Errorf("below-majority departure was not refused: %s: %v", output, commandErr)
	}
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return err
	}
	if len(listed.Nodes) != 2 {
		return fmt.Errorf("refused departure changed membership: %d nodes", len(listed.Nodes))
	}
	fmt.Println("ok promotion: each operator promotion adds one caught-up voter up to three; a fourth, a follower's, a concurrent and a below-majority change refused; admission follows demotion")
	return nil
}

func awaitStoredRole(ctx context.Context, state, role string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(filepath.Join(state, "swarm", "certificates")); err != nil {
		return err
	}
	for {
		admission, stored, err := swarmruntime.StoredAdmission(state)
		if err != nil {
			return err
		}
		if !stored || admission.HostID != "worker-0" || admission.InstanceID != "instance-0" {
			return fmt.Errorf("role transition changed stored identity")
		}
		if admission.Role == role {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-watcher.Errors:
			return err
		case <-watcher.Events:
		}
	}
}

func awaitPromotionReady(ctx context.Context, client api.ControlClient, watcher api.WatchClient, count, managers int) error {
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := watcher.Watch(watchCtx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{Kind: "node", Action: api.WatchActionKindUpdate}}})
	if err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil {
		return err
	}
	for {
		listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
		if err != nil {
			return err
		}
		ready, readyManagers := 0, 0
		for _, node := range listed.Nodes {
			if node.Status.State == api.NodeStatus_READY {
				ready++
				if node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Reachability == api.RaftMemberStatus_REACHABLE {
					readyManagers++
				}
			}
		}
		if ready == count && readyManagers == managers {
			return nil
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}
