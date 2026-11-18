package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func departedFounder(ctx context.Context, state string, executor *swarmruntime.Executor, founder, worker *swarmruntime.Node, client api.ControlClient, watcher api.WatchClient, material regionjoin.Material) error {
	joining, err := swarmruntime.JoiningAdmission("survivor", "survivor", material.Managers[0], material.WorkerToken)
	if err != nil {
		return err
	}
	survivor, err := swarmruntime.StartHost(ctx, filepath.Join(state, "survivor"), executor, "127.0.0.1:4244", "127.0.0.1:4244", joining)
	if err != nil {
		return err
	}
	defer func() { _ = survivor.Stop(context.WithoutCancel(ctx)) }()
	for _, node := range []*swarmruntime.Node{worker, survivor} {
		current, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: node.ID()})
		if err != nil {
			return err
		}
		spec := current.Node.Spec.Copy()
		spec.DesiredRole = api.NodeRoleManager
		if _, err := client.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: node.ID(), NodeVersion: &current.Node.Meta.Version, Spec: spec}); err != nil {
			return err
		}
	}
	if err := awaitPromotionReady(ctx, client, watcher, 3, 3); err != nil {
		return err
	}
	successor, conn, err := swarmruntime.DialControl(filepath.Join(state, "survivor"))
	if err != nil {
		return err
	}
	defer conn.Close()
	current, err := successor.GetNode(ctx, &api.GetNodeRequest{NodeID: founder.ID()})
	if err != nil {
		return err
	}
	spec := current.Node.Spec.Copy()
	spec.DesiredRole = api.NodeRoleWorker
	if _, err := successor.UpdateNode(ctx, &api.UpdateNodeRequest{NodeID: founder.ID(), NodeVersion: &current.Node.Meta.Version, Spec: spec}); err != nil {
		return err
	}
	if err := awaitPromotionReady(ctx, successor, api.NewWatchClient(conn), 3, 2); err != nil {
		return err
	}
	if err := swarmruntime.RemoveMember(ctx, successor, material.Founder, func(ctx context.Context) error { return ctx.Err() }); err != nil {
		return err
	}
	stop, done := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	err = founder.Stop(stop)
	done()
	if err != nil {
		return err
	}
	refreshed, err := regionjoin.ClusterMaterial(ctx, successor, material.Founder)
	if err != nil {
		return err
	}
	if refreshed.Founder == material.Founder || !slices.Contains(refreshed.Nodes, refreshed.Founder) || slices.Contains(refreshed.Nodes, material.Founder) || refreshed.WorkerToken != material.WorkerToken {
		return errors.New("departed founder was not replaced by a current member with the same cluster token")
	}
	refreshed.Managers = []string{"127.0.0.1:4243", "127.0.0.1:4244"}
	manager, accepts := regionjoin.ReachableManager(ctx, refreshed)
	if !accepts {
		return errors.New("departed founder prevented joining its surviving cluster")
	}
	joining, err = swarmruntime.JoiningAdmission("replacement", "replacement", manager, refreshed.WorkerToken)
	if err != nil {
		return err
	}
	replacement, err := swarmruntime.StartHost(ctx, filepath.Join(state, "replacement"), executor, "127.0.0.1:4245", "127.0.0.1:4245", joining)
	if err != nil {
		return err
	}
	ready := awaitPromotionReady(ctx, successor, api.NewWatchClient(conn), 3, 2)
	stop, done = context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer done()
	return errors.Join(ready, replacement.Stop(stop))
}
