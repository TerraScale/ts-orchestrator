package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func rebuiltRegion(ctx context.Context, state string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, state)
	if err != nil {
		return err
	}
	defer executor.Close()
	var old regionjoin.Material
	for _, founder := range []string{"old-founder", "new-founder"} {
		cluster := filepath.Join(state, founder)
		node, err := swarmruntime.StartHost(ctx, cluster, executor, "127.0.0.1:4242", "127.0.0.1:4242", swarmruntime.FoundingAdmission(founder, founder))
		if err != nil {
			return err
		}
		err = func() error {
			defer func() {
				stop, done := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
				defer done()
				_ = node.Stop(stop)
			}()
			client, conn, err := swarmruntime.DialControl(cluster)
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := awaitPromotionReady(ctx, client, api.NewWatchClient(conn), 1, 1); err != nil {
				return err
			}
			material, err := regionjoin.ClusterMaterial(ctx, client, founder)
			if err != nil {
				return err
			}
			material.Managers = []string{"127.0.0.1:4242"}
			if old.WorkerToken != "" {
				if material.WorkerToken == old.WorkerToken {
					return errors.New("rebuilt region kept the deleted cluster's token")
				}
				if _, accepts := regionjoin.ReachableManager(ctx, old); accepts {
					return errors.New("rebuilt manager accepted deleted cluster material")
				}
				forged := material
				forged.Founder = old.Founder
				if _, accepts := regionjoin.ReachableManager(ctx, forged); accepts {
					return errors.New("current cluster accepted material naming an absent founder")
				}
				absent, err := regionjoin.ClusterMaterial(ctx, client, old.Founder)
				if err != nil {
					return err
				}
				if absent.Founder != founder || absent.WorkerToken != material.WorkerToken {
					return errors.New("cluster did not replace the absent founder while preserving its token")
				}
			}
			rollout := material
			rollout.Nodes = nil
			manager, accepts := regionjoin.ReachableManager(ctx, rollout)
			if !accepts {
				return errors.New("old publisher material without nodes did not authenticate its manager")
			}
			joining, err := swarmruntime.JoiningAdmission(founder+"-worker", founder+"-worker", manager, material.WorkerToken)
			if err != nil {
				return err
			}
			worker, err := swarmruntime.StartHost(ctx, filepath.Join(state, founder+"-worker"), executor, "127.0.0.1:4243", "127.0.0.1:4243", joining)
			if err != nil {
				return err
			}
			ready := awaitPromotionReady(ctx, client, api.NewWatchClient(conn), 2, 1)
			if ready == nil && founder == "new-founder" {
				ready = departedFounder(ctx, state, executor, node, worker, client, api.NewWatchClient(conn), material)
			}
			stop, done := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer done()
			if err := errors.Join(ready, worker.Stop(stop)); err != nil {
				return err
			}
			old = material
			return nil
		}()
		if err != nil {
			return err
		}
	}
	fmt.Println("rebuilt region and departed founder: replacement workers join; cluster token stays unchanged on founder departure; old publishers remain joinable; stale cluster material is refused")
	return nil
}
